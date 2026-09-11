'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import * as THREE from 'three'
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js'
import { getEmail } from '../../lib/api'
import type { EmailDetail, GraphEdge, GraphNode } from '../../types/api'

type Position = { x: number; y: number; z: number }

type PositionedNode = GraphNode & {
  position: Position
  depth: number
  connected: number
}

type SceneProps = {
  nodes: PositionedNode[]
  edges: GraphEdge[]
  selectedId: string | null
  rootId: string | null
  onSelect: (node: PositionedNode | null) => void
}

type HoverState = {
  node: PositionedNode
  x: number
  y: number
  email?: EmailDetail | null
  loadingEmail?: boolean
}

function colorFor(type = 'entity', isRoot = false, selected = false) {
  if (selected) return 0xf8fafc
  if (isRoot) return 0x7c6cff
  switch (type.toLowerCase()) {
    case 'email': return 0x8b7dff
    case 'ip': return 0xf7b955
    case 'domain':
    case 'sender': return 0x45c6f2
    case 'case': return 0x9aa7b8
    case 'hash':
    case 'attachment': return 0xfb7185
    default: return 0xc4d0dd
  }
}

function makeNodeMesh(node: PositionedNode, rootId: string | null, selectedId: string | null) {
  const type = String(node.nodeType || node.type || 'entity')
  const isRoot = String(node.id) === String(rootId)
  const selected = String(node.id) === String(selectedId)
  const base = isRoot ? 0.82 : selected ? 0.68 : 0.46 + Math.min(node.connected, 6) * 0.045
  const group = new THREE.Group()
  group.position.set(node.position.x, node.position.y, node.position.z)
  group.userData.nodeId = String(node.id)

  const color = colorFor(type, isRoot, selected)
  const geometry = new THREE.SphereGeometry(base, 40, 28)
  const material = new THREE.MeshPhysicalMaterial({
    color,
    emissive: color,
    emissiveIntensity: isRoot ? 0.36 : selected ? 0.2 : 0.075,
    roughness: 0.22,
    metalness: 0.3,
    clearcoat: 0.72,
    clearcoatRoughness: 0.16,
  })
  const mesh = new THREE.Mesh(geometry, material)
  mesh.castShadow = true
  mesh.receiveShadow = true
  mesh.userData.nodeId = String(node.id)
  group.add(mesh)

  // Soft volumetric-looking glow without another rendering dependency.
  const glowMaterial = new THREE.MeshBasicMaterial({
    color,
    transparent: true,
    opacity: isRoot ? 0.09 : selected ? 0.075 : 0.045,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  })
  const glow = new THREE.Mesh(new THREE.SphereGeometry(base * 1.7, 24, 18), glowMaterial)
  glow.userData.nodeId = String(node.id)
  group.add(glow)

  if (isRoot || selected) {
    const ring = new THREE.Mesh(
      new THREE.TorusGeometry(base * 1.32, base * 0.045, 10, 64),
      new THREE.MeshBasicMaterial({
        color: isRoot ? 0xb6adff : 0xffffff,
        transparent: true,
        opacity: isRoot ? 0.72 : 0.52,
      }),
    )
    ring.rotation.x = Math.PI / 2
    group.add(ring)
  }

  return group
}

function makeLine(source: PositionedNode, target: PositionedNode, focused: boolean) {
  const geometry = new THREE.BufferGeometry().setFromPoints([
    new THREE.Vector3(source.position.x, source.position.y, source.position.z),
    new THREE.Vector3(target.position.x, target.position.y, target.position.z),
  ])
  const material = new THREE.LineBasicMaterial({
    color: focused ? 0xa79cff : 0x718096,
    transparent: true,
    opacity: focused ? 0.9 : 0.24,
  })
  return new THREE.Line(geometry, material)
}

function formatDate(value?: string | null) {
  if (!value) return 'Date unavailable'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}

function emailPreview(node: PositionedNode, email?: EmailDetail | null) {
  const subject = email?.subject || node.label || `Email #${node.email_id ?? node.id}`
  return {
    subject,
    sender: email?.sender || 'Sender details available in the investigation view',
    date: formatDate(email?.date || email?.created_at),
    id: email?.id ?? node.email_id ?? node.id,
  }
}

export default function Graph3D({ nodes, edges, selectedId, rootId, onSelect }: SceneProps) {
  const hostRef = useRef<HTMLDivElement | null>(null)
  const selectionRef = useRef(selectedId)
  const rootRef = useRef(rootId)
  const nodesRef = useRef(nodes)
  const onSelectRef = useRef(onSelect)
  const graphGroupRef = useRef<THREE.Group | null>(null)
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null)
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null)
  const controlsRef = useRef<OrbitControls | null>(null)
  const raycasterRef = useRef(new THREE.Raycaster())
  const pointerRef = useRef(new THREE.Vector2())
  const pointerDownRef = useRef<{ x: number; y: number } | null>(null)
  const emailCacheRef = useRef(new Map<number, EmailDetail | null>())
  const hoverTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const [hovered, setHovered] = useState<HoverState | null>(null)

  useEffect(() => { selectionRef.current = selectedId }, [selectedId])
  useEffect(() => { rootRef.current = rootId }, [rootId])
  useEffect(() => { nodesRef.current = nodes }, [nodes])
  useEffect(() => { onSelectRef.current = onSelect }, [onSelect])

  const nodeById = useMemo(() => new Map(nodes.map((node) => [String(node.id), node])), [nodes])

  useEffect(() => {
    const host = hostRef.current
    if (!host) return

    const scene = new THREE.Scene()
    scene.background = new THREE.Color(0x07101f)
    scene.fog = new THREE.FogExp2(0x07101f, 0.014)

    const camera = new THREE.PerspectiveCamera(50, 1, 0.1, 120)
    camera.position.set(0, 1.2, 14)
    cameraRef.current = camera

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' })
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.8))
    renderer.setSize(Math.max(1, host.clientWidth), Math.max(1, host.clientHeight), false)
    renderer.outputColorSpace = THREE.SRGBColorSpace
    renderer.toneMapping = THREE.ACESFilmicToneMapping
    renderer.toneMappingExposure = 1.1
    renderer.shadowMap.enabled = true
    renderer.shadowMap.type = THREE.PCFSoftShadowMap
    rendererRef.current = renderer
    host.appendChild(renderer.domElement)

    const controls = new OrbitControls(camera, renderer.domElement)
    controls.enableDamping = true
    controls.dampingFactor = 0.07
    controls.enablePan = true
    controls.enableZoom = true
    controls.minDistance = 5
    controls.maxDistance = 36
    controls.target.set(0, 0, 0)
    controlsRef.current = controls

    const hemi = new THREE.HemisphereLight(0xeaf2ff, 0x162238, 1.45)
    scene.add(hemi)

    const keyLight = new THREE.DirectionalLight(0xffffff, 2.7)
    keyLight.position.set(8, 12, 10)
    keyLight.castShadow = true
    keyLight.shadow.mapSize.set(1024, 1024)
    scene.add(keyLight)

    const violetLight = new THREE.PointLight(0x7c6cff, 16, 34, 2)
    violetLight.position.set(-8, 2, 4)
    scene.add(violetLight)

    const cyanLight = new THREE.PointLight(0x27c5ff, 12, 30, 2)
    cyanLight.position.set(7, -5, 0)
    scene.add(cyanLight)

    const warmLight = new THREE.PointLight(0xffb44a, 5, 22, 2)
    warmLight.position.set(0, 8, -9)
    scene.add(warmLight)

    const starsGeometry = new THREE.BufferGeometry()
    const starCount = 900
    const starPositions = new Float32Array(starCount * 3)
    for (let i = 0; i < starCount; i += 1) {
      const radius = 22 + Math.random() * 36
      const theta = Math.random() * Math.PI * 2
      const phi = Math.acos(2 * Math.random() - 1)
      starPositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta)
      starPositions[i * 3 + 1] = radius * Math.cos(phi)
      starPositions[i * 3 + 2] = radius * Math.sin(phi) * Math.sin(theta)
    }
    starsGeometry.setAttribute('position', new THREE.BufferAttribute(starPositions, 3))
    const stars = new THREE.Points(
      starsGeometry,
      new THREE.PointsMaterial({ color: 0x7d89a5, size: 0.06, transparent: true, opacity: 0.5, sizeAttenuation: true }),
    )
    scene.add(stars)

    const graphGroup = new THREE.Group()
    scene.add(graphGroup)
    graphGroupRef.current = graphGroup

    const resize = () => {
      const width = Math.max(1, host.clientWidth)
      const height = Math.max(1, host.clientHeight)
      camera.aspect = width / height
      camera.updateProjectionMatrix()
      renderer.setSize(width, height, false)
    }
    const observer = new ResizeObserver(resize)
    observer.observe(host)
    resize()

    const getNodeFromPointer = (event: PointerEvent) => {
      const rect = renderer.domElement.getBoundingClientRect()
      pointerRef.current.x = ((event.clientX - rect.left) / rect.width) * 2 - 1
      pointerRef.current.y = -((event.clientY - rect.top) / rect.height) * 2 + 1
      raycasterRef.current.setFromCamera(pointerRef.current, camera)
      const meshes = graphGroup.children.flatMap((child) => child.children).filter((child) => child instanceof THREE.Mesh)
      const hits = raycasterRef.current.intersectObjects(meshes, false)
      const hit = hits[0]?.object
      if (!hit) return null
      const id = String(hit.userData.nodeId || '')
      return nodesRef.current.find((node) => String(node.id) === id) || null
    }

    const showHover = async (node: PositionedNode, event: PointerEvent) => {
      const rect = renderer.domElement.getBoundingClientRect()
      const x = event.clientX - rect.left
      const y = event.clientY - rect.top
      const emailId = Number(node.email_id)
      const isEmail = String(node.nodeType || node.type || '').toLowerCase() === 'email' && Number.isFinite(emailId)

      if (!isEmail) {
        setHovered({ node, x, y })
        return
      }

      const cached = emailCacheRef.current.get(emailId)
      if (cached !== undefined) {
        setHovered({ node, x, y, email: cached })
        return
      }

      setHovered({ node, x, y, loadingEmail: true })
      try {
        const email = await getEmail(emailId)
        emailCacheRef.current.set(emailId, email)
        setHovered((current) => current && String(current.node.id) === String(node.id) ? { ...current, email, loadingEmail: false } : current)
      } catch {
        emailCacheRef.current.set(emailId, null)
        setHovered((current) => current && String(current.node.id) === String(node.id) ? { ...current, email: null, loadingEmail: false } : current)
      }
    }

    const pointerMove = (event: PointerEvent) => {
      if (pointerDownRef.current) {
        const dx = event.clientX - pointerDownRef.current.x
        const dy = event.clientY - pointerDownRef.current.y
        if (Math.hypot(dx, dy) > 6) {
          setHovered(null)
          return
        }
      }

      const node = getNodeFromPointer(event)
      if (hoverTimerRef.current) clearTimeout(hoverTimerRef.current)
      if (!node) {
        hoverTimerRef.current = setTimeout(() => setHovered(null), 40)
        return
      }
      hoverTimerRef.current = setTimeout(() => { void showHover(node, event) }, 70)
    }

    const pointerLeave = () => {
      if (hoverTimerRef.current) clearTimeout(hoverTimerRef.current)
      setHovered(null)
      pointerDownRef.current = null
    }

    const pointerDown = (event: PointerEvent) => {
      pointerDownRef.current = { x: event.clientX, y: event.clientY }
    }

    const pointerUp = (event: PointerEvent) => {
      const down = pointerDownRef.current
      pointerDownRef.current = null
      if (!down) return
      if (Math.hypot(event.clientX - down.x, event.clientY - down.y) > 6) return

      const node = getNodeFromPointer(event)
      if (!node) {
        onSelectRef.current(null)
        return
      }
      // Intentionally do not modify camera position/controls.target here.
      // Selecting a node changes the detail panel only; the camera stays where the analyst left it.
      onSelectRef.current(node)
    }

    renderer.domElement.addEventListener('pointermove', pointerMove)
    renderer.domElement.addEventListener('pointerleave', pointerLeave)
    renderer.domElement.addEventListener('pointerdown', pointerDown)
    renderer.domElement.addEventListener('pointerup', pointerUp)

    let frame = 0
    let disposed = false
    const animate = () => {
      if (disposed) return
      frame = requestAnimationFrame(animate)
      controls.update()
      stars.rotation.y += 0.00018
      stars.rotation.x += 0.00003
      renderer.render(scene, camera)
    }
    animate()

    return () => {
      disposed = true
      cancelAnimationFrame(frame)
      observer.disconnect()
      renderer.domElement.removeEventListener('pointermove', pointerMove)
      renderer.domElement.removeEventListener('pointerleave', pointerLeave)
      renderer.domElement.removeEventListener('pointerdown', pointerDown)
      renderer.domElement.removeEventListener('pointerup', pointerUp)
      if (hoverTimerRef.current) clearTimeout(hoverTimerRef.current)
      controls.dispose()
      scene.traverse((object) => {
        if (object instanceof THREE.Mesh || object instanceof THREE.Line || object instanceof THREE.Points) {
          object.geometry.dispose()
          if (Array.isArray(object.material)) object.material.forEach((material) => material.dispose())
          else object.material.dispose()
        }
        if (object instanceof THREE.Light && 'dispose' in object) {
          const maybeDisposable = object as unknown as { dispose?: () => void }
          maybeDisposable.dispose?.()
        }
      })
      renderer.dispose()
      if (renderer.domElement.parentElement === host) host.removeChild(renderer.domElement)
      rendererRef.current = null
      cameraRef.current = null
      controlsRef.current = null
      graphGroupRef.current = null
    }
  }, [])

  useEffect(() => {
    const graphGroup = graphGroupRef.current
    if (!graphGroup) return

    while (graphGroup.children.length) {
      const child = graphGroup.children[0]
      graphGroup.remove(child)
      child.traverse((object) => {
        if (object instanceof THREE.Mesh || object instanceof THREE.Line) {
          object.geometry.dispose()
          if (Array.isArray(object.material)) object.material.forEach((material) => material.dispose())
          else object.material.dispose()
        }
      })
    }

    edges.forEach((edge, index) => {
      const source = nodeById.get(String(edge.source))
      const target = nodeById.get(String(edge.target))
      if (!source || !target) return
      const focused = String(source.id) === String(selectedId) || String(target.id) === String(selectedId) || String(source.id) === String(rootId) || String(target.id) === String(rootId)
      const line = makeLine(source, target, focused)
      line.userData.edgeKey = edge.id || `${edge.source}-${edge.target}-${index}`
      graphGroup.add(line)
    })

    nodes.forEach((node) => graphGroup.add(makeNodeMesh(node, rootId, selectedId)))
  }, [edges, nodes, nodeById, rootId, selectedId])

  const tooltip = hovered
  const type = String(tooltip?.node.nodeType || tooltip?.node.type || 'entity').toLowerCase()
  const preview = tooltip ? emailPreview(tooltip.node, tooltip.email) : null

  return (
    <div ref={hostRef} className="relative h-full w-full overflow-hidden" aria-label="Interactive 3D threat correlation graph" role="img">
      {tooltip ? (
        <div
          className="pointer-events-none absolute z-20 w-[270px] -translate-x-1/2 -translate-y-[calc(100%+14px)] rounded-2xl border border-white/10 bg-slate-950/94 p-3 text-white shadow-2xl backdrop-blur-md"
          style={{ left: tooltip.x, top: tooltip.y }}
        >
          <div className="mb-1 flex items-center justify-between gap-3">
            <span className="text-[9px] font-black uppercase tracking-[0.16em] text-indigo-300">{type}</span>
            <span className="text-[9px] font-semibold text-slate-400">{tooltip.node.connected} connections</span>
          </div>
          {type === 'email' ? (
            <>
              <div className="line-clamp-2 text-[12px] font-bold leading-4">{preview?.subject}</div>
              <div className="mt-2 space-y-1.5 text-[10px] text-slate-300">
                <div><span className="text-slate-500">From:</span> {tooltip.loadingEmail ? 'Loading…' : preview?.sender}</div>
                <div><span className="text-slate-500">Date:</span> {preview?.date}</div>
                <div><span className="text-slate-500">Email ID:</span> {preview?.id}</div>
              </div>
            </>
          ) : (
            <>
              <div className="line-clamp-2 text-[12px] font-bold leading-4">{tooltip.node.label || tooltip.node.id}</div>
              <div className="mt-2 text-[10px] text-slate-300">Identifier: <span className="font-mono text-slate-400">{tooltip.node.id}</span></div>
            </>
          )}
        </div>
      ) : null}
    </div>
  )
}
