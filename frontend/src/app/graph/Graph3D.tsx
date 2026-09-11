'use client'

import { useEffect, useRef } from 'react'
import * as THREE from 'three'
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js'
import type { GraphEdge, GraphNode } from '../../types/api'

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

function colorFor(type = 'entity', isRoot = false, selected = false) {
  if (selected) return 0xf8fafc
  if (isRoot) return 0x6366f1
  switch (type.toLowerCase()) {
    case 'email': return 0x818cf8
    case 'ip': return 0xf59e0b
    case 'domain':
    case 'sender': return 0x38bdf8
    case 'case': return 0x94a3b8
    case 'hash':
    case 'attachment': return 0xfb7185
    default: return 0xcbd5e1
  }
}

function makeNodeMesh(node: PositionedNode, rootId: string | null, selectedId: string | null) {
  const type = String(node.nodeType || node.type || 'entity')
  const isRoot = String(node.id) === String(rootId)
  const selected = String(node.id) === String(selectedId)
  const size = isRoot ? 0.78 : selected ? 0.62 : 0.42 + Math.min(node.connected, 5) * 0.035
  const group = new THREE.Group()
  group.position.set(node.position.x, node.position.y, node.position.z)

  const geometry = new THREE.SphereGeometry(size, 24, 18)
  const material = new THREE.MeshStandardMaterial({
    color: colorFor(type, isRoot, selected),
    emissive: colorFor(type, isRoot, selected),
    emissiveIntensity: isRoot ? 0.32 : selected ? 0.18 : 0.06,
    roughness: 0.32,
    metalness: 0.16,
  })
  const mesh = new THREE.Mesh(geometry, material)
  mesh.userData.nodeId = String(node.id)
  group.add(mesh)

  if (isRoot || selected) {
    const halo = new THREE.Mesh(
      new THREE.SphereGeometry(size * 1.28, 16, 12),
      new THREE.MeshBasicMaterial({
        color: isRoot ? 0x818cf8 : 0xe2e8f0,
        wireframe: true,
        transparent: true,
        opacity: 0.36,
      }),
    )
    group.add(halo)
  }

  return { group, mesh, glow: isRoot || selected }
}

function makeLine(source: PositionedNode, target: PositionedNode, focused: boolean) {
  const geometry = new THREE.BufferGeometry().setFromPoints([
    new THREE.Vector3(source.position.x, source.position.y, source.position.z),
    new THREE.Vector3(target.position.x, target.position.y, target.position.z),
  ])
  const material = new THREE.LineBasicMaterial({
    color: focused ? 0x818cf8 : 0x64748b,
    transparent: true,
    opacity: focused ? 0.86 : 0.28,
  })
  return new THREE.Line(geometry, material)
}

export default function Graph3D({ nodes, edges, selectedId, rootId, onSelect }: SceneProps) {
  const hostRef = useRef<HTMLDivElement | null>(null)
  const selectionRef = useRef(selectedId)
  const rootRef = useRef(rootId)
  const nodesRef = useRef(nodes)
  const onSelectRef = useRef(onSelect)

  useEffect(() => { selectionRef.current = selectedId }, [selectedId])
  useEffect(() => { rootRef.current = rootId }, [rootId])
  useEffect(() => { nodesRef.current = nodes }, [nodes])
  useEffect(() => { onSelectRef.current = onSelect }, [onSelect])

  useEffect(() => {
    const host = hostRef.current
    if (!host) return

    const scene = new THREE.Scene()
    scene.background = new THREE.Color(0x07101f)

    const camera = new THREE.PerspectiveCamera(52, 1, 0.1, 100)
    camera.position.set(0, 1.5, 12)

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.7))
    renderer.setSize(host.clientWidth, host.clientHeight, false)
    renderer.outputColorSpace = THREE.SRGBColorSpace
    host.appendChild(renderer.domElement)

    const controls = new OrbitControls(camera, renderer.domElement)
    controls.enableDamping = true
    controls.dampingFactor = 0.08
    controls.enablePan = true
    controls.enableZoom = true
    controls.minDistance = 5
    controls.maxDistance = 32
    controls.target.set(0, 0, 0)

    scene.add(new THREE.AmbientLight(0xffffff, 1.25))
    const keyLight = new THREE.DirectionalLight(0xffffff, 2.0)
    keyLight.position.set(7, 10, 8)
    scene.add(keyLight)
    const fillLight = new THREE.PointLight(0x818cf8, 1.1, 28)
    fillLight.position.set(-7, -4, -6)
    scene.add(fillLight)

    const starsGeometry = new THREE.BufferGeometry()
    const starCount = 650
    const starPositions = new Float32Array(starCount * 3)
    for (let i = 0; i < starCount; i += 1) {
      const radius = 24 + Math.random() * 20
      const theta = Math.random() * Math.PI * 2
      const phi = Math.acos(2 * Math.random() - 1)
      starPositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta)
      starPositions[i * 3 + 1] = radius * Math.cos(phi)
      starPositions[i * 3 + 2] = radius * Math.sin(phi) * Math.sin(theta)
    }
    starsGeometry.setAttribute('position', new THREE.BufferAttribute(starPositions, 3))
    const stars = new THREE.Points(
      starsGeometry,
      new THREE.PointsMaterial({ color: 0x64748b, size: 0.055, transparent: true, opacity: 0.55 }),
    )
    scene.add(stars)

    const graphGroup = new THREE.Group()
    scene.add(graphGroup)

    const nodeById = new Map(nodes.map((node) => [String(node.id), node]))
    const nodeMeshes = new Map<string, THREE.Object3D>()

    edges.forEach((edge, index) => {
      const source = nodeById.get(String(edge.source))
      const target = nodeById.get(String(edge.target))
      if (!source || !target) return
      const focused = String(source.id) === String(selectedId) || String(target.id) === String(selectedId) || String(source.id) === String(rootId) || String(target.id) === String(rootId)
      const line = makeLine(source, target, focused)
      line.userData.edgeKey = edge.id || `${edge.source}-${edge.target}-${index}`
      graphGroup.add(line)
    })

    nodes.forEach((node) => {
      const item = makeNodeMesh(node, rootId, selectedId)
      item.group.userData.nodeId = String(node.id)
      item.mesh.userData.nodeId = String(node.id)
      nodeMeshes.set(String(node.id), item.group)
      graphGroup.add(item.group)
    })

    const raycaster = new THREE.Raycaster()
    const pointer = new THREE.Vector2()

    const selectAtPointer = (event: PointerEvent) => {
      const rect = renderer.domElement.getBoundingClientRect()
      pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1
      pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1
      raycaster.setFromCamera(pointer, camera)
      const meshes = Array.from(nodeMeshes.values()).flatMap((object) => object.children).filter((child) => child instanceof THREE.Mesh)
      const hits = raycaster.intersectObjects(meshes, false)
      const hit = hits[0]?.object
      if (!hit) {
        onSelectRef.current(null)
        return
      }
      const id = String(hit.userData.nodeId || '')
      const selectedNode = nodesRef.current.find((node) => String(node.id) === id) || null
      onSelectRef.current(selectedNode)
    }

    renderer.domElement.addEventListener('pointerdown', selectAtPointer)

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

    let frame = 0
    let disposed = false
    const animate = () => {
      if (disposed) return
      frame = requestAnimationFrame(animate)
      controls.update()
      stars.rotation.y += 0.00025
      renderer.render(scene, camera)
    }
    animate()

    return () => {
      disposed = true
      cancelAnimationFrame(frame)
      observer.disconnect()
      renderer.domElement.removeEventListener('pointerdown', selectAtPointer)
      controls.dispose()
      scene.traverse((object) => {
        if (object instanceof THREE.Mesh || object instanceof THREE.Line || object instanceof THREE.Points) {
          object.geometry.dispose()
          if (Array.isArray(object.material)) object.material.forEach((material) => material.dispose())
          else object.material.dispose()
        }
      })
      renderer.dispose()
      if (renderer.domElement.parentElement === host) host.removeChild(renderer.domElement)
    }
  }, [nodes, edges, selectedId, rootId])

  return <div ref={hostRef} className="h-full w-full" aria-label="Interactive 3D threat correlation graph" role="img" />
}
