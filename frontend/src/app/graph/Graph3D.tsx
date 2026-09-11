'use client'

import { Canvas, useThree } from '@react-three/fiber'
import { Html, Line, OrbitControls, Stars } from '@react-three/drei'
import { useEffect, useMemo, useRef } from 'react'
import * as THREE from 'three'
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
  if (selected) return '#111827'
  if (isRoot) return '#4f46e5'
  switch (type.toLowerCase()) {
    case 'email': return '#6366f1'
    case 'ip': return '#f59e0b'
    case 'domain':
    case 'sender': return '#0ea5e9'
    case 'case': return '#64748b'
    case 'hash':
    case 'attachment': return '#ef4444'
    default: return '#94a3b8'
  }
}

function SceneCamera({ targetId, nodes }: { targetId: string | null; nodes: PositionedNode[] }) {
  const { camera } = useThree()
  const lastTarget = useRef<string | null>(null)

  useEffect(() => {
    if (!targetId || targetId === lastTarget.current) return
    const target = nodes.find((node) => node.id === targetId)
    if (!target) return
    camera.position.lerp(new THREE.Vector3(target.position.x + 4, target.position.y + 4, target.position.z + 10), 0.35)
    camera.lookAt(target.position.x, target.position.y, target.position.z)
    lastTarget.current = targetId
  }, [camera, nodes, targetId])

  return null
}

function Node({ node, rootId, selectedId, onSelect }: {
  node: PositionedNode
  rootId: string | null
  selectedId: string | null
  onSelect: (node: PositionedNode) => void
}) {
  const type = String(node.nodeType || node.type || 'entity')
  const isRoot = node.id === rootId
  const selected = node.id === selectedId
  const size = isRoot ? 0.72 : selected ? 0.58 : 0.45 + Math.min(node.connected, 4) * 0.025

  return (
    <group position={[node.position.x, node.position.y, node.position.z]}>
      <mesh
        onClick={(event) => {
          event.stopPropagation()
          onSelect(node)
        }}
      >
        <sphereGeometry args={[size, 28, 28]} />
        <meshStandardMaterial
          color={colorFor(type, isRoot, selected)}
          emissive={colorFor(type, isRoot, selected)}
          emissiveIntensity={isRoot ? 0.24 : selected ? 0.16 : 0.04}
          roughness={0.28}
          metalness={0.18}
        />
      </mesh>
      {(isRoot || selected) && (
        <mesh scale={1.22}>
          <sphereGeometry args={[size, 20, 20]} />
          <meshBasicMaterial color={isRoot ? '#818cf8' : '#cbd5e1'} wireframe transparent opacity={0.34} />
        </mesh>
      )}
      {(isRoot || selected) && (
        <Html center distanceFactor={8} position={[0, size + 0.2, 0]}>
          <div className="pointer-events-none rounded-lg border border-white/15 bg-slate-950/90 px-2.5 py-1.5 text-center shadow-xl backdrop-blur">
            <div className="max-w-40 truncate text-[10px] font-bold text-white">{String(node.label || node.id)}</div>
            <div className="mt-0.5 text-[9px] font-medium uppercase tracking-wide text-slate-300">{type}</div>
          </div>
        </Html>
      )}
    </group>
  )
}

function GraphScene({ nodes, edges, selectedId, rootId, onSelect }: SceneProps) {
  const nodeById = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes])

  return (
    <>
      <ambientLight intensity={1.3} />
      <directionalLight position={[6, 10, 8]} intensity={2.2} />
      <pointLight position={[-8, -4, -4]} intensity={0.9} />
      <Stars radius={55} depth={30} count={900} factor={2.2} saturation={0} fade speed={0.35} />
      <group>
        {edges.map((edge, index) => {
          const source = nodeById.get(String(edge.source))
          const target = nodeById.get(String(edge.target))
          if (!source || !target) return null
          const focused = source.id === selectedId || target.id === selectedId || source.id === rootId || target.id === rootId
          return (
            <Line
              key={edge.id || `${edge.source}-${edge.target}-${index}`}
              points={[
                [source.position.x, source.position.y, source.position.z],
                [target.position.x, target.position.y, target.position.z],
              ]}
              color={focused ? '#818cf8' : '#64748b'}
              lineWidth={focused ? 1.6 : 0.75}
              transparent
              opacity={focused ? 0.78 : 0.3}
            />
          )
        })}
        {nodes.map((node) => (
          <Node key={node.id} node={node} rootId={rootId} selectedId={selectedId} onSelect={onSelect} />
        ))}
      </group>
      <OrbitControls enablePan enableZoom minDistance={5} maxDistance={32} dampingFactor={0.08} enableDamping />
      <SceneCamera targetId={selectedId} nodes={nodes} />
    </>
  )
}

export default function Graph3D(props: SceneProps) {
  return (
    <Canvas
      camera={{ position: [0, 1.5, 12], fov: 52, near: 0.1, far: 100 }}
      dpr={[1, 1.7]}
      gl={{ antialias: true, alpha: true }}
      onPointerMissed={() => props.onSelect(null)}
      style={{ width: '100%', height: '100%' }}
    >
      <color attach="background" args={['#07101f']} />
      <GraphScene {...props} />
    </Canvas>
  )
}
