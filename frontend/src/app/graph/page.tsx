'use client'

import dynamic from 'next/dynamic'
import Link from 'next/link'
import { useEffect, useMemo, useState } from 'react'
import { FolderKanban, Globe2, Mail, Search, Server, Share2, Sparkles, Target, Waypoints } from 'lucide-react'
import { Badge, Button, Card, EmptyState, Page, PageHeader, Skeleton } from '../../components/ui'
import { apiError, getCorrelationGraph, getSharedInfrastructure } from '../../lib/api'
import type { GraphEdge, GraphNode } from '../../types/api'

const Graph3D = dynamic(() => import('./Graph3D'), { ssr: false, loading: () => <div className="grid h-full place-items-center text-xs text-slate-400">Preparing 3D workspace…</div> })

type Position = { x: number; y: number; z: number }
type PositionedNode = GraphNode & { position: Position; depth: number; connected: number }

function degreeMap(edges: GraphEdge[]) {
  const map = new Map<string, number>()
  for (const edge of edges) {
    const source = String(edge.source)
    const target = String(edge.target)
    map.set(source, (map.get(source) || 0) + 1)
    map.set(target, (map.get(target) || 0) + 1)
  }
  return map
}

function chooseRoot(nodes: GraphNode[], edges: GraphEdge[]) {
  const degree = degreeMap(edges)
  const emails = nodes.filter((node) => String(node.nodeType || node.type || '').toLowerCase() === 'email')
  return [...emails, ...nodes]
    .filter((node, index, list) => list.findIndex((candidate) => candidate.id === node.id) === index)
    .sort((a, b) => (degree.get(String(b.id)) || 0) - (degree.get(String(a.id)) || 0))[0]?.id || null
}

function buildDepths(nodes: GraphNode[], edges: GraphEdge[], rootId: string | null) {
  const neighbors = new Map<string, Set<string>>()
  for (const node of nodes) neighbors.set(String(node.id), new Set())
  for (const edge of edges) {
    const source = String(edge.source)
    const target = String(edge.target)
    neighbors.get(source)?.add(target)
    neighbors.get(target)?.add(source)
  }

  const depth = new Map<string, number>()
  if (!rootId) return depth
  depth.set(rootId, 0)
  const queue = [rootId]
  while (queue.length) {
    const current = queue.shift()!
    const nextDepth = (depth.get(current) || 0) + 1
    for (const neighbor of neighbors.get(current) || []) {
      if (!depth.has(neighbor)) {
        depth.set(neighbor, nextDepth)
        queue.push(neighbor)
      }
    }
  }
  return depth
}

function fibonacciPoint(index: number, count: number, radius: number, phase: number): Position {
  if (count <= 1) return { x: 0, y: radius, z: 0 }
  const golden = Math.PI * (3 - Math.sqrt(5))
  const y = 1 - (index / (count - 1)) * 2
  const ring = Math.sqrt(Math.max(0, 1 - y * y))
  const theta = golden * index + phase
  return {
    x: Math.cos(theta) * ring * radius,
    y: y * radius,
    z: Math.sin(theta) * ring * radius,
  }
}

function positionNodes(nodes: GraphNode[], edges: GraphEdge[], rootId: string | null) {
  const depths = buildDepths(nodes, edges, rootId)
  const degree = degreeMap(edges)
  const positioned: PositionedNode[] = []
  const groups = new Map<number, GraphNode[]>()

  for (const node of nodes.slice(0, 60)) {
    const depth = depths.get(String(node.id)) ?? 3
    const group = groups.get(Math.min(depth, 3)) || []
    group.push(node)
    groups.set(Math.min(depth, 3), group)
  }

  for (const node of nodes.slice(0, 60)) {
    const depth = Math.min(depths.get(String(node.id)) ?? 3, 3)
    const group = groups.get(depth) || [node]
    const index = group.findIndex((item) => item.id === node.id)
    let position: Position
    if (String(node.id) === String(rootId)) {
      position = { x: 0, y: 0, z: 0 }
    } else {
      const radius = depth === 1 ? 3.6 : depth === 2 ? 5.5 : 7.2
      position = fibonacciPoint(index, group.length, radius, depth * 0.85)
    }
    positioned.push({ ...node, position, depth, connected: degree.get(String(node.id)) || 0 })
  }

  return positioned
}

function nodeIcon(type = '') {
  switch (type.toLowerCase()) {
    case 'email': return <Mail size={14} />
    case 'ip': return <Server size={14} />
    case 'domain':
    case 'sender': return <Globe2 size={14} />
    case 'case': return <FolderKanban size={14} />
    default: return <Waypoints size={14} />
  }
}

export default function GraphPage() {
  const [nodes, setNodes] = useState<GraphNode[]>([])
  const [edges, setEdges] = useState<GraphEdge[]>([])
  const [shared, setShared] = useState<Record<string, unknown>>({})
  const [filter, setFilter] = useState('ALL')
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<PositionedNode | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    Promise.all([getCorrelationGraph(), getSharedInfrastructure()])
      .then(([g, s]) => {
        const ns: GraphNode[] = g.elements?.nodes
          ? g.elements.nodes.flatMap((item) => (item.data ? [item.data] : []))
          : (g.nodes ?? [])
        const es: GraphEdge[] = g.elements?.edges
          ? g.elements.edges.flatMap((item) => (item.data ? [item.data] : []))
          : (g.links ?? [])
        setNodes(ns)
        setEdges(es)
        setShared(s.shared ?? {})
      })
      .catch((e) => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return nodes.filter((node) => {
      const type = String(node.nodeType || node.type || 'ENTITY').toUpperCase()
      return (filter === 'ALL' || type === filter) && (!q || `${node.label || ''} ${node.id}`.toLowerCase().includes(q))
    })
  }, [nodes, filter, query])

  const rootId = useMemo(() => chooseRoot(filtered.length ? filtered : nodes, edges), [filtered, nodes, edges])
  const positioned = useMemo(() => positionNodes(filtered, edges, rootId), [filtered, edges, rootId])
  const sharedKeys = Object.keys(shared)

  const visibleEdges = useMemo(() => {
    const visibleIds = new Set(positioned.map((node) => String(node.id)))
    return edges.filter((edge) => visibleIds.has(String(edge.source)) && visibleIds.has(String(edge.target)))
  }, [edges, positioned])

  const centerRoot = () => {
    if (!rootId) return
    setSelected(positioned.find((node) => node.id === rootId) || null)
  }

  return (
    <Page>
      <PageHeader
        eyebrow="Campaign intelligence"
        title="Threat correlation"
        description="Explore the relationships VERTEX found between emails, senders, domains, IPs, cases and other evidence."
        actions={
          <Button variant="secondary" onClick={centerRoot} disabled={!rootId}>
            <Target size={15} />
            Center root
          </Button>
        }
      />

      {error ? <div className="mb-5 border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-300">{error}</div> : null}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        {loading ? (
          <Skeleton className="h-[680px]" />
        ) : (
          <Card className="overflow-hidden p-0">
            <div className="flex flex-col gap-3 border-b border-border p-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <div className="flex items-center gap-2 text-sm font-black"><Share2 size={15} className="text-primary" /> 3D relationship map</div>
                <p className="mt-1 text-xs text-text-secondary">The most-connected email or entity is centered as the investigation root.</p>
              </div>
              <div className="flex flex-col gap-2 sm:items-end">
                <div className="flex flex-wrap gap-1.5">
                  {['ALL', 'EMAIL', 'IP', 'DOMAIN', 'SENDER', 'CASE'].map((value) => (
                    <button key={value} onClick={() => setFilter(value)} className={`rounded-full px-3 py-1.5 text-[10px] font-black transition ${filter === value ? 'bg-slate-950 text-white shadow-sm dark:bg-white dark:text-slate-950' : 'bg-surface-soft text-text-secondary hover:bg-border/70'}`}>{value}</button>
                  ))}
                </div>
                <div className="relative w-full sm:w-56">
                  <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-tertiary" />
                  <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Find a node" className="focus-ring h-9 w-full rounded-full border border-border bg-surface-soft pl-8 pr-3 text-xs outline-none focus:border-slate-400" />
                </div>
              </div>
            </div>

            {positioned.length === 0 ? (
              <div className="grid min-h-[620px] place-items-center p-6"><EmptyState title="No matching nodes" description="Add analyzed emails to the correlation graph from an investigation page." /></div>
            ) : (
              <div className="h-[620px] bg-[#07101f]">
                <Graph3D nodes={positioned} edges={visibleEdges} rootId={rootId} selectedId={selected?.id || null} onSelect={(node) => setSelected(node)} />
              </div>
            )}

            <div className="grid border-t border-border sm:grid-cols-4">
              <Stat label="Nodes" value={nodes.length} />
              <Stat label="Relationships" value={edges.length} />
              <Stat label="Visible" value={positioned.length} />
              <Stat label="Shared indicators" value={sharedKeys.length} />
            </div>
          </Card>
        )}

        <div className="space-y-5">
          <Card className="p-5">
            <div className="flex items-center gap-2 text-sm font-black"><Sparkles size={15} className="text-primary" /> Investigation root</div>
            <p className="mt-1 text-xs leading-5 text-text-secondary">VERTEX centers the strongest connected email/entity so the surrounding infrastructure is easier to read.</p>
            {rootId ? <div className="mt-4 rounded-xl border border-indigo-200 bg-indigo-50 p-3 dark:border-indigo-900/50 dark:bg-indigo-950/30"><div className="text-[10px] font-black uppercase tracking-wider text-indigo-700 dark:text-indigo-300">Centered entity</div><div className="mt-1 break-all text-sm font-bold text-indigo-950 dark:text-indigo-100">{positioned.find((node) => node.id === rootId)?.label || rootId}</div></div> : null}
          </Card>

          <Card className="p-5">
            <div className="text-sm font-black">Shared infrastructure</div>
            <p className="mt-1 text-xs leading-5 text-text-secondary">Repeated infrastructure across more than one analyzed email.</p>
            <div className="mt-4 space-y-2">
              {sharedKeys.length ? sharedKeys.map((key) => (
                <div key={key} className="rounded-xl border border-border bg-surface-soft p-3">
                  <div className="flex items-center justify-between gap-2"><span className="font-mono text-[11px] font-bold">{key}</span><Badge tone="warning">shared</Badge></div>
                  <div className="mt-1 text-[10px] leading-4 text-text-secondary">{Array.isArray(shared[key]) ? shared[key].join(', ') : JSON.stringify(shared[key])}</div>
                </div>
              )) : <div className="rounded-xl border border-dashed border-border p-4 text-xs text-text-tertiary">No shared indicators detected.</div>}
            </div>
          </Card>

          <Card className="p-5">
            <div className="text-sm font-black">Node details</div>
            {selected ? (
              <div className="mt-4 space-y-3">
                <div className="flex items-center gap-2"><span className="grid h-8 w-8 place-items-center rounded-full bg-surface-soft text-primary">{nodeIcon(String(selected.nodeType || selected.type || 'ENTITY'))}</span><div><div className="text-[10px] font-black uppercase tracking-wider text-text-tertiary">Type</div><div className="text-xs font-bold">{selected.nodeType || selected.type || 'ENTITY'}</div></div></div>
                <div><div className="text-[10px] font-black uppercase tracking-wider text-text-tertiary">Connections</div><div className="mt-1 text-sm font-bold">{selected.connected}</div></div>
                <div><div className="text-[10px] font-black uppercase tracking-wider text-text-tertiary">Label</div><div className="mt-1 break-all text-sm font-semibold">{selected.label || selected.id}</div></div>
                <div><div className="text-[10px] font-black uppercase tracking-wider text-text-tertiary">Identifier</div><div className="mt-1 break-all font-mono text-[10px] text-text-secondary">{selected.id}</div></div>
                {selected.email_id ? <Link href={`/emails/${selected.email_id}`}><Button className="mt-2 w-full">Open email</Button></Link> : null}
              </div>
            ) : <div className="mt-4 rounded-xl bg-surface-soft p-4 text-xs leading-5 text-text-tertiary">Select a node in the 3D workspace to inspect it. Drag to rotate, scroll to zoom, and pan to move around the investigation.</div>}
          </Card>
        </div>
      </div>
    </Page>
  )
}

function Stat({ label, value }: { label: string; value: number }) {
  return <div className="border-r border-border p-4 last:border-0"><div className="text-[10px] font-black uppercase tracking-wider text-text-tertiary">{label}</div><div className="mt-1 text-xl font-black">{value}</div></div>
}
