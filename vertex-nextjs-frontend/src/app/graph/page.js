'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { GitBranch, Link2, Mail, Network, ShieldAlert } from 'lucide-react'
import { getCorrelationGraph, getSharedInfrastructure } from '../../lib/api'
import { Alert, Badge, Card, EmptyState, MetricCard, Page, PageHeader, Skeleton } from '../../components/ui'

function nodeTone(type) {
  const t = String(type || '').toLowerCase()
  if (t === 'email') return 'primary'
  if (t === 'ip') return 'warning'
  if (t === 'domain' || t === 'sender') return 'info'
  if (t === 'hash' || t === 'attachment') return 'danger'
  return 'neutral'
}

export default function GraphPage() {
  const [graph, setGraph] = useState(null)
  const [shared, setShared] = useState({})
  const [filter, setFilter] = useState('ALL')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let alive = true
    Promise.all([getCorrelationGraph(), getSharedInfrastructure()]).then(([g, s]) => { if (alive) { setGraph(g || {}); setShared(s || {}); setLoading(false) } }).catch((err) => alive && (setError(err.message), setLoading(false)))
    return () => { alive = false }
  }, [])

  const nodes = useMemo(() => ((graph?.elements?.nodes || graph?.nodes || []).map((n) => n.data || n)), [graph])
  const edges = useMemo(() => ((graph?.elements?.edges || graph?.links || []).map((e) => e.data || e)), [graph])
  const filtered = useMemo(() => nodes.filter((n) => filter === 'ALL' || String(n.nodeType || n.type || '').toUpperCase() === filter), [nodes, filter])
  const sharedKeys = Object.keys(shared || {})

  return <Page>
    <PageHeader eyebrow="Threat intelligence" title="Correlation graph" description="Explore shared infrastructure, senders and evidence relationships across analyzed email." />
    {error && <div className="mb-5"><Alert>{error}</Alert></div>}
    <div className="mb-5 grid gap-3 sm:grid-cols-3"><MetricCard label="Entities" value={graph?.stats?.total_nodes || nodes.length} icon={Network} tone="primary" /><MetricCard label="Relationships" value={graph?.stats?.total_edges || edges.length} icon={Link2} /><MetricCard label="Shared indicators" value={sharedKeys.length} icon={ShieldAlert} tone={sharedKeys.length ? 'warning' : 'success'} /></div>
    {sharedKeys.length > 0 && <Alert tone="warning"><div className="font-bold">Coordinated campaign signal detected.</div><div className="mt-1 text-xs opacity-80">Indicators below appear across multiple analyzed artifacts and may represent shared adversary infrastructure.</div></Alert>}

    <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1.2fr)_380px]">
      <Card className="overflow-hidden"><div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3"><div className="flex flex-wrap items-center gap-1.5">{['ALL','EMAIL','IP','DOMAIN','SENDER','CASE'].map((item) => <button key={item} onClick={() => setFilter(item)} className={`rounded-lg px-2.5 py-1.5 text-[10px] font-bold transition ${filter === item ? 'bg-slate-950 text-white' : 'text-text-tertiary hover:bg-surface-muted hover:text-text'}`}>{item}</button>)}</div><div className="text-[11px] font-semibold text-text-tertiary">{filtered.length} visible nodes</div></div><div className="relative min-h-[540px] overflow-hidden bg-[radial-gradient(circle_at_center,#eef2ff_0,transparent_46%),linear-gradient(#fbfcfe,#f8fafc)] p-5"><div className="pointer-events-none absolute inset-0 opacity-60 [background-image:linear-gradient(#e7eaf0_1px,transparent_1px),linear-gradient(90deg,#e7eaf0_1px,transparent_1px)] [background-size:28px_28px]" />{filtered.slice(0, 18).map((node, i) => { const angle = (i / Math.max(filtered.length,1)) * Math.PI * 2; const r = i % 2 === 0 ? 34 : 20; const left = 50 + Math.cos(angle) * r; const top = 50 + Math.sin(angle) * r; const type = node.nodeType || node.type || 'ENTITY'; const tone = nodeTone(type); return <div key={node.id || i} className="absolute" style={{ left: `${Math.min(82,Math.max(8,left))}%`, top: `${Math.min(84,Math.max(12,top))}%` }}><div className="-translate-x-1/2 -translate-y-1/2"><div className={`grid h-11 w-11 place-items-center rounded-2xl border bg-white shadow-[0_8px_25px_rgba(15,23,42,.09)] ${tone === 'danger' ? 'border-red-200 text-danger' : tone === 'warning' ? 'border-amber-200 text-warning' : tone === 'info' ? 'border-blue-200 text-info' : tone === 'primary' ? 'border-indigo-200 text-primary' : 'border-border text-text-secondary'}`}>{type.toLowerCase() === 'email' ? <Mail size={17} /> : <GitBranch size={16} />}</div><div className="mt-1 max-w-[120px] rounded-full bg-white/90 px-2 py-1 text-center text-[9px] font-bold text-text shadow-sm ring-1 ring-border">{String(node.label || node.id || type).slice(0, 22)}</div></div></div>})}{filtered.length === 0 && <div className="absolute inset-0 grid place-items-center"><EmptyState title="No nodes found" description="Analyze or correlate emails to populate this workspace." /></div>}</div></Card>
      <div className="space-y-5"><Card className="p-5"><div className="text-sm font-extrabold">Shared infrastructure</div><p className="mt-1 text-xs leading-5 text-text-secondary">Indicators that repeat across multiple artifacts.</p><div className="mt-4 space-y-2">{sharedKeys.length ? sharedKeys.map((key) => <div key={key} className="rounded-xl border border-border bg-surface-muted p-3"><div className="flex items-center justify-between gap-2"><span className="font-mono text-[11px] font-bold text-text">{key}</span><Badge tone="warning">shared</Badge></div><div className="mt-1 text-[10px] leading-4 text-text-secondary">{Array.isArray(shared[key]) ? shared[key].join(', ') : JSON.stringify(shared[key])}</div></div>) : <div className="rounded-xl bg-surface-muted p-4 text-xs text-text-tertiary">No shared indicators detected.</div>}</div></Card><Card className="p-5"><div className="text-sm font-extrabold">Relationship ledger</div><div className="mt-3 max-h-[300px] space-y-2 overflow-auto">{edges.length ? edges.slice(0, 30).map((edge, index) => <div key={edge.id || index} className="rounded-xl border border-border p-3 text-xs"><div className="font-mono text-text">{edge.source}</div><div className="my-1 text-[10px] font-bold uppercase tracking-wider text-primary">{edge.edgeType || 'CONNECTED_TO'}</div><div className="font-mono text-text-secondary">{edge.target}</div></div>) : <div className="rounded-xl bg-surface-muted p-4 text-xs text-text-tertiary">No relationships yet.</div>}</div></Card></div>
    </div>
  </Page>
}
