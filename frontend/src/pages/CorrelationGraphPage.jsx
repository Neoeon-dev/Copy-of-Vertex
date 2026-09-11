import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getCorrelationGraph, getSharedInfrastructure } from '../api'

const filters = ['ALL', 'EMAIL', 'IP', 'DOMAIN', 'SENDER', 'CASE']

function nodeTone(type) {
  switch (type?.toLowerCase()) {
    case 'email': return 'bg-indigo-50 text-indigo-700 border-indigo-100'
    case 'ip': return 'bg-amber-50 text-amber-700 border-amber-100'
    case 'domain':
    case 'sender': return 'bg-blue-50 text-blue-700 border-blue-100'
    case 'case': return 'bg-violet-50 text-violet-700 border-violet-100'
    case 'hash':
    case 'attachment': return 'bg-red-50 text-red-700 border-red-100'
    default: return 'bg-slate-50 text-slate-600 border-slate-200'
  }
}

export default function CorrelationGraphPage() {
  const [graphData, setGraphData] = useState(null)
  const [sharedInfra, setSharedInfra] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filterType, setFilterType] = useState('ALL')

  useEffect(() => {
    let active = true
    Promise.all([getCorrelationGraph(), getSharedInfrastructure()]).then(([graph, shared]) => { if (active) { setGraphData(graph || { nodes: [], links: [] }); setSharedInfra(shared || {}) } }).catch((err) => { if (active) setError(err.message) }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [])

  const allNodes = (graphData?.elements?.nodes || graphData?.nodes || []).map((node) => node.data || node)
  const allEdges = (graphData?.elements?.edges || graphData?.links || []).map((edge) => edge.data || edge)
  const stats = graphData?.stats || {}
  const nodes = allNodes.filter((node) => filterType === 'ALL' || (node.nodeType || node.type || '').toUpperCase() === filterType)
  const sharedKeys = sharedInfra ? Object.keys(sharedInfra) : []

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div><p className="section-label">Relationship intelligence</p><h1 className="mt-2 text-3xl font-bold tracking-tight text-slate-950">Threat correlation</h1><p className="mt-2 text-sm text-slate-500">See the existing cross-email relationships and shared infrastructure exposed by VERTEX.</p></div>
      {error && <div className="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-700">{error}</div>}

      {sharedKeys.length > 0 && <div className="rounded-3xl border border-amber-200 bg-amber-50 p-5"><div className="flex items-center gap-2 text-sm font-bold text-amber-800"><span>⚡</span> Shared infrastructure detected</div><p className="mt-1 text-xs leading-5 text-amber-700">These indicators appear across multiple analyzed emails.</p><div className="mt-4 grid gap-3 md:grid-cols-2 lg:grid-cols-3">{sharedKeys.map((key) => <div key={key} className="rounded-2xl border border-amber-200 bg-white/80 p-3"><p className="font-mono text-xs font-semibold text-slate-800">{key}</p><p className="mt-1 text-[11px] leading-5 text-slate-500">{Array.isArray(sharedInfra[key]) ? sharedInfra[key].join(', ') : JSON.stringify(sharedInfra[key])}</p></div>)}</div></div>}

      <div className="surface-card flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between"><div className="flex flex-wrap gap-1.5">{filters.map((filter) => <button key={filter} onClick={() => setFilterType(filter)} className={`rounded-xl px-3 py-1.5 text-[11px] font-bold tracking-wide transition ${filterType === filter ? 'bg-slate-950 text-white' : 'bg-slate-50 text-slate-500 hover:bg-slate-100'}`}>{filter}</button>)}</div><div className="text-xs font-medium text-slate-400">{stats.total_nodes || allNodes.length} nodes · {stats.total_edges || allEdges.length} relationships</div></div>

      {loading ? <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">{[1,2,3,4,5,6].map((i) => <div key={i} className="surface-card h-36 animate-pulse bg-slate-100" />)}</div> : nodes.length === 0 ? <div className="surface-card p-10 text-center"><p className="font-semibold text-slate-900">No correlation nodes found.</p><p className="mt-2 text-sm text-slate-500">Upload and analyze emails to populate the relationship workspace.</p><Link to="/" className="mt-5 btn-primary">Upload email</Link></div> : <><div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">{nodes.map((node, index) => { const nodeType = node.nodeType || node.type || 'ENTITY'; return <div key={node.id || index} className="surface-card p-4"><div className="flex items-center justify-between gap-3"><span className={`rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase ${nodeTone(nodeType)}`}>{nodeType}</span>{nodeType.toLowerCase() === 'email' && node.email_id && <Link to={`/emails/${node.email_id}`} className="text-[11px] font-semibold text-indigo-600">View →</Link>}</div><p className="mt-4 truncate text-sm font-semibold text-slate-900">{node.label || node.id}</p><p className="mt-1 truncate font-mono text-[11px] text-slate-400">{node.id}</p></div>})}</div>{allEdges.length > 0 && <div className="surface-card overflow-hidden"><div className="border-b border-slate-100 px-5 py-4"><h2 className="text-sm font-semibold text-slate-900">Correlated threat links</h2></div><div className="divide-y divide-slate-100">{allEdges.map((edge, index) => <div key={edge.id || index} className="flex flex-col gap-2 px-5 py-3 text-xs sm:flex-row sm:items-center sm:justify-between"><span className="truncate font-mono font-semibold text-slate-700">{edge.source}</span><span className="self-start rounded-full bg-slate-50 px-2.5 py-1 text-[10px] font-bold text-indigo-600 sm:self-auto">{edge.edgeType || 'CONNECTED_TO'}</span><span className="truncate font-mono text-slate-400 sm:text-right">{edge.target}</span></div>)}</div></div>}</>}
    </div>
  )
}
