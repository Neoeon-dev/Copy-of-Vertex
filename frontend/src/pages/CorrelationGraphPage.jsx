import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { getCorrelationGraph, getSharedInfrastructure } from '../api'

export default function CorrelationGraphPage() {
  const [graphData, setGraphData] = useState(null)
  const [sharedInfra, setSharedInfra] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filterType, setFilterType] = useState('ALL')

  useEffect(() => {
    let ignore = false
    Promise.all([getCorrelationGraph(), getSharedInfrastructure()])
      .then(([g, s]) => {
        if (!ignore) {
          setGraphData(g || { nodes: [], links: [] })
          setSharedInfra(s || {})
          setLoading(false)
        }
      })
      .catch((err) => {
        if (!ignore) {
          setError(err.message)
          setLoading(false)
        }
      })
    return () => {
      ignore = true
    }
  }, [])

  const rawNodes = graphData?.elements?.nodes || graphData?.nodes || []
  const allNodes = rawNodes.map((n) => n.data || n)
  const rawEdges = graphData?.elements?.edges || graphData?.links || []
  const allEdges = rawEdges.map((e) => e.data || e)
  const stats = graphData?.stats || {}

  const filteredNodes = allNodes.filter((n) => {
    const t = (n.nodeType || n.type || '').toUpperCase()
    return filterType === 'ALL' || t === filterType
  })

  const nodeColor = (type) => {
    switch (type?.toLowerCase()) {
      case 'email':
        return 'bg-primary text-white'
      case 'ip':
        return 'bg-warning/20 text-warning border-warning/40'
      case 'domain':
      case 'sender':
        return 'bg-info/20 text-info border-info/40'
      case 'case':
        return 'bg-purple-100 text-purple-700 border-purple-300'
      case 'hash':
      case 'attachment':
        return 'bg-danger/20 text-danger border-danger/40'
      default:
        return 'bg-surface text-text border-border'
    }
  }

  const sharedKeys = sharedInfra ? Object.keys(sharedInfra) : []

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-text">Threat Correlation & Campaign Graph</h2>
          <p className="text-text-muted mt-1">Cross-email intelligence discovering shared infrastructure and coordinated attacks</p>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-danger-bg border border-danger/20 rounded-lg text-danger text-sm">
          {error}
        </div>
      )}

      {/* Shared Infrastructure Alert if coordinated campaigns detected */}
      {sharedKeys.length > 0 && (
        <div className="p-5 bg-warning-bg border border-warning/30 rounded-xl space-y-3">
          <div className="flex items-center gap-2 text-warning font-bold text-sm">
            <span>⚡</span>
            <span>Coordinated Campaign Alert: Shared Infrastructure Detected</span>
          </div>
          <p className="text-xs text-text-muted">
            The following indicators of compromise (IOCs) are shared across multiple analyzed emails, indicating coordinated adversary infrastructure:
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 pt-1">
            {sharedKeys.map((k) => (
              <div key={k} className="p-3 bg-white/80 rounded-lg border border-warning/30">
                <span className="text-xs font-mono font-semibold text-text">{k}</span>
                <p className="text-[11px] text-text-dim mt-1">
                  Shared across: {Array.isArray(sharedInfra[k]) ? sharedInfra[k].join(', ') : JSON.stringify(sharedInfra[k])}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Graph Overview Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-surface p-4 rounded-xl border border-border">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-text-muted">Filter:</span>
          {['ALL', 'EMAIL', 'IP', 'DOMAIN', 'SENDER', 'CASE'].map((t) => (
            <button
              key={t}
              onClick={() => setFilterType(t)}
              className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                filterType === t
                  ? 'bg-primary text-white'
                  : 'bg-surface-alt text-text-muted hover:bg-border/60'
              }`}
            >
              {t}
            </button>
          ))}
        </div>
        <div className="text-xs text-text-dim">
          Nodes: <strong>{stats.total_nodes || allNodes.length}</strong> &nbsp;|&nbsp;
          Relationships: <strong>{stats.total_edges || allEdges.length}</strong>
        </div>
      </div>

      {loading ? (
        <div className="text-center py-12 text-text-dim">Analyzing correlation matrix...</div>
      ) : filteredNodes.length === 0 ? (
        <div className="text-center py-16 bg-surface rounded-xl border border-border text-text-muted">
          <p className="font-medium">No correlation nodes found.</p>
          <p className="text-xs text-text-dim mt-1">Upload and analyze emails to populate the threat correlation graph.</p>
          <Link to="/" className="inline-block mt-4 text-primary text-sm font-medium hover:underline">
            Upload email →
          </Link>
        </div>
      ) : (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredNodes.map((node, idx) => {
              const nodeType = node.nodeType || node.type || 'ENTITY'
              return (
                <div key={node.id || idx} className="p-4 bg-surface rounded-xl border border-border hover:border-primary/50 transition-all space-y-2">
                  <div className="flex items-center justify-between">
                    <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border font-semibold ${nodeColor(nodeType)}`}>
                      {nodeType}
                    </span>
                    {nodeType === 'email' && node.email_id && (
                      <Link to={`/emails/${node.email_id}`} className="text-xs text-primary hover:underline">
                        View Details →
                      </Link>
                    )}
                  </div>
                  <p className="text-sm font-semibold text-text truncate" title={node.label || node.id}>
                    {node.label || node.id}
                  </p>
                  <p className="text-xs font-mono text-text-dim truncate">
                    ID: {node.id}
                  </p>
                </div>
              )
            })}
          </div>

          {/* Graph Correlation Edges */}
          {allEdges.length > 0 && (
            <div className="bg-surface rounded-xl border border-border p-5 space-y-3">
              <h3 className="text-sm font-bold text-text">Correlated Threat Links ({allEdges.length})</h3>
              <div className="divide-y divide-border/60 text-xs">
                {allEdges.map((edge, idx) => (
                  <div key={edge.id || idx} className="py-2.5 flex items-center justify-between gap-4 font-mono">
                    <span className="text-text font-semibold truncate flex-1">{edge.source}</span>
                    <span className="px-2 py-0.5 rounded bg-surface-alt border border-border text-primary font-bold text-[10px]">
                      ── {edge.edgeType || 'CONNECTED_TO'} ──▶
                    </span>
                    <span className="text-text-muted truncate flex-1 text-right">{edge.target}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
