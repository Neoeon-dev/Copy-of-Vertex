import { useEffect, useState } from 'react'
import { getAuditLogs, verifyAuditLog } from '../api'

export default function AuditTrailPage() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [verifying, setVerifying] = useState(false)
  const [verifyResult, setVerifyResult] = useState(null)

  const fetchLogs = () => getAuditLogs(0, 100).then((data) => setLogs(data || [])).catch((err) => setError(err.message)).finally(() => setLoading(false))
  useEffect(() => { fetchLogs() }, [])

  const handleVerify = async () => {
    setVerifying(true); setVerifyResult(null)
    try { setVerifyResult(await verifyAuditLog()) } catch (err) { setVerifyResult({ valid: false, error: err.message }) } finally { setVerifying(false) }
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between"><div><p className="section-label">Evidence integrity</p><h1 className="mt-2 text-3xl font-bold tracking-tight text-slate-950">Audit ledger</h1><p className="mt-2 text-sm text-slate-500">Review the append-only evidence chain and verify its integrity.</p></div><button onClick={handleVerify} disabled={verifying} className="btn-primary">{verifying ? 'Verifying…' : 'Verify hash chain'}</button></div>
      {error && <div className="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-700">{error}</div>}
      {verifyResult && <div className={`rounded-3xl border p-5 ${verifyResult.valid ? 'border-emerald-200 bg-emerald-50' : 'border-red-200 bg-red-50'}`}><div className="flex items-start gap-3"><div className={`mt-0.5 flex h-9 w-9 items-center justify-center rounded-2xl ${verifyResult.valid ? 'bg-emerald-100 text-emerald-700' : 'bg-red-100 text-red-700'}`}>{verifyResult.valid ? '✓' : '!'}</div><div className="min-w-0"><p className={`text-sm font-bold ${verifyResult.valid ? 'text-emerald-800' : 'text-red-800'}`}>{verifyResult.valid ? 'Hash chain verified' : 'Verification failed'}</p><p className={`mt-1 text-xs leading-5 ${verifyResult.valid ? 'text-emerald-700' : 'text-red-700'}`}>{verifyResult.message || verifyResult.error || `Checked ${logs.length} ledger entries.`}</p></div></div></div>}
      <div className="grid gap-3 md:grid-cols-3"><Metric label="Ledger events" value={logs.length} /><Metric label="Integrity algorithm" value="SHA-256" mono /><Metric label="Chain state" value="Tamper-evident" tone="success" /></div>
      {loading ? <div className="space-y-3">{[1,2,3,4].map((i) => <div key={i} className="surface-card h-24 animate-pulse bg-slate-100" />)}</div> : logs.length === 0 ? <div className="surface-card p-10 text-center text-sm text-slate-500">No audit entries recorded yet.</div> : <div className="space-y-3">{logs.map((log) => <div key={log.id} className="surface-card p-4 sm:p-5"><div className="flex flex-col gap-4 sm:flex-row sm:items-center"><div className="min-w-0 sm:w-44"><p className="text-[10px] font-bold uppercase tracking-[0.16em] text-slate-400">Timestamp</p><p className="mt-1 text-xs text-slate-600">{new Date(log.timestamp).toLocaleString()}</p></div><div className="sm:w-36"><p className="text-[10px] font-bold uppercase tracking-[0.16em] text-slate-400">Action</p><span className="mt-1 inline-flex rounded-full bg-indigo-50 px-2.5 py-1 text-[10px] font-bold text-indigo-600">{log.action}</span></div><div className="min-w-0 flex-1"><p className="text-[10px] font-bold uppercase tracking-[0.16em] text-slate-400">Entity</p><p className="mt-1 truncate text-sm font-semibold text-slate-800">{log.entity_type}{log.entity_id ? ` #${log.entity_id}` : ''}</p></div><div className="min-w-0 sm:w-56"><p className="text-[10px] font-bold uppercase tracking-[0.16em] text-slate-400">Entry hash</p><p title={log.entry_hash} className="mt-1 truncate font-mono text-xs text-slate-500">{log.entry_hash ? `${log.entry_hash.slice(0, 18)}…` : '—'}</p></div></div></div>)}</div>}
    </div>
  )
}

function Metric({ label, value, mono = false, tone }) { return <div className="surface-card p-5"><p className="section-label">{label}</p><p className={`mt-2 text-2xl font-bold tracking-tight ${tone === 'success' ? 'text-emerald-600' : 'text-slate-900'} ${mono ? 'font-mono text-lg' : ''}`}>{value}</p></div> }
