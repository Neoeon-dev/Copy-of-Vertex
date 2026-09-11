'use client'

import { useEffect, useState } from 'react'
import { Check, Clock3, Copy, Fingerprint, RefreshCw, ShieldCheck, Terminal } from 'lucide-react'
import { getAuditLogs, verifyAuditLog } from '../../lib/api'
import { Alert, Badge, Button, Card, EmptyState, MetricCard, Page, PageHeader, Skeleton } from '../../components/ui'

export default function AuditPage() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [checking, setChecking] = useState(false)
  const [result, setResult] = useState(null)

  async function load() {
    setLoading(true); setError('')
    try { setLogs((await getAuditLogs()) || []) } catch (err) { setError(err.message) } finally { setLoading(false) }
  }
  useEffect(() => { load() }, [])
  async function verify() { setChecking(true); setResult(null); try { setResult(await verifyAuditLog()) } catch (err) { setResult({ valid: false, message: err.message }) } finally { setChecking(false) } }
  function copy(value) { if (value) navigator.clipboard?.writeText(value) }

  return <Page>
    <PageHeader eyebrow="Evidence integrity" title="Audit ledger" description="Cryptographically verifiable activity history for forensic actions and evidence state." actions={<Button onClick={verify} disabled={checking}><ShieldCheck size={15} /> {checking ? 'Verifying…' : 'Verify hash chain'}</Button>} />
    {result && <div className="mb-5"><Alert tone={result.valid ? 'success' : 'danger'}><div className="font-bold">{result.valid ? 'Cryptographic verification passed.' : 'Verification failed.'}</div><div className="mt-1 text-xs opacity-80">{result.message || `Verified ${logs.length} ledger entries.`}</div></Alert></div>}
    {error && <div className="mb-5"><Alert>{error}</Alert></div>}
    <div className="mb-5 grid gap-3 md:grid-cols-3"><MetricCard label="Ledger events" value={logs.length} icon={Terminal} tone="primary" /><MetricCard label="Integrity model" value="SHA-256" hint="Chained entries" icon={Fingerprint} /><MetricCard label="Chain state" value={result?.valid === false ? 'Review' : 'Ready'} icon={ShieldCheck} tone={result?.valid === false ? 'danger' : 'success'} /></div>
    {loading ? <div className="space-y-3">{[1,2,3,4].map((x) => <Skeleton key={x} className="h-[96px]" />)}</div> : logs.length === 0 ? <EmptyState icon={Clock3} title="No audit events yet" description="Upload or analyze an email to generate forensic ledger entries." /> : <Card className="overflow-hidden"><div className="divide-y divide-border">{logs.map((log, index) => <div key={log.id} className="relative p-4 sm:p-5"><div className="flex gap-4"><div className="relative flex w-6 shrink-0 justify-center"><div className={`z-10 mt-1 h-3 w-3 rounded-full ring-4 ring-white ${index === 0 ? 'bg-primary' : 'bg-slate-300'}`} />{index < logs.length - 1 && <div className="absolute left-1/2 top-4 h-full w-px -translate-x-1/2 bg-border" />}</div><div className="min-w-0 flex-1"><div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between"><div><div className="flex flex-wrap items-center gap-2"><Badge tone="primary">{log.action}</Badge><span className="text-xs font-bold text-text">{log.entity_type}{log.entity_id ? ` #${log.entity_id}` : ''}</span></div><div className="mt-1 text-[11px] text-text-secondary">{log.actor || 'system'} · {log.timestamp ? new Date(log.timestamp).toLocaleString() : 'Unknown time'}</div></div><span className="text-[10px] font-mono text-text-tertiary">event {log.id}</span></div><div className="mt-3 grid gap-2 md:grid-cols-2"><HashRow label="Entry hash" value={log.entry_hash} copy={copy} /><HashRow label="Previous hash" value={log.previous_hash} copy={copy} /></div></div></div></div>)}</div></Card>}
  </Page>
}

function HashRow({ label, value, copy }) { return <div className="rounded-xl border border-border bg-surface-muted p-3"><div className="flex items-center justify-between gap-2"><span className="text-[10px] font-bold uppercase tracking-wider text-text-tertiary">{label}</span>{value && <button onClick={() => copy(value)} className="rounded-lg p-1.5 text-text-tertiary hover:bg-white hover:text-text"><Copy size={13} /></button>}</div><div className="mt-1 truncate font-mono text-[11px] text-text">{value || 'genesis'}</div></div> }
