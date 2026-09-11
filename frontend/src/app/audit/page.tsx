'use client'

import { useEffect, useState } from 'react'
import { Copy, Fingerprint, ShieldCheck, Terminal, RotateCw } from 'lucide-react'
import { Alert, Badge, Button, Card, EmptyState, Page, PageHeader, Skeleton } from '../../components/ui'
import { apiError, getAuditLogs, verifyAuditLog } from '../../lib/api'
import { formatDate } from '../../lib/utils'
import type { AuditLog, AuditVerification } from '../../types/api'

export default function AuditPage() {
  const [logs, setLogs] = useState<AuditLog[]>([])
  const [result, setResult] = useState<AuditVerification | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function load() { setLoading(true); setError(''); try { setLogs(await getAuditLogs(0,100)) } catch (e) { setError(apiError(e)) } finally { setLoading(false) } }
  useEffect(()=>{load()},[])
  async function verify() { setBusy(true); setError(''); try { setResult(await verifyAuditLog()) } catch (e) { setError(apiError(e)) } finally { setBusy(false) } }
  function copy(value:string) { navigator.clipboard?.writeText(value).catch(()=>undefined) }

  return <Page><PageHeader eyebrow="Evidence integrity" title="Audit ledger" description="Append-only forensic activity recorded by the backend. Verify the chained hash structure when you need an integrity check." actions={<><Button variant="secondary" onClick={load}><RotateCw size={14}/> Refresh</Button><Button onClick={verify} disabled={busy} busy={busy}><ShieldCheck size={14}/> Verify chain</Button></>}/>{error?<Alert className="mb-5">{error}</Alert>:null}{result?<Alert tone={result.valid?'success':'danger'} className="mb-5"><div className="flex flex-wrap items-center justify-between gap-3"><div><div className="font-bold">{result.valid?'Verification passed':'Verification failed'}</div><div className="mt-1 text-xs opacity-80">{result.entry_count} ledger entries checked.</div></div><Badge tone={result.valid?'success':'danger'}>{result.valid?'VALID':'REVIEW'}</Badge></div>{result.errors.length?<ul className="mt-3 list-disc space-y-1 pl-4 text-xs">{result.errors.map((x,i)=><li key={i}>{x}</li>)}</ul>:null}</Alert>:null}<div className="mb-5 grid gap-3 md:grid-cols-3"><Metric label="Events" value={logs.length} icon={Terminal}/><Metric label="Integrity model" value="SHA-256" icon={Fingerprint}/><Metric label="Current state" value={result?.valid===false?'Review':'Ready'} icon={ShieldCheck}/></div>{loading?<div className="space-y-2">{[1,2,3,4].map(i=><Skeleton key={i} className="h-24"/>)}</div>:logs.length===0?<EmptyState title="No audit events yet" description="Upload, analyze, or link evidence to a case to generate ledger entries."/>:<Card className="overflow-hidden"><div className="divide-y divide-border">{logs.map((log,index)=><div key={log.id} className="p-4 sm:p-5"><div className="flex gap-4"><div className="flex w-5 shrink-0 flex-col items-center"><div className={`mt-1 h-3 w-3 ${index===0?'bg-slate-950':'bg-slate-300'}`}/>{index<logs.length-1?<div className="mt-1 w-px flex-1 bg-border"/>:null}</div><div className="min-w-0 flex-1"><div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between"><div><div className="flex flex-wrap items-center gap-2"><Badge tone="primary">{log.action}</Badge><span className="text-xs font-bold">{log.entity_type}{log.entity_id?` #${log.entity_id}`:''}</span></div><div className="mt-1 text-[11px] text-text-tertiary">{log.actor || 'system'} · {formatDate(log.timestamp)}</div></div><span className="text-[10px] font-mono text-text-tertiary">event {log.id}</span></div>{log.details?<div className="mt-3 border-l-2 border-border pl-3 text-xs leading-5 text-text-secondary">{log.details}</div>:null}<div className="mt-3 flex items-center gap-2 border border-border bg-surface-soft p-2.5"><div className="min-w-0 flex-1 truncate font-mono text-[10px] text-text-secondary">{log.entry_hash}</div><button onClick={()=>copy(log.entry_hash)} className="border border-border bg-white p-1.5 text-text-tertiary hover:text-text" title="Copy hash"><Copy size={13}/></button></div></div></div></div>)}</div></Card>}</Page>
}

function Metric({label,value,icon:Icon}:{label:string;value:string|number;icon:typeof Terminal}) { return <Card className="p-4"><div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-wider text-text-tertiary"><Icon size={14}/>{label}</div><div className="mt-2 text-2xl font-black">{value}</div></Card> }
