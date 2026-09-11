'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { useParams } from 'next/navigation'
import { motion } from 'motion/react'
import { Activity, CheckCircle2, Copy, Download, FileText, Globe2, Link2, LoaderCircle, LockKeyhole, Mail, Paperclip, Server, ShieldAlert, ShieldCheck, Waypoints } from 'lucide-react'
import { Alert, Badge, Button, Card, Page, PageHeader, Skeleton } from '../../../components/ui'
import { addEmailToGraph, apiError, classifyEmail, computeRisk, getAuthentication, getEmail, getReportUrl, runFullAnalysis, verifyEvidence } from '../../../lib/api'
import { formatBytes, formatDate, humanize, riskTone } from '../../../lib/utils'
import type { AuthenticationSummary, EmailDetail, FullAnalysis, MLClassification, RiskAssessment } from '../../../types/api'

export default function EmailDetailPage() {
  const { id } = useParams<{ id: string }>()
  const emailId = Number(id)
  const [email, setEmail] = useState<EmailDetail | null>(null)
  const [auth, setAuth] = useState<AuthenticationSummary | null>(null)
  const [analysis, setAnalysis] = useState<FullAnalysis | null>(null)
  const [ml, setMl] = useState<MLClassification | null>(null)
  const [risk, setRisk] = useState<RiskAssessment | null>(null)
  const [verification, setVerification] = useState<Awaited<ReturnType<typeof verifyEvidence>> | null>(null)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  useEffect(() => {
    if (!Number.isFinite(emailId)) return
    let alive = true
    Promise.all([getEmail(emailId), getAuthentication(emailId)]).then(([mail, authentication]) => { if (!alive) return; setEmail(mail); setAuth(authentication) }).catch((e)=>alive&&setError(apiError(e))).finally(()=>alive&&setLoading(false))
    return () => { alive = false }
  }, [emailId])

  async function runAnalysis() {
    setRunning(true); setError(''); setNotice('')
    try {
      const [fullResult, classification, assessment] = await Promise.all([runFullAnalysis(emailId), classifyEmail(emailId), computeRisk(emailId)])
      setAnalysis(fullResult); setMl(classification); setRisk(assessment)
    } catch (e) { setError(apiError(e)) } finally { setRunning(false) }
  }

  async function verify() { try { setVerification(await verifyEvidence(emailId)) } catch (e) { setNotice(apiError(e)) } }
  async function correlate() { try { await addEmailToGraph(emailId); setNotice('Email linked to the correlation graph.') } catch (e) { setNotice(apiError(e)) } }
  function copy(value?: string | null) { if (value) navigator.clipboard?.writeText(value).then(()=>setNotice('Copied to clipboard.')).catch(()=>undefined) }

  const score = risk?.score ?? (analysis ? Math.round(analysis.overall_risk_score * 100) : null)
  const level = risk?.level ?? (score === null ? 'UNASSESSED' : score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW')
  const categoryRows = useMemo(() => Object.entries(risk?.category_scores || {}).sort((a,b)=>b[1]-a[1]), [risk])

  if (loading) return <Page><div className="space-y-3"><Skeleton className="h-12 w-2/3"/><Skeleton className="h-40 w-full"/><Skeleton className="h-64 w-full"/></div></Page>
  if (!email) return <Page><Alert>{error || 'Email not found.'}</Alert></Page>

  return <Page>
    <PageHeader back={{ href: '/emails', label: 'Back to email feed' }} eyebrow={`Evidence #${email.id}`} title={email.subject || '(no subject)'} description={`${email.sender || 'Unknown sender'} · ${formatDate(email.date || email.created_at)}`} actions={<><Badge tone={riskTone(level)}>{level}{score !== null ? ` · ${Math.round(score)}/100` : ''}</Badge><Button variant="secondary" onClick={()=>window.open(getReportUrl(email.id),'_blank')}><Download size={14}/> Export report</Button></>}/>
    {error ? <Alert className="mb-4">{error}</Alert> : null}
    {notice ? <Alert tone="info" className="mb-4">{notice}</Alert> : null}

    <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
      <div className="space-y-5">
        <Card className="p-5 sm:p-6"><div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between"><div className="min-w-0"><div className="text-[10px] font-black uppercase tracking-[.14em] text-text-tertiary">Investigation</div><h2 className="mt-1 text-lg font-black">Evidence overview</h2><p className="mt-1 max-w-2xl text-sm leading-6 text-text-secondary">Run the existing backend analysis only when you need the deeper forensic findings. Nothing here invents a result the API did not return.</p></div><Button onClick={runAnalysis} disabled={running} busy={running}><Activity size={15}/>{running ? 'Running analysis…' : analysis ? 'Re-run analysis' : 'Run full analysis'}</Button></div></Card>

        {risk || analysis ? <Card className="p-5 sm:p-6"><div className="grid gap-6 lg:grid-cols-[180px_minmax(0,1fr)] lg:items-center"><RiskGauge score={score ?? 0} level={level}/><div><div className="flex flex-wrap items-center gap-2"><Badge tone={riskTone(level)}>{level}</Badge>{ml ? <span className="text-xs font-semibold text-text-secondary">Classifier: {ml.label} · {Math.round(ml.confidence * 100)}% confidence</span> : null}</div>{risk?.summary ? <p className="mt-3 text-sm leading-6 text-text-secondary">{risk.summary}</p> : null}<div className="mt-5 grid gap-3 sm:grid-cols-2">{categoryRows.slice(0,6).map(([key,value])=><div key={key}><div className="mb-1.5 flex items-center justify-between text-[10px] font-bold uppercase tracking-wider text-text-tertiary"><span>{humanize(key)}</span><span>{Math.round(value)}</span></div><div className="h-1.5 bg-border"><motion.div initial={{width:0}} animate={{width:`${Math.min(100,Math.max(0,value))}%`}} className={`h-full ${value >= 60 ? 'bg-danger' : value >= 30 ? 'bg-warning' : 'bg-slate-950'}`}/></div></div>)}</div></div></div></Card> : <Card className="p-6"><div className="flex items-start gap-3"><ShieldAlert size={18} className="mt-0.5 text-text-secondary"/><div><div className="text-sm font-bold">Risk has not been assessed yet</div><div className="mt-1 text-sm leading-6 text-text-secondary">Run the full analysis to calculate the 0–100 weighted risk score and explanation.</div></div></div></Card>}

        <div className="grid gap-5 md:grid-cols-2"><AuthCard auth={auth}/><Card className="p-5"><SectionHeading icon={Mail} title="Message metadata"/><div className="mt-4 space-y-3"><Row label="From" value={email.sender}/><Row label="Display name" value={email.sender_name}/><Row label="Reply-To" value={email.reply_to}/><Row label="To" value={email.to.map((x)=>x.address || x.name).filter(Boolean).join(', ') || '—'}/><Row label="Date" value={formatDate(email.date)}/></div></Card></div>

        {analysis ? <Card className="p-5"><SectionHeading icon={Server} title="Mail path & indicators"/><div className="mt-4 grid gap-3 sm:grid-cols-3"><MiniMetric label="Received hops" value={analysis.total_hops}/><MiniMetric label="Public IPs" value={analysis.public_ips.length}/><MiniMetric label="URLs" value={analysis.total_urls}/></div>{analysis.received_anomalies.length ? <div className="mt-4 border border-amber-200 bg-amber-50 p-3 text-xs text-amber-950"><div className="font-bold">Header anomalies</div><ul className="mt-2 list-disc space-y-1 pl-4">{analysis.received_anomalies.map((x,i)=><li key={i}>{x}</li>)}</ul></div> : null}</Card> : null}

        {risk?.contributions?.length ? <Card className="p-5"><SectionHeading icon={ShieldCheck} title="Top contributing signals"/><div className="mt-4 space-y-2">{risk.contributions.filter((x)=>x.contribution>0).sort((a,b)=>b.contribution-a.contribution).slice(0,8).map((item,index)=><div key={`${item.signal}-${index}`} className="grid gap-2 border border-border p-3 sm:grid-cols-[auto_1fr_auto] sm:items-start"><Badge tone={item.confidence==='fact'?'info':item.confidence==='inference'?'warning':'neutral'}>{item.confidence}</Badge><div className="text-xs leading-5 text-text-secondary">{item.description}</div><div className="font-mono text-[11px] font-bold text-text">+{item.contribution.toFixed(1)}</div></div>)}</div></Card> : null}

        <Card className="p-5"><SectionHeading icon={FileText} title="Message body"/><div className="mt-4 border border-border bg-surface-soft p-4"><pre className="max-h-[420px] overflow-auto whitespace-pre-wrap break-words font-sans text-sm leading-6 text-text-secondary">{email.body_text || 'No plain-text body stored.'}</pre></div></Card>
      </div>

      <div className="space-y-5"><Card className="p-5"><SectionHeading icon={LockKeyhole} title="Evidence integrity"/><div className="mt-4 border border-border bg-surface-soft p-4"><div className="flex items-center gap-2 text-xs font-bold"><span className="h-2 w-2 bg-success"/>Evidence chain available</div><p className="mt-2 text-xs leading-5 text-text-secondary">Verify the stored evidence chain before relying on this artifact in an investigation.</p><Button className="mt-4 w-full" variant="secondary" onClick={verify}><CheckCircle2 size={14}/> Verify evidence</Button>{verification ? <div className="mt-3 border-t border-border pt-3"><div className={`text-xs font-black ${verification.valid ? 'text-success' : 'text-danger'}`}>{verification.valid ? 'VERIFIED' : 'TAMPERED'}</div><div className="mt-1 text-xs text-text-secondary">{verification.entry_count} chain entr{verification.entry_count === 1 ? 'y' : 'ies'} checked.</div>{verification.errors.length ? <ul className="mt-2 list-disc space-y-1 pl-4 text-[11px] text-danger">{verification.errors.map((x,i)=><li key={i}>{x}</li>)}</ul> : null}</div> : null}</div></Card>
        <Card className="p-5"><SectionHeading icon={Waypoints} title="Threat correlation"/><p className="mt-2 text-xs leading-5 text-text-secondary">Add this email and its extracted indicators to the in-memory correlation graph.</p><Button className="mt-4 w-full" variant="secondary" onClick={correlate}><Link2 size={14}/> Add to graph</Button><Link href="/graph" className="mt-3 inline-flex text-xs font-bold text-primary hover:underline">Open correlation workspace →</Link></Card>
        <Card className="p-5"><SectionHeading icon={Paperclip} title="Attachments"/><div className="mt-4 space-y-2">{email.attachments.length ? email.attachments.map((item)=><div key={item.id} className="border border-border p-3"><div className="text-xs font-bold">{item.filename || 'unnamed attachment'}</div><div className="mt-1 text-[10px] text-text-tertiary">{item.content_type} · {formatBytes(item.size)}</div><div className="mt-2 truncate font-mono text-[10px] text-text-secondary">SHA {item.sha256}</div></div>) : <div className="text-xs text-text-tertiary">No attachments stored.</div>}</div></Card>
        <Card className="p-5"><SectionHeading icon={Globe2} title="Evidence hash"/><div className="mt-3 break-all border border-border bg-surface-soft p-3 font-mono text-[10px] leading-5 text-text-secondary">{email.sha256}</div><Button variant="ghost" className="mt-2 w-full" onClick={()=>copy(email.sha256)}><Copy size={14}/> Copy SHA-256</Button></Card></div>
    </div>
  </Page>
}

function RiskGauge({score, level}:{score:number;level:string}) { const pct=Math.max(0,Math.min(100,score)); return <div className="relative mx-auto grid h-40 w-40 place-items-center"><svg viewBox="0 0 120 120" className="h-full w-full -rotate-90"><circle cx="60" cy="60" r="48" fill="none" stroke="#e2e3e6" strokeWidth="10"/><motion.circle cx="60" cy="60" r="48" fill="none" stroke={pct>=75?'#c92a2a':pct>=50?'#a85d00':pct>=25?'#4f46e5':'#16803c'} strokeWidth="10" strokeLinecap="butt" strokeDasharray={2*Math.PI*48} initial={{strokeDashoffset:2*Math.PI*48}} animate={{strokeDashoffset:2*Math.PI*48*(1-pct/100)}} transition={{duration:.8,ease:'easeOut'}}/></svg><div className="absolute text-center"><div className="text-4xl font-black tracking-[-.05em]">{Math.round(pct)}</div><div className="text-[9px] font-black uppercase tracking-[.16em] text-text-tertiary">{level}</div></div></div> }
function AuthCard({auth}:{auth:AuthenticationSummary|null}) { return <Card className="p-5"><SectionHeading icon={ShieldCheck} title="Authentication"/><div className="mt-4 grid gap-2">{[['SPF',auth?.spf],['DKIM',auth?.dkim],['DMARC',auth?.dmarc]].map(([name,item])=><div key={name as string} className="flex items-center justify-between border border-border px-3 py-2.5"><div><div className="text-xs font-bold">{name as string}</div><div className="mt-0.5 truncate text-[10px] text-text-tertiary">{(item as any)?.domain || 'no domain returned'}</div></div><Badge tone={(item as any)?.result === 'PASS' ? 'success' : (item as any)?.result === 'FAIL' ? 'danger' : (item as any) ? 'warning' : 'neutral'}>{(item as any)?.result || 'NOT RUN'}</Badge></div>)}</div></Card> }
function SectionHeading({icon:Icon,title}:{icon:typeof ShieldCheck;title:string}) { return <div className="flex items-center gap-2 text-sm font-black"><div className="grid h-8 w-8 place-items-center border border-border bg-surface-soft text-text-secondary"><Icon size={15}/></div>{title}</div> }
function Row({label,value}:{label:string;value?:string|null}) { return <div className="flex gap-3"><div className="w-20 shrink-0 text-[10px] font-black uppercase tracking-wider text-text-tertiary">{label}</div><div className="min-w-0 break-all text-xs text-text-secondary">{value || '—'}</div></div> }
function MiniMetric({label,value}:{label:string;value:number}) { return <div className="border border-border p-3"><div className="text-[10px] font-black uppercase tracking-wider text-text-tertiary">{label}</div><div className="mt-1 text-xl font-black">{value}</div></div> }
