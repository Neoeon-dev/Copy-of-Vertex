'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { useParams } from 'next/navigation'
import { motion } from 'motion/react'
import { Activity, CheckCircle2, Copy, Download, FileText, Globe2, Link2, LockKeyhole, Mail, Paperclip, Server, ShieldAlert, ShieldCheck, Waypoints } from 'lucide-react'
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
    Promise.all([getEmail(emailId), getAuthentication(emailId)])
      .then(([mail, authentication]) => { if (alive) { setEmail(mail); setAuth(authentication) } })
      .catch((e) => alive && setError(apiError(e)))
      .finally(() => alive && setLoading(false))
    return () => { alive = false }
  }, [emailId])

  async function runAnalysis() {
    setRunning(true); setError(''); setNotice('')
    try {
      const [fullResult, classification, assessment] = await Promise.all([
        runFullAnalysis(emailId), classifyEmail(emailId), computeRisk(emailId),
      ])
      setAnalysis(fullResult); setMl(classification); setRisk(assessment)
    } catch (e) { setError(apiError(e)) } finally { setRunning(false) }
  }

  async function verify() { try { setVerification(await verifyEvidence(emailId)); setNotice('Evidence chain verification completed.') } catch (e) { setNotice(apiError(e)) } }
  async function correlate() { try { await addEmailToGraph(emailId); setNotice('Email linked to the correlation graph.') } catch (e) { setNotice(apiError(e)) } }
  function copy(value?: string | null) { if (!value) return; navigator.clipboard?.writeText(value).then(() => setNotice('Copied to clipboard.')).catch(() => undefined) }

  const score = risk?.score ?? (analysis ? Math.round(analysis.overall_risk_score * 100) : null)
  const level = risk?.level ?? (score === null ? 'UNASSESSED' : score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW')
  const categoryRows = useMemo<[string, number][]>(() => Object.entries(risk?.category_scores || {}).map(([key, value]) => [key, Number(value)] as [string, number]).sort((a, b) => b[1] - a[1]), [risk])
  const topContribs = useMemo(() => risk?.contributions?.filter((x) => x.contribution > 0).sort((a, b) => b.contribution - a.contribution).slice(0, 8) ?? [], [risk])

  if (loading) return <Page><div className="space-y-4"><Skeleton className="h-14 w-3/4"/><div className="grid gap-4 lg:grid-cols-[1.5fr_1fr] lg:items-stretch"><Skeleton className="h-72"/><Skeleton className="h-72"/></div><Skeleton className="h-80"/></div></Page>
  if (!email) return <Page><Alert>{error || 'Email not found.'}</Alert></Page>

  return <Page>
    <PageHeader
      back={{ href: '/emails', label: 'Back to email feed' }}
      eyebrow={`Evidence #${email.id}`}
      title={email.subject || '(no subject)'}
      description={`${email.sender || 'Unknown sender'} · ${formatDate(email.date || email.created_at)}`}
      actions={<><Badge tone={riskTone(level)}>{level}{score !== null ? ` · ${Math.round(score)}/100` : ''}</Badge><Button variant="secondary" onClick={() => window.open(getReportUrl(email.id), '_blank')}><Download size={14}/> Export report</Button></>}
    />
    {error ? <Alert className="mb-4">{error}</Alert> : null}
    {notice ? <Alert tone="info" className="mb-4">{notice}</Alert> : null}

    <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
      <div className="space-y-5">
        <Card className="p-5 sm:p-6">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
            <div><div className="text-[10px] font-black uppercase tracking-[.14em] text-text-tertiary">Investigation</div><h2 className="mt-1 text-lg font-black">Evidence overview</h2><p className="mt-1 max-w-2xl text-sm leading-6 text-text-secondary">The screen stays grounded in the actual API responses. Run the heavier forensic pipeline only when you want the expanded explanation.</p></div>
            <Button onClick={runAnalysis} disabled={running} busy={running}><Activity size={15}/>{running ? 'Running analysis…' : analysis ? 'Re-run analysis' : 'Run full analysis'}</Button>
          </div>
        </Card>

        {risk || analysis ? <>
          <Card className="overflow-hidden p-5 sm:p-6">
            <div className="grid gap-6 lg:grid-cols-[220px_minmax(0,1fr)] lg:items-center">
              <RiskGauge score={score ?? 0} level={level}/>
              <div>
                <div className="flex flex-wrap items-center gap-2"><Badge tone={riskTone(level)}>{level}</Badge>{ml ? <span className="text-xs font-semibold text-text-secondary">Classifier: {ml.label} · {Math.round(ml.confidence * 100)}% confidence</span> : null}</div>
                {risk?.summary ? <p className="mt-3 text-sm leading-6 text-text-secondary">{risk.summary}</p> : null}
                <RiskCategoryChart rows={categoryRows}/>
              </div>
            </div>
          </Card>

          <div className="grid gap-5 lg:grid-cols-2">
            {ml ? <ProbabilityChart ml={ml}/> : <Card className="p-5"><SectionHeading icon={ShieldAlert} title="Model classification"/><p className="mt-4 text-sm text-text-secondary">Run the full analysis to populate the classifier probabilities and signal breakdown.</p></Card>}
            {analysis ? <IndicatorChart analysis={analysis} email={email}/> : <Card className="p-5"><SectionHeading icon={Server} title="Forensic indicators"/><p className="mt-4 text-sm text-text-secondary">The graph fills after the full forensic pipeline returns.</p></Card>}
          </div>
        </> : <Card className="p-6"><div className="flex items-start gap-3"><ShieldAlert size={18} className="mt-0.5 text-text-secondary"/><div><div className="text-sm font-bold">Risk has not been assessed yet</div><div className="mt-1 text-sm leading-6 text-text-secondary">Run the full analysis to calculate the weighted 0–100 score and the explainable signal breakdown.</div></div></div></Card>}

        <div className="grid gap-5 md:grid-cols-2"><AuthCard auth={auth}/><Card className="p-5"><SectionHeading icon={Mail} title="Message metadata"/><div className="mt-4 space-y-3"><Row label="From" value={email.sender}/><Row label="Display name" value={email.sender_name}/><Row label="Reply-To" value={email.reply_to}/><Row label="To" value={email.to.map((x) => x.address || x.name).filter(Boolean).join(', ') || '—'}/><Row label="Date" value={formatDate(email.date)}/><Row label="Message-ID" value={email.message_id}/></div></Card></div>

        <InvestigationTimeline email={email} auth={auth} analysis={analysis} risk={risk} verification={verification}/>

        {analysis ? <Card className="p-5"><SectionHeading icon={Server} title="Mail path & forensic indicators"/><div className="mt-4 grid gap-3 sm:grid-cols-4"><MiniMetric label="Received hops" value={analysis.total_hops}/><MiniMetric label="Public IPs" value={analysis.public_ips.length}/><MiniMetric label="Domains" value={analysis.domain_analysis.length}/><MiniMetric label="URLs" value={analysis.total_urls}/></div>{analysis.received_anomalies.length ? <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-3 text-xs text-amber-950 dark:border-amber-900/50 dark:bg-amber-950/30 dark:text-amber-100"><div className="font-bold">Header anomalies</div><ul className="mt-2 list-disc space-y-1 pl-4">{analysis.received_anomalies.map((x, i) => <li key={i}>{x}</li>)}</ul></div> : <div className="mt-4 rounded-xl bg-surface-soft p-3 text-xs text-text-secondary">No received-header anomalies were returned by the backend.</div>}</Card> : null}

        {topContribs.length ? <SignalContributionChart items={topContribs}/> : null}

        <Card className="p-5"><SectionHeading icon={FileText} title="Message body"/><div className="mt-4 max-h-[420px] overflow-auto rounded-xl border border-border bg-surface-soft p-4"><pre className="whitespace-pre-wrap break-words font-sans text-sm leading-6 text-text-secondary">{email.body_text || 'No plain-text body stored.'}</pre></div></Card>

        {email.attachments.length ? <Card className="p-5"><SectionHeading icon={Paperclip} title={`Attachments · ${email.attachments.length}`}/><div className="mt-4 grid gap-3 md:grid-cols-2">{email.attachments.map((attachment) => <div key={attachment.id} className="rounded-xl border border-border bg-surface-soft p-4"><div className="font-semibold text-sm">{attachment.filename || 'Unnamed attachment'}</div><div className="mt-1 text-xs text-text-secondary">{attachment.content_type} · {formatBytes(attachment.size)}</div><div className="mt-3 flex items-center gap-2"><span className="truncate font-mono text-[10px] text-text-tertiary">{attachment.sha256}</span><button onClick={() => copy(attachment.sha256)} className="focus-ring rounded-full p-1.5 text-text-tertiary hover:bg-surface hover:text-text" title="Copy hash"><Copy size={13}/></button></div></div>)}</div></Card> : null}
      </div>

      <div className="space-y-5">
        <Card className="p-5"><SectionHeading icon={LockKeyhole} title="Evidence integrity"/><div className="mt-4 rounded-2xl border border-border bg-surface-soft p-4"><div className="flex items-center gap-2 text-xs font-bold"><span className="h-2 w-2 rounded-full bg-success"/>Evidence chain available</div><p className="mt-2 text-xs leading-5 text-text-secondary">Verify the stored evidence chain before relying on this artifact in an investigation.</p><Button className="mt-4 w-full" variant="secondary" onClick={verify}><CheckCircle2 size={14}/> Verify evidence</Button>{verification ? <div className="mt-3 border-t border-border pt-3"><div className={`text-xs font-black ${verification.valid ? 'text-success' : 'text-danger'}`}>{verification.valid ? 'VERIFIED' : 'TAMPERED'}</div><div className="mt-1 text-xs text-text-secondary">{verification.entry_count} chain entr{verification.entry_count === 1 ? 'y' : 'ies'} checked.</div>{verification.errors.length ? <ul className="mt-2 list-disc space-y-1 pl-4 text-[11px] text-danger">{verification.errors.map((x, i) => <li key={i}>{x}</li>)}</ul> : null}</div> : null}</div></Card>
        <Card className="p-5"><SectionHeading icon={Waypoints} title="Threat correlation"/><p className="mt-2 text-xs leading-5 text-text-secondary">Add this email and its extracted indicators to the in-memory correlation graph.</p><Button className="mt-4 w-full" variant="secondary" onClick={correlate}><Link2 size={14}/> Add to graph</Button><Link href="/graph" className="mt-2 block text-center text-xs font-bold text-primary hover:underline">Open correlation workspace →</Link></Card>
        <Card className="p-5"><SectionHeading icon={Globe2} title="Evidence identity"/><div className="mt-4 rounded-2xl border border-border bg-surface-soft p-4"><div className="text-[10px] font-black uppercase tracking-wider text-text-tertiary">SHA-256</div><div className="mt-2 break-all font-mono text-[11px] leading-5 text-text-secondary">{email.sha256}</div><div className="mt-3 flex gap-2"><Button variant="ghost" className="h-8 px-2.5 text-xs" onClick={() => copy(email.sha256)}><Copy size={13}/> Copy</Button><span className="inline-flex items-center rounded-full bg-surface px-2.5 text-[10px] font-semibold text-text-tertiary">{formatBytes(email.size)}</span></div></div></Card>
        <Card className="p-5"><SectionHeading icon={Paperclip} title="Raw structure"/><div className="mt-4 space-y-2">{email.headers.slice(0, 12).map((header) => <div key={`${header.position}-${header.name}`} className="rounded-xl border border-border bg-surface-soft p-3"><div className="text-[10px] font-black uppercase tracking-wider text-text-tertiary">{header.name}</div><div className="mt-1 break-words font-mono text-[10px] leading-4 text-text-secondary">{header.value}</div></div>)}{email.headers.length > 12 ? <div className="text-[11px] text-text-tertiary">Showing first 12 headers of {email.headers.length}.</div> : null}</div></Card>
      </div>
    </div>
  </Page>
}

function RiskGauge({ score, level }: { score: number; level: string }) {
  const clamped = Math.max(0, Math.min(100, score))
  const circumference = 2 * Math.PI * 52
  const offset = circumference - (clamped / 100) * circumference
  const stroke = level === 'CRITICAL' || level === 'HIGH' ? '#ef4444' : level === 'MEDIUM' ? '#f59e0b' : '#22c55e'
  return <div className="relative mx-auto grid h-[190px] w-[190px] place-items-center"><svg className="absolute inset-0 h-full w-full -rotate-90" viewBox="0 0 120 120"><circle cx="60" cy="60" r="52" fill="none" stroke="currentColor" className="text-surface-soft" strokeWidth="9"/><motion.circle cx="60" cy="60" r="52" fill="none" stroke={stroke} strokeWidth="9" strokeLinecap="round" strokeDasharray={circumference} initial={{strokeDashoffset:circumference}} animate={{strokeDashoffset:offset}} transition={{duration:.8,ease:'easeOut'}}/></svg><div className="text-center"><div className="text-4xl font-black tracking-tight">{Math.round(clamped)}</div><div className="mt-1 text-[10px] font-bold uppercase tracking-[.14em] text-text-tertiary">risk score</div></div></div>
}

function RiskCategoryChart({ rows }: { rows: [string, number][] }) {
  return <div className="mt-5"><div className="mb-3 text-[10px] font-black uppercase tracking-[.14em] text-text-tertiary">Risk categories</div><div className="space-y-3">{rows.slice(0, 8).map(([name, value]) => <div key={name}><div className="mb-1.5 flex items-center justify-between gap-3 text-[10px] font-bold"><span className="text-text-secondary">{humanize(name)}</span><span className="font-mono text-text-tertiary">{Math.round(value)}</span></div><div className="h-2 overflow-hidden rounded-full bg-surface-soft"><motion.div initial={{width:0}} animate={{width:`${Math.min(100, Math.max(0, value))}%`}} transition={{duration:.5}} className={`h-full rounded-full ${value >= 60 ? 'bg-danger' : value >= 30 ? 'bg-warning' : 'bg-slate-950 dark:bg-white'}`}/></div></div>)}</div></div>
}

function ProbabilityChart({ ml }: { ml: MLClassification }) {
  const rows = Object.entries(ml.probabilities).sort((a, b) => Number(b[1]) - Number(a[1]))
  return <Card className="p-5"><SectionHeading icon={Activity} title="Model probabilities"/><p className="mt-1 text-xs text-text-secondary">Classification confidence returned by the backend model.</p><div className="mt-5 space-y-3">{rows.slice(0, 5).map(([label, value]) => <div key={label}><div className="mb-1 flex items-center justify-between text-xs font-semibold"><span>{humanize(label)}</span><span className="font-mono text-text-tertiary">{Math.round(value * 100)}%</span></div><div className="h-2.5 overflow-hidden rounded-full bg-surface-soft"><motion.div initial={{width:0}} animate={{width:`${Math.round(value * 100)}%`}} className="h-full rounded-full bg-primary"/></div></div>)}</div></Card>
}

function IndicatorChart({ analysis, email }: { analysis: FullAnalysis; email: EmailDetail }) {
  const points = [
    { label:'Public IPs', value:analysis.public_ips.length, max:Math.max(1, analysis.public_ips.length, analysis.private_ips.length), tone:'bg-blue-500' },
    { label:'Private IPs', value:analysis.private_ips.length, max:Math.max(1, analysis.public_ips.length, analysis.private_ips.length), tone:'bg-slate-500' },
    { label:'Domains', value:analysis.domain_analysis.length, max:Math.max(1, analysis.domain_analysis.length, analysis.urls.length), tone:'bg-indigo-500' },
    { label:'URLs', value:analysis.total_urls, max:Math.max(1, analysis.domain_analysis.length, analysis.total_urls), tone:'bg-amber-500' },
    { label:'Attachments', value:email.attachments.length, max:Math.max(1, email.attachments.length, analysis.total_urls), tone:'bg-rose-500' },
  ]
  return <Card className="p-5"><SectionHeading icon={Server} title="Forensic indicator volume"/><p className="mt-1 text-xs text-text-secondary">Count of indicators returned by each analysis module.</p><div className="mt-5 space-y-3">{points.map((item) => <div key={item.label}><div className="mb-1 flex items-center justify-between text-xs font-semibold"><span>{item.label}</span><span className="font-mono text-text-tertiary">{item.value}</span></div><div className="h-3 overflow-hidden rounded-full bg-surface-soft"><div className={`h-full rounded-full ${item.tone}`} style={{width:`${Math.min(100, item.value / item.max * 100)}%`}}/></div></div>)}</div></Card>
}

function SignalContributionChart({ items }: { items: RiskAssessment['contributions'] }) {
  const max = Math.max(...items.map((item) => item.contribution), 1)
  return <Card className="p-5"><SectionHeading icon={ShieldCheck} title="Top contributing signals"/><p className="mt-1 text-xs text-text-secondary">The same explainable signal values are visualized here instead of a plain list.</p><div className="mt-5 space-y-3">{items.map((item, index) => <div key={`${item.signal}-${index}`}><div className="mb-1 flex items-start justify-between gap-3 text-xs"><div className="min-w-0"><div className="font-semibold">{humanize(item.signal)}</div><div className="mt-0.5 truncate text-[10px] text-text-tertiary">{item.description}</div></div><span className="shrink-0 rounded-full bg-surface-soft px-2 py-1 font-mono text-[10px] font-bold">+{item.contribution.toFixed(1)}</span></div><div className="h-2 overflow-hidden rounded-full bg-surface-soft"><motion.div initial={{width:0}} animate={{width:`${item.contribution / max * 100}%`}} className="h-full rounded-full bg-slate-950 dark:bg-white"/></div></div>)}</div></Card>
}

function InvestigationTimeline({ email, auth, analysis, risk, verification }: { email: EmailDetail; auth: AuthenticationSummary | null; analysis: FullAnalysis | null; risk: RiskAssessment | null; verification: Awaited<ReturnType<typeof verifyEvidence>> | null }) {
  const items = [
    { title:'Evidence ingested', text:`Email #${email.id} stored with SHA-256 evidence identity.`, done:true },
    { title:'Authentication', text:'SPF, DKIM and DMARC response available.', done:Boolean(auth) },
    { title:'Forensic analysis', text:'Headers, routing, URLs, domains and attachments analyzed.', done:Boolean(analysis) },
    { title:'Risk assessment', text:'Weighted model and explainable contributions calculated.', done:Boolean(risk) },
    { title:'Evidence verification', text:verification ? verification.valid ? 'Integrity chain verified.' : 'Integrity verification returned a warning.' : 'Run verification when you need to validate the stored evidence chain.', done:verification?.valid ?? false },
  ]
  return <Card className="p-5"><SectionHeading icon={Waypoints} title="Investigation timeline"/><div className="mt-5 space-y-4">{items.map((item, index) => <div key={item.title} className="flex gap-3"><div className="flex flex-col items-center"><span className={`grid h-7 w-7 place-items-center rounded-full ${item.done ? 'bg-slate-950 text-white dark:bg-white dark:text-slate-950' : 'border border-border bg-surface-soft text-text-tertiary'}`}>{item.done ? <CheckCircle2 size={14}/> : <span className="h-2 w-2 rounded-full bg-current"/>}</span>{index < items.length - 1 ? <span className="mt-1 h-8 w-px bg-border"/> : null}</div><div className="pb-1"><div className="text-sm font-bold">{item.title}</div><div className="mt-1 text-xs leading-5 text-text-secondary">{item.text}</div></div></div>)}</div></Card>
}

function AuthCard({ auth }: { auth: AuthenticationSummary | null }) {
  const items = [auth?.spf, auth?.dkim, auth?.dmarc]
  return <Card className="p-5"><SectionHeading icon={ShieldCheck} title="Authentication"/><p className="mt-1 text-xs text-text-secondary">SPF, DKIM and DMARC are shown exactly as returned by the backend.</p><div className="mt-4 grid gap-3">{['SPF','DKIM','DMARC'].map((label, i) => { const item = items[i]; return <div key={label} className="rounded-xl border border-border bg-surface-soft p-3"><div className="flex items-center justify-between"><span className="text-xs font-black">{label}</span><AuthPill result={item?.result}/></div><div className="mt-2 text-[11px] text-text-secondary">{item?.domain || 'No domain returned'}</div><div className="mt-1 text-[10px] leading-4 text-text-tertiary">{item?.details || 'No additional details returned.'}</div></div> })}</div></Card>
}

function AuthPill({ result }: { result?: string }) { const tone = result === 'PASS' ? 'success' : result === 'FAIL' || result === 'PERMERROR' ? 'danger' : result === 'SOFTFAIL' || result === 'TEMPERROR' ? 'warning' : 'neutral'; return <Badge tone={tone}>{result || 'NOT RUN'}</Badge> }
function SectionHeading({ icon: Icon, title }: { icon: typeof ShieldCheck; title: string }) { return <div className="flex items-center gap-2 text-sm font-black"><span className="grid h-8 w-8 place-items-center rounded-xl bg-surface-soft text-text-secondary"><Icon size={15}/></span>{title}</div> }
function Row({ label, value }: { label: string; value?: string | null }) { return <div className="flex gap-3 border-b border-border pb-3 last:border-0 last:pb-0"><span className="w-24 shrink-0 text-[10px] font-black uppercase tracking-wider text-text-tertiary">{label}</span><span className="min-w-0 break-words text-xs leading-5 text-text-secondary">{value || '—'}</span></div> }
function MiniMetric({ label, value }: { label: string; value: number }) { return <div className="rounded-xl border border-border bg-surface-soft p-4"><div className="text-[10px] font-black uppercase tracking-wider text-text-tertiary">{label}</div><div className="mt-1 text-2xl font-black">{value}</div></div> }
