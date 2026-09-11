'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { useParams } from 'next/navigation'
import { motion } from 'motion/react'
import { ArrowLeft, CheckCircle2, Download, ExternalLink, Fingerprint, Globe2, Link2, Loader2, LockKeyhole, ShieldAlert, Sparkles, Waypoints } from 'lucide-react'
import { addEmailToGraph, classifyEmail, computeRisk, getEmail, getReportUrl, runFullAnalysis, verifyEvidence } from '../../../lib/api'
import { Alert, Badge, Button, Card, Page, PageHeader, Skeleton } from '../../../components/ui'

function riskTone(level) { return ({ LOW: 'success', MEDIUM: 'warning', HIGH: 'danger', CRITICAL: 'danger' })[level] || 'neutral' }
function levelFor(score) { const pct = Number(score || 0); return pct >= 75 ? 'CRITICAL' : pct >= 50 ? 'HIGH' : pct >= 25 ? 'MEDIUM' : 'LOW' }

export default function EmailDetailPage() {
  const { id } = useParams()
  const [email, setEmail] = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [ml, setMl] = useState(null)
  const [risk, setRisk] = useState(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [verification, setVerification] = useState(null)
  const [notice, setNotice] = useState(null)

  useEffect(() => {
    let alive = true
    getEmail(id).then((data) => alive && setEmail(data)).catch((err) => alive && setError(err.message)).finally(() => alive && setLoading(false))
    return () => { alive = false }
  }, [id])

  const riskScore = risk?.score ?? analysis?.overall_risk_score ?? ml?.risk_score ?? 0
  const riskLevel = risk?.level || levelFor(riskScore)
  const signals = useMemo(() => Object.entries(risk?.category_scores || {}).sort((a,b) => Number(b[1]) - Number(a[1])), [risk])

  async function analyze() {
    setBusy(true); setError(''); setNotice(null)
    try { const [full, classif, riskRes] = await Promise.all([runFullAnalysis(id), classifyEmail(id), computeRisk(id)]); setAnalysis(full); setMl(classif); setRisk(riskRes) } catch (err) { setError(err.response?.data?.detail || err.message) } finally { setBusy(false) }
  }
  async function verify() { try { setVerification(await verifyEvidence(id)) } catch (err) { setNotice({ ok: false, text: err.response?.data?.detail || err.message }) } }
  async function correlate() { try { await addEmailToGraph(id); setNotice({ ok: true, text: `Email #${id} linked to the correlation graph.` }) } catch (err) { setNotice({ ok: false, text: err.response?.data?.detail || err.message }) } }

  if (loading) return <Page><div className="space-y-4"><Skeleton className="h-32" /><Skeleton className="h-56" /><Skeleton className="h-80" /></div></Page>
  if (!email) return <Page><Alert>Email not found.</Alert></Page>

  return <Page>
    <PageHeader back={{ href: '/emails', label: 'Back to email feed' }} eyebrow={`Evidence #${id}`} title={email.subject || '(no subject)'} description={email.sender ? `From ${email.sender}${email.date ? ` · ${new Date(email.date).toLocaleString()}` : ''}` : 'Sender unavailable'} actions={<Badge tone={riskTone(riskLevel)}><span className={`h-1.5 w-1.5 rounded-full ${riskTone(riskLevel) === 'success' ? 'bg-success' : riskTone(riskLevel) === 'warning' ? 'bg-warning' : 'bg-danger'}`} />{riskLevel} · {Math.round(Number(riskScore || 0))}/100</Badge>} />
    {error && <div className="mb-5"><Alert>{error}</Alert></div>}
    {notice && <div className="mb-5"><Alert tone={notice.ok ? 'success' : 'danger'}>{notice.text}</Alert></div>}

    <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_330px]">
      <div className="space-y-5">
        <Card className="p-5 sm:p-6"><div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between"><div><div className="text-[10px] font-bold uppercase tracking-[.16em] text-text-tertiary">Investigation controls</div><h2 className="mt-1 text-lg font-extrabold">From raw evidence to defensible finding</h2><p className="mt-1 max-w-2xl text-xs leading-5 text-text-secondary">Run the existing forensic pipeline, verify evidence integrity, export the report or connect this artifact to the correlation graph.</p></div><div className="flex flex-wrap gap-2"><Button onClick={analyze} disabled={busy}>{busy ? <><Loader2 size={14} className="animate-spin" /> Analyzing…</> : <><Sparkles size={14} /> Run full analysis</>}</Button><Button variant="secondary" onClick={() => window.open(getReportUrl(id), '_blank')}><Download size={14} /> Export PDF</Button></div></div></Card>

        {risk && <Card className="p-5 sm:p-6"><div className="flex flex-col gap-6 lg:flex-row lg:items-center"><div className="relative grid h-44 w-44 shrink-0 place-items-center rounded-full bg-surface-muted ring-8 ring-slate-50"><div className="absolute inset-3 rounded-full border-[12px] border-border" /><motion.div className="absolute inset-3 rounded-full border-[12px] border-primary border-r-transparent border-b-transparent" initial={{ rotate: -45 }} animate={{ rotate: 315 }} transition={{ duration: .9, ease: 'easeOut' }} /><div className="text-center"><div className="text-4xl font-black tracking-tight text-text">{Math.round(Number(risk.score || 0))}</div><div className="text-[10px] font-bold uppercase tracking-wider text-text-tertiary">risk score</div></div></div><div className="min-w-0 flex-1"><div className="flex items-center gap-2"><Badge tone={riskTone(risk.level)}>{risk.level}</Badge>{risk.summary && <span className="text-xs text-text-secondary">{risk.summary}</span>}</div><div className="mt-5 grid gap-2 sm:grid-cols-2">{signals.slice(0, 6).map(([key, value]) => <Signal key={key} label={key.replace(/_/g,' ')} value={Number(value)} />)}</div></div></div></Card>}

        <div className="grid gap-4 md:grid-cols-2"><Card className="p-5"><SectionTitle icon={Fingerprint} title="Identity & authentication" /><div className="mt-4 space-y-3"><Info label="Sender" value={email.sender} /><Info label="Display name" value={email.sender_name} /><Info label="SHA-256" value={email.sha256} mono /></div></Card><Card className="p-5"><SectionTitle icon={Globe2} title="Message footprint" /><div className="mt-4 space-y-3"><Info label="Message ID" value={email.message_id} mono /><Info label="Date" value={email.date ? new Date(email.date).toLocaleString() : '—'} /><Info label="Subject" value={email.subject || '(no subject)'} /></div></Card></div>

        {risk?.contributions?.length > 0 && <Card className="p-5"><SectionTitle icon={ShieldAlert} title="Top contributing signals" /><div className="mt-4 space-y-2">{risk.contributions.filter((item) => item.contribution > 0).sort((a,b) => b.contribution - a.contribution).slice(0, 8).map((item, index) => <div key={index} className="flex items-start gap-3 rounded-xl border border-border bg-surface-muted p-3"><Badge tone={item.confidence === 'fact' ? 'info' : item.confidence === 'inference' ? 'warning' : 'neutral'}>{item.confidence}</Badge><div className="min-w-0 flex-1 text-xs leading-5 text-text-secondary">{item.description}</div><span className="font-mono text-[11px] font-bold text-text">+{Number(item.contribution).toFixed(1)}</span></div>)}</div></Card>}
      </div>

      <div className="space-y-5"><Card className="p-5"><SectionTitle icon={LockKeyhole} title="Evidence integrity" /><div className="mt-4 rounded-2xl bg-surface-muted p-4"><div className="flex items-center gap-2 text-xs font-bold text-text"><span className="h-2 w-2 rounded-full bg-success" /> Tamper-evident workflow</div><div className="mt-2 text-[11px] leading-5 text-text-secondary">Verify the evidence chain before relying on this artifact in an investigation.</div><Button variant="secondary" className="mt-4 w-full" onClick={verify}><CheckCircle2 size={14} /> Verify evidence</Button></div>{verification && <div className="mt-3 rounded-2xl border border-border p-4 text-xs"><div className={`font-bold ${verification.valid ? 'text-success' : 'text-danger'}`}>{verification.valid ? 'VERIFIED' : 'TAMPERED'}</div><div className="mt-1 text-text-secondary">{verification.entries?.length || 0} chain entries checked.</div></div>}</Card><Card className="p-5"><SectionTitle icon={Waypoints} title="Threat correlation" /><p className="mt-2 text-xs leading-5 text-text-secondary">Link this email to the shared infrastructure graph without leaving the investigation.</p><Button variant="soft" className="mt-4 w-full" onClick={correlate}><Link2 size={14} /> Add to graph</Button><Link href="/graph" className="mt-3 inline-flex items-center gap-1.5 text-xs font-bold text-primary hover:underline">Open correlation workspace <ExternalLink size={12} /></Link></Card><Card className="p-5"><SectionTitle icon={ArrowLeft} title="Evidence source" /><p className="mt-2 break-all font-mono text-[10px] leading-5 text-text-tertiary">{email.sha256 || 'SHA-256 unavailable'}</p></Card></div>
    </div>
  </Page>
}

function SectionTitle({ icon: Icon, title }) { return <div className="flex items-center gap-2 text-sm font-extrabold text-text"><div className="grid h-8 w-8 place-items-center rounded-xl bg-surface-muted text-text-secondary"><Icon size={15} /></div>{title}</div> }
function Info({ label, value, mono }) { return <div className="flex items-start gap-4"><span className="w-24 shrink-0 text-[10px] font-bold uppercase tracking-wider text-text-tertiary">{label}</span><span className={`break-all text-xs text-text ${mono ? 'font-mono' : ''}`}>{value || '—'}</span></div> }
function Signal({ label, value }) { const pct = Math.max(0, Math.min(100, Number(value || 0))); const tone = pct >= 60 ? 'danger' : pct >= 30 ? 'warning' : 'success'; return <div><div className="mb-1 flex items-center justify-between text-[10px] font-bold uppercase tracking-wider text-text-tertiary"><span>{label}</span><span>{Math.round(pct)}</span></div><div className="h-2 rounded-full bg-border"><div className={`h-full rounded-full ${tone === 'danger' ? 'bg-danger' : tone === 'warning' ? 'bg-warning' : 'bg-success'}`} style={{ width: `${pct}%` }} /></div></div> }
