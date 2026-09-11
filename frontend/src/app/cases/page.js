'use client'

import { useEffect, useState } from 'react'
import { FileText, Link2, Plus, ShieldAlert, X } from 'lucide-react'
import { createCase, assignEmailToCase, listCases, listEmails } from '../../lib/api'
import { Alert, Button, Card, EmptyState, MetricCard, Page, PageHeader, Skeleton } from '../../components/ui'

export default function CasesPage() {
  const [cases, setCases] = useState([])
  const [emails, setEmails] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [open, setOpen] = useState(false)
  const [selected, setSelected] = useState(null)
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [selectedEmail, setSelectedEmail] = useState('')
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState(null)

  async function load() {
    setLoading(true); setError('')
    try { const [a, b] = await Promise.all([listCases(), listEmails()]); setCases(a || []); setEmails(b || []) } catch (err) { setError(err.message) } finally { setLoading(false) }
  }
  useEffect(() => { load() }, [])

  async function submit(e) {
    e.preventDefault(); if (!title.trim()) return
    setBusy(true); setNotice(null)
    try { await createCase({ title: title.trim(), description: description.trim() || null }); setTitle(''); setDescription(''); setOpen(false); await load() } catch (err) { setError(err.response?.data?.detail || err.message) } finally { setBusy(false) }
  }

  async function linkEmail() {
    if (!selected || !selectedEmail) return
    setBusy(true); setNotice(null)
    try { await assignEmailToCase(selected.id, Number(selectedEmail)); setNotice({ ok: true, text: `Email #${selectedEmail} linked to case #${selected.id}.` }); await load() } catch (err) { setNotice({ ok: false, text: err.response?.data?.detail || err.message }) } finally { setBusy(false) }
  }

  return <Page>
    <PageHeader eyebrow="Investigation workspace" title="Cases" description="Group related evidence into focused forensic investigations." actions={<Button onClick={() => setOpen(true)}><Plus size={15} /> New case</Button>} />
    {error && <div className="mb-5"><Alert>{error}</Alert></div>}
    <div className="mb-5 grid gap-3 sm:grid-cols-3"><MetricCard label="Open dossiers" value={cases.length} icon={FileText} tone="primary" /><MetricCard label="Analyzed evidence" value={emails.length} icon={ShieldAlert} /><MetricCard label="Workspace mode" value="Forensic" icon={Link2} tone="success" /></div>
    {loading ? <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{[1,2,3].map((i) => <Skeleton key={i} className="h-[190px]" />)}</div> : cases.length === 0 ? <EmptyState icon={FileText} title="No investigation cases yet" description="Create a case to start grouping suspicious messages and evidence." action={<Button onClick={() => setOpen(true)}><Plus size={15} /> Create case</Button>} /> : <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{cases.map((item) => <button key={item.id} className={`text-left ${selected?.id === item.id ? 'ring-2 ring-indigo-200' : ''}`} onClick={() => setSelected(item)}><Card hover className="h-full p-5"><div className="flex items-center justify-between gap-3"><span className="font-mono text-[10px] font-bold uppercase tracking-wider text-primary">CASE #{item.id}</span><span className="text-[10px] text-text-tertiary">{item.created_at ? new Date(item.created_at).toLocaleDateString() : '—'}</span></div><h3 className="mt-3 text-base font-extrabold tracking-tight text-text">{item.title}</h3><p className="mt-1 line-clamp-3 text-xs leading-5 text-text-secondary">{item.description || 'No description provided.'}</p><div className="mt-5 flex items-center justify-between border-t border-border pt-3 text-[11px] font-semibold text-text-tertiary"><span>Forensic dossier</span><span>Open →</span></div></Card></button>)}</div>}

    {selected && <Card className="mt-6 p-5 sm:p-6"><div className="flex items-start justify-between gap-4"><div><div className="text-[10px] font-bold uppercase tracking-[.16em] text-primary">Case dossier #{selected.id}</div><h2 className="mt-1 text-xl font-extrabold tracking-tight">{selected.title}</h2><p className="mt-1 text-sm text-text-secondary">{selected.description || 'No description provided.'}</p></div><button onClick={() => setSelected(null)} className="rounded-xl p-2 text-text-tertiary hover:bg-surface-muted"><X size={17} /></button></div><div className="mt-6 border-t border-border pt-5"><div className="text-xs font-bold text-text">Link analyzed evidence</div><div className="mt-3 flex flex-col gap-2 sm:flex-row"><select value={selectedEmail} onChange={(e) => setSelectedEmail(e.target.value)} className="min-w-0 flex-1 rounded-xl border border-border bg-surface-muted px-3 py-2.5 text-xs outline-none focus:border-indigo-300"><option value="">Select an analyzed email…</option>{emails.map((email) => <option key={email.id} value={email.id}>#{email.id} — {email.subject || '(no subject)'}</option>)}</select><Button onClick={linkEmail} disabled={!selectedEmail || busy}><Link2 size={14} /> {busy ? 'Linking…' : 'Link to case'}</Button></div>{notice && <div className={`mt-3 text-xs font-semibold ${notice.ok ? 'text-success' : 'text-danger'}`}>{notice.text}</div>}</div></Card>}

    {open && <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/25 p-4 backdrop-blur-sm"><Card className="w-full max-w-md p-6 shadow-2xl"><div className="flex items-center justify-between"><div><div className="text-xs font-bold uppercase tracking-[.16em] text-text-tertiary">New dossier</div><h2 className="mt-1 text-lg font-extrabold">Create investigation case</h2></div><button onClick={() => setOpen(false)} className="rounded-xl p-2 text-text-tertiary hover:bg-surface-muted"><X size={17} /></button></div><form onSubmit={submit} className="mt-5 space-y-4"><div><label className="mb-1.5 block text-xs font-bold text-text-secondary">Case title</label><input required value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Executive spoofing campaign" className="w-full rounded-xl border border-border bg-surface-muted px-3 py-2.5 text-sm outline-none focus:border-indigo-300 focus:bg-white" /></div><div><label className="mb-1.5 block text-xs font-bold text-text-secondary">Description</label><textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={4} placeholder="Add context for the investigation…" className="w-full resize-none rounded-xl border border-border bg-surface-muted px-3 py-2.5 text-sm outline-none focus:border-indigo-300 focus:bg-white" /></div><div className="flex justify-end gap-2 pt-2"><Button type="button" variant="secondary" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create case'}</Button></div></form></Card></div>}
  </Page>
}
