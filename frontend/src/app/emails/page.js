'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { motion } from 'motion/react'
import { ArrowUpRight, CalendarClock, ChevronDown, Search, ShieldAlert, SlidersHorizontal } from 'lucide-react'
import { listEmails } from '../../lib/api'
import { Badge, Button, Card, EmptyState, Page, PageHeader, Skeleton } from '../../components/ui'

function riskFor(email) {
  const score = Number(email.risk_score ?? email.risk ?? 0)
  return score >= 75 ? ['CRITICAL', 'danger'] : score >= 50 ? ['HIGH', 'danger'] : score >= 25 ? ['MEDIUM', 'warning'] : ['LOW', 'success']
}

function formatDate(date) {
  if (!date) return 'No date'
  try { return new Date(date).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) } catch { return 'No date' }
}

export default function EmailsPage() {
  const [emails, setEmails] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const [risk, setRisk] = useState('ALL')
  const [sort, setSort] = useState('newest')

  useEffect(() => {
    let alive = true
    listEmails().then((data) => alive && setEmails(data || [])).catch((err) => alive && setError(err.message)).finally(() => alive && setLoading(false))
    return () => { alive = false }
  }, [])

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    const filtered = emails.filter((email) => {
      const [level] = riskFor(email)
      const haystack = `${email.subject || ''} ${email.sender || ''} ${email.sender_name || ''} ${email.sha256 || ''}`.toLowerCase()
      return (!q || haystack.includes(q)) && (risk === 'ALL' || level === risk)
    })
    return filtered.sort((a, b) => sort === 'oldest' ? new Date(a.date || 0) - new Date(b.date || 0) : new Date(b.date || 0) - new Date(a.date || 0))
  }, [emails, query, risk, sort])

  return (
    <Page>
      <PageHeader
        eyebrow="Evidence inbox"
        title="Analyzed email feed"
        description={`${emails.length} analyzed email${emails.length === 1 ? '' : 's'} in the current workspace.`}
        actions={<Link href="/"><Button><ArrowUpRight size={15} /> Analyze another</Button></Link>}
      />

      <Card className="mb-5 p-3 sm:p-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
          <div className="relative flex-1"><Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-text-tertiary" /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search subject, sender or SHA-256…" className="w-full rounded-xl border border-border bg-surface-muted py-2.5 pl-10 pr-3 text-sm text-text outline-none transition focus:border-indigo-300 focus:bg-white focus:ring-4 focus:ring-indigo-50" /></div>
          <div className="flex flex-wrap items-center gap-2"><div className="flex items-center gap-1.5 rounded-xl bg-surface-muted px-2 py-1.5"><SlidersHorizontal size={14} className="text-text-tertiary" />{['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((item) => <button key={item} onClick={() => setRisk(item)} className={`rounded-lg px-2.5 py-1.5 text-[11px] font-bold transition ${risk === item ? 'bg-white text-text shadow-sm ring-1 ring-border' : 'text-text-tertiary hover:text-text'}`}>{item === 'ALL' ? 'All' : item}</button>)}</div><label className="flex items-center gap-2 rounded-xl border border-border bg-white px-3 py-2 text-xs font-semibold text-text-secondary"><CalendarClock size={14} /><select value={sort} onChange={(e) => setSort(e.target.value)} className="bg-transparent outline-none"><option value="newest">Newest</option><option value="oldest">Oldest</option></select><ChevronDown size={13} /></label></div>
        </div>
      </Card>

      {loading && <div className="space-y-3">{[1,2,3,4].map((i) => <Skeleton key={i} className="h-[132px]" />)}</div>}
      {!loading && error && <Card className="p-5 text-sm text-danger">{error}</Card>}
      {!loading && !error && visible.length === 0 && <EmptyState icon={ShieldAlert} title={emails.length ? 'No emails match this view' : 'No analyzed emails yet'} description={emails.length ? 'Try another search term or risk filter.' : 'Upload your first .eml file to start the forensic workflow.'} action={<Link href="/"><Button>Analyze an email</Button></Link>} />}

      {!loading && visible.length > 0 && <div className="space-y-3">{visible.map((email, index) => {
        const [level, tone] = riskFor(email)
        const initials = (email.sender_name || email.sender || '?').slice(0, 2).toUpperCase()
        return <motion.div key={email.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(index * .025, .2) }}><Link href={`/emails/${email.id}`} className="block"><Card hover className="p-4 sm:p-5"><div className="flex gap-4"><div className="grid h-11 w-11 shrink-0 place-items-center rounded-2xl bg-slate-950 text-xs font-extrabold text-white">{initials}</div><div className="min-w-0 flex-1"><div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between"><div className="min-w-0"><div className="truncate text-sm font-bold text-text">{email.subject || '(no subject)'}</div><div className="mt-1 truncate text-xs text-text-secondary">{email.sender || 'Unknown sender'}</div></div><div className="flex items-center gap-2"><Badge tone={tone}>{level}</Badge><span className="text-[11px] text-text-tertiary">{formatDate(email.date)}</span></div></div><div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3"><span className="font-mono text-[10px] text-text-tertiary">#{email.id} · SHA-256 {email.sha256?.slice(0, 16) || '—'}…</span><span className="inline-flex items-center gap-1 text-[11px] font-bold text-text-secondary">Open investigation <ArrowUpRight size={13} /></span></div></div></div></Card></Link></motion.div>
      })}</div>}
    </Page>
  )
}
