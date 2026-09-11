'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { ArrowUpRight, Search, SlidersHorizontal } from 'lucide-react'
import { motion } from 'motion/react'
import { Button, Card, EmptyState, Page, PageHeader, Skeleton } from '../../components/ui'
import { apiError, listEmails } from '../../lib/api'
import { formatDate, formatBytes } from '../../lib/utils'
import type { EmailSummary } from '../../types/api'

export default function EmailsPage() {
  const [emails, setEmails] = useState<EmailSummary[]>([])
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState<'newest' | 'oldest'>('newest')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => { listEmails(0, 100).then(setEmails).catch((e) => setError(apiError(e))).finally(() => setLoading(false)) }, [])

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    return [...emails].filter((email) => `${email.subject || ''} ${email.sender || ''} ${email.sender_name || ''} ${email.filename || ''} ${email.sha256 || ''}`.toLowerCase().includes(q)).sort((a,b) => {
      const av = new Date(a.created_at).getTime(); const bv = new Date(b.created_at).getTime(); return sort === 'newest' ? bv - av : av - bv
    })
  }, [emails, query, sort])

  return <Page>
    <PageHeader eyebrow="Evidence inbox" title="Email feed" description={`${emails.length} stored email${emails.length === 1 ? '' : 's'}. Search the evidence already ingested by VERTEX.`} actions={<Link href="/"><Button><ArrowUpRight size={15}/> Analyze email</Button></Link>}/>
    <Card className="mb-5 p-3"><div className="flex flex-col gap-3 md:flex-row md:items-center"><div className="relative flex-1"><Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-tertiary"/><input value={query} onChange={(e)=>setQuery(e.target.value)} placeholder="Search subject, sender, filename or SHA-256" className="h-10 w-full border border-border bg-surface-soft pl-9 pr-3 text-sm outline-none focus:border-slate-400 focus:bg-white"/></div><div className="flex items-center gap-2"><span className="hidden text-[10px] font-bold uppercase tracking-wider text-text-tertiary sm:inline"><SlidersHorizontal size={14} className="mr-1 inline"/>Sort</span><select value={sort} onChange={(e)=>setSort(e.target.value as 'newest'|'oldest')} className="h-10 border border-border bg-white px-3 text-xs font-semibold outline-none"><option value="newest">Newest first</option><option value="oldest">Oldest first</option></select></div></div></Card>
    {loading ? <div className="space-y-2">{[1,2,3,4,5].map(i=><Skeleton key={i} className="h-[120px]"/>)}</div> : error ? <div className="border border-red-200 bg-red-50 p-4 text-sm text-danger">{error}</div> : visible.length === 0 ? <EmptyState title={emails.length ? 'Nothing matches your search' : 'No evidence yet'} description={emails.length ? 'Try a different subject, sender or hash.' : 'Upload your first .eml file to create an evidence record.'} action={<Link href="/"><Button>Analyze an email</Button></Link>}/> : <div className="space-y-2">{visible.map((email,index)=><motion.div key={email.id} initial={{opacity:0,y:5}} animate={{opacity:1,y:0}} transition={{duration:.16,delay:Math.min(index*.02,.16)}}><Link href={`/emails/${email.id}`} className="block"><Card className="p-4 transition hover:border-slate-400 hover:shadow-[0_6px_20px_rgba(0,0,0,.05)]"><div className="flex items-start gap-4"><div className="grid h-10 w-10 shrink-0 place-items-center bg-slate-950 text-xs font-black text-white">{(email.sender_name || email.sender || '?').slice(0,2).toUpperCase()}</div><div className="min-w-0 flex-1"><div className="flex flex-col gap-1.5 lg:flex-row lg:items-start lg:justify-between"><div className="min-w-0"><div className="truncate text-sm font-bold text-text">{email.subject || '(no subject)'}</div><div className="mt-1 truncate text-xs text-text-secondary">{email.sender || 'Unknown sender'}{email.sender_name ? ` · ${email.sender_name}` : ''}</div></div><div className="shrink-0 text-left lg:text-right"><div className="text-[10px] font-bold uppercase tracking-wider text-text-tertiary">Ingested</div><div className="mt-1 text-xs font-semibold text-text-secondary">{formatDate(email.created_at)}</div></div></div><div className="mt-4 grid gap-2 border-t border-border pt-3 text-[10px] font-mono text-text-tertiary sm:grid-cols-3"><span>#{email.id}</span><span className="truncate">SHA {email.sha256.slice(0,20)}…</span><span>{formatBytes(email.size)} · {email.filename || '.eml'}</span></div></div><ArrowUpRight size={16} className="mt-1 hidden shrink-0 text-text-tertiary sm:block"/></div></Card></Link></motion.div>)}</div>}
  </Page>
}
