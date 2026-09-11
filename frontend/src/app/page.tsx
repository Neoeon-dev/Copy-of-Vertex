'use client'

import { useEffect, useRef, useState } from 'react'
import { motion } from 'motion/react'
import Link from 'next/link'
import { FileUp, LockKeyhole, CheckCircle2, AlertCircle, ArrowUpRight, Paperclip, MailCheck } from 'lucide-react'
import { Alert, Badge, Button, Card, EmptyState, Page, PageHeader, Skeleton } from '../components/ui'
import { apiError, listEmails, uploadEmail } from '../lib/api'
import { formatBytes, formatDate } from '../lib/utils'
import type { EmailSummary } from '../types/api'

export default function HomePage() {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [progress, setProgress] = useState(0)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState('')
  const [recent, setRecent] = useState<EmailSummary[]>([])
  const [loadingRecent, setLoadingRecent] = useState(true)

  useEffect(() => { listEmails(0, 6).then(setRecent).catch(() => undefined).finally(() => setLoadingRecent(false)) }, [])

  function choose(next: File | undefined) {
    setError('')
    if (!next) return
    if (!next.name.toLowerCase().endsWith('.eml')) { setFile(null); setError('Only .eml files are accepted by the backend.'); return }
    if (next.size > 10 * 1024 * 1024) { setFile(null); setError('The backend accepts files up to 10 MB.'); return }
    setFile(next)
  }

  async function submit() {
    if (!file) return
    setUploading(true); setProgress(0); setError('')
    try {
      const result = await uploadEmail(file, setProgress)
      window.location.href = `/emails/${result.id}`
    } catch (err) { setError(apiError(err)) } finally { setUploading(false) }
  }

  return <Page>
    <PageHeader eyebrow="Forensic workspace" title="Analyze an email" description="Upload a raw .eml file. VERTEX preserves the evidence hash, parses the message, and gives you a defensible forensic workspace." />

    <div className="grid gap-5 xl:grid-cols-[minmax(0,1.25fr)_360px]">
      <div>
        <Card className="overflow-hidden">
          <div className="border-b border-border px-5 py-4 sm:px-6"><div className="flex items-center justify-between gap-3"><div><div className="text-sm font-bold">Evidence intake</div><div className="mt-1 text-xs text-text-secondary">Raw message files only. No client-side parsing is performed.</div></div><Badge tone="success"><LockKeyhole size={11}/> evidence hash</Badge></div></div>
          <div className="p-5 sm:p-7">
            <input ref={inputRef} type="file" accept=".eml" className="hidden" onChange={(e) => choose(e.target.files?.[0])}/>
            <motion.button type="button" onClick={() => inputRef.current?.click()} onDragOver={(e) => { e.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)} onDrop={(e) => { e.preventDefault(); setDragging(false); choose(e.dataTransfer.files?.[0]) }} className={`flex min-h-[290px] w-full flex-col items-center justify-center rounded-2xl border-2 border-dashed px-6 text-center transition ${dragging ? 'border-primary bg-indigo-50' : 'border-border-strong bg-surface-soft hover:border-slate-400 hover:bg-white'}`} whileTap={{ scale: .995 }}>
              <div className="grid h-14 w-14 place-items-center border border-border bg-white"><FileUp size={24} className="text-text-secondary"/></div>
              <div className="mt-5 text-base font-bold">Drop a .eml file here</div>
              <div className="mt-1 text-sm text-text-secondary">or click to browse your computer</div>
              <div className="mt-4 text-[11px] font-semibold text-text-tertiary">Maximum 10 MB</div>
            </motion.button>

            {file ? <div className="mt-4 border border-border bg-white p-4"><div className="flex items-start gap-3"><div className="grid h-9 w-9 place-items-center bg-slate-950 text-white"><MailCheck size={16}/></div><div className="min-w-0 flex-1"><div className="truncate text-sm font-bold">{file.name}</div><div className="mt-1 text-xs text-text-secondary">{formatBytes(file.size)} · ready to ingest</div></div><button onClick={() => setFile(null)} className="text-xs font-semibold text-text-tertiary hover:text-text">Remove</button></div>{uploading ? <div className="mt-4"><div className="mb-1 flex items-center justify-between text-[11px] font-semibold"><span>{progress < 100 ? 'Uploading evidence…' : 'Waiting for analysis response…'}</span><span>{progress}%</span></div><div className="h-1.5 bg-border"><div className="h-full bg-slate-950 transition-[width] duration-200" style={{ width: `${progress}%` }}/></div></div> : <Button className="mt-4 w-full" onClick={submit}><FileUp size={15}/> Start analysis</Button>}</div> : null}
            {error ? <Alert className="mt-4"><div className="flex items-start gap-2"><AlertCircle size={16} className="mt-0.5 shrink-0"/><span>{error}</span></div></Alert> : null}
          </div>
        </Card>
      </div>

      <div className="space-y-5">
        <Card className="p-5"><div className="text-[10px] font-black uppercase tracking-[.14em] text-text-tertiary">What happens next</div><div className="mt-4 space-y-4"><Step icon={LockKeyhole} title="Evidence hash" text="The backend computes SHA-256 before parsing the file."/><Step icon={Paperclip} title="MIME extraction" text="Headers, recipients, body content and attachment metadata are stored."/><Step icon={CheckCircle2} title="Forensic analysis" text="SPF, DKIM, DMARC, URLs, domains, IPs, attachments and risk signals can be run from the investigation page."/></div></Card>
        <Card className="p-5"><div className="flex items-center justify-between"><div className="text-sm font-bold">Recent evidence</div><Link href="/emails" className="text-xs font-bold text-primary hover:underline">View all</Link></div>{loadingRecent ? <div className="mt-4 space-y-3">{[1,2,3].map((i)=><Skeleton key={i} className="h-12"/>)}</div> : recent.length === 0 ? <div className="mt-4"><EmptyState title="Nothing analyzed yet" description="Your first uploaded email will show up here."/></div> : <div className="mt-3 divide-y divide-border">{recent.map((item)=><Link key={item.id} href={`/emails/${item.id}`} className="flex items-center justify-between gap-3 py-3 hover:bg-surface-soft"><div className="min-w-0"><div className="truncate text-xs font-bold">{item.subject || '(no subject)'}</div><div className="mt-1 truncate text-[11px] text-text-secondary">{item.sender || 'Unknown sender'}</div></div><div className="shrink-0 text-right"><div className="text-[10px] font-semibold text-text-tertiary">#{item.id}</div><div className="mt-1 text-[10px] text-text-tertiary">{formatDate(item.created_at)}</div></div></Link>)}</div>}</Card>
      </div>
    </div>
  </Page>
}

function Step({ icon: Icon, title, text }: { icon: typeof LockKeyhole; title: string; text: string }) { return <div className="flex gap-3"><div className="grid h-8 w-8 shrink-0 place-items-center border border-border bg-surface-soft text-text-secondary"><Icon size={15}/></div><div><div className="text-sm font-bold">{title}</div><div className="mt-1 text-xs leading-5 text-text-secondary">{text}</div></div></div> }
