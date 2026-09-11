'use client'

import { useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { AnimatePresence, motion } from 'motion/react'
import { CheckCircle2, FileUp, Fingerprint, Gauge, LockKeyhole, ScanLine, ShieldAlert, Sparkles, UploadCloud } from 'lucide-react'
import { uploadEmail } from '../lib/api'
import { Alert, Badge, Button, Card, Page, PageHeader } from '../components/ui'

const capabilities = [
  { icon: ScanLine, label: 'MIME intelligence', text: 'Headers, routing, attachments and message structure.' },
  { icon: Fingerprint, label: 'Authentication', text: 'SPF, DKIM and DMARC evidence in one place.' },
  { icon: Gauge, label: 'Risk assessment', text: 'Multi-signal scoring with transparent evidence.' },
]

export default function AnalyzePage() {
  const inputRef = useRef(null)
  const router = useRouter()
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [fileName, setFileName] = useState('')
  const [success, setSuccess] = useState(null)
  const [error, setError] = useState('')

  async function handleFile(file) {
    if (!file) return
    if (!file.name.toLowerCase().endsWith('.eml')) {
      setError('Only .eml files are accepted.')
      return
    }
    if (file.size > 10 * 1024 * 1024) {
      setError('The maximum file size is 10 MB.')
      return
    }
    setError('')
    setSuccess(null)
    setFileName(file.name)
    setUploading(true)
    try {
      const result = await uploadEmail(file)
      setSuccess(result)
      setTimeout(() => router.push(`/emails/${result.id}`), 650)
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Upload failed. Please try again.')
    } finally {
      setUploading(false)
    }
  }

  return (
    <Page>
      <PageHeader
        eyebrow="Forensic workspace"
        title="Analyze a suspicious email"
        description="Drop an .eml file and VERTEX will preserve the source, extract forensic evidence and calculate a transparent risk assessment."
        actions={<Badge tone="success"><span className="h-1.5 w-1.5 rounded-full bg-success" /> Analysis pipeline ready</Badge>}
      />

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.3fr)_360px]">
        <Card className="overflow-hidden">
          <div className="border-b border-border px-5 py-4 sm:px-6">
            <div className="flex items-center justify-between gap-3">
              <div><div className="text-sm font-bold text-text">Secure intake</div><div className="mt-0.5 text-xs text-text-secondary">Original evidence remains the source of truth.</div></div>
              <div className="hidden items-center gap-1.5 rounded-full bg-surface-muted px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider text-text-tertiary sm:flex"><LockKeyhole size={12} /> Evidence safe</div>
            </div>
          </div>

          <motion.button
            type="button"
            onClick={() => inputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files?.[0]) }}
            whileHover={{ scale: 1.002 }}
            className={`m-5 flex min-h-[350px] w-[calc(100%-2.5rem)] flex-col items-center justify-center rounded-3xl border-2 border-dashed px-6 text-center transition sm:m-6 sm:min-h-[390px] sm:w-[calc(100%-3rem)] ${dragging ? 'border-primary bg-primary-soft/60' : 'border-border-strong bg-surface-muted/45 hover:border-indigo-300 hover:bg-primary-soft/30'}`}
          >
            <input ref={inputRef} type="file" accept=".eml" className="hidden" onChange={(e) => handleFile(e.target.files?.[0])} />
            <AnimatePresence mode="wait">
              {uploading ? (
                <motion.div key="uploading" initial={{ opacity: 0, scale: .96 }} animate={{ opacity: 1, scale: 1 }} className="max-w-sm">
                  <div className="mx-auto grid h-16 w-16 place-items-center rounded-3xl bg-slate-950 text-white shadow-xl shadow-slate-950/15"><UploadCloud className="animate-pulse" size={28} /></div>
                  <div className="mt-5 text-lg font-extrabold text-text">Analyzing {fileName}</div>
                  <p className="mt-1 text-sm text-text-secondary">Preserving evidence and starting the forensic pipeline…</p>
                  <div className="mx-auto mt-5 h-2 max-w-xs overflow-hidden rounded-full bg-border"><motion.div className="h-full rounded-full bg-primary" initial={{ width: '10%' }} animate={{ width: ['10%', '55%', '82%'] }} transition={{ duration: 2.2, repeat: Infinity, ease: 'easeInOut' }} /></div>
                </motion.div>
              ) : success ? (
                <motion.div key="success" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="max-w-sm">
                  <div className="mx-auto grid h-16 w-16 place-items-center rounded-3xl bg-success-soft text-success"><CheckCircle2 size={30} /></div>
                  <div className="mt-5 text-lg font-extrabold text-text">Analysis complete</div>
                  <p className="mt-1 text-sm text-text-secondary">Opening the forensic report for email #{success.id}.</p>
                  <Badge tone="success">SHA-256 {success.sha256?.slice(0, 14)}…</Badge>
                </motion.div>
              ) : (
                <motion.div key="idle" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="max-w-sm">
                  <div className={`mx-auto grid h-16 w-16 place-items-center rounded-3xl ${dragging ? 'bg-primary text-white' : 'bg-white text-primary'} shadow-sm ring-1 ring-border`}><FileUp size={28} /></div>
                  <div className="mt-5 text-lg font-extrabold tracking-tight text-text">Drop your .eml file here</div>
                  <p className="mt-1 text-sm text-text-secondary">or click anywhere in this area to browse from your computer.</p>
                  <div className="mt-5 flex items-center justify-center gap-2 text-[11px] font-semibold text-text-tertiary"><span className="rounded-full border border-border bg-white px-2.5 py-1">.eml only</span><span>•</span><span>10 MB max</span></div>
                  <div className="mt-7"><Button variant="secondary"><UploadCloud size={15} /> Choose file</Button></div>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.button>

          {error && <div className="px-5 pb-5 sm:px-6 sm:pb-6"><Alert>{error}</Alert></div>}
        </Card>

        <div className="space-y-4">
          <Card className="p-5">
            <div className="flex items-center gap-2 text-sm font-bold text-text"><Sparkles size={17} className="text-primary" /> What VERTEX checks</div>
            <div className="mt-5 space-y-4">
              {capabilities.map(({ icon: Icon, label, text }) => <div key={label} className="flex gap-3"><div className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-surface-muted text-text-secondary"><Icon size={16} /></div><div><div className="text-xs font-bold text-text">{label}</div><div className="mt-0.5 text-xs leading-5 text-text-secondary">{text}</div></div></div>)}
            </div>
          </Card>
          <Card className="p-5">
            <div className="flex items-start gap-3"><div className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-danger-soft text-danger"><ShieldAlert size={16} /></div><div><div className="text-xs font-bold text-text">Built for investigation</div><p className="mt-1 text-xs leading-5 text-text-secondary">The workflow keeps raw evidence, extracted indicators and downstream risk decisions connected so analysts can move from inbox noise to defensible findings.</p></div></div>
          </Card>
        </div>
      </div>
    </Page>
  )
}
