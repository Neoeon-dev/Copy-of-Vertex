import { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { uploadEmail } from '../api'

const capabilities = [
  ['Header forensics', 'MIME parsing, routing and sender metadata'],
  ['Authentication', 'SPF, DKIM and DMARC validation'],
  ['Risk intelligence', 'Multi-signal threat scoring and evidence'],
]

export default function UploadPage() {
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState(null)
  const [success, setSuccess] = useState(null)
  const fileRef = useRef()
  const navigate = useNavigate()

  const handleFile = async (file) => {
    if (!file) return
    if (!file.name.toLowerCase().endsWith('.eml')) {
      setError('Only .eml email files are accepted.')
      return
    }
    if (file.size > 10 * 1024 * 1024) {
      setError('This file is larger than the 10 MB upload limit.')
      return
    }
    setError(null)
    setSuccess(null)
    setUploading(true)
    try {
      const result = await uploadEmail(file)
      setSuccess(result)
      window.setTimeout(() => navigate(`/emails/${result.id}`), 700)
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Upload failed. Please try again.')
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="section-label">Start an investigation</p>
          <h1 className="mt-2 text-3xl font-bold tracking-tight text-slate-950 sm:text-4xl">Analyze an email</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500 sm:text-base">Upload a raw <span className="font-mono text-slate-700">.eml</span> file and VERTEX will preserve the evidence chain while analyzing its forensic signals.</p>
        </div>
        <div className="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-500 shadow-sm">Maximum 10 MB</div>
      </div>

      <div className="grid gap-5 lg:grid-cols-[1.45fr_0.85fr]">
        <div
          onDrop={(e) => { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files?.[0]) }}
          onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onClick={() => !uploading && fileRef.current?.click()}
          className={`surface-card group min-h-[390px] cursor-pointer p-6 transition sm:p-10 ${dragging ? 'border-indigo-300 bg-indigo-50/60' : 'hover:-translate-y-0.5 hover:border-slate-300'}`}
        >
          <input ref={fileRef} type="file" accept=".eml" className="hidden" onChange={(e) => handleFile(e.target.files?.[0])} />
          <div className="flex h-full min-h-[330px] flex-col items-center justify-center rounded-[28px] border border-dashed border-slate-300 bg-slate-50/80 px-6 text-center transition group-hover:border-slate-400">
            <div className={`flex h-16 w-16 items-center justify-center rounded-3xl ${dragging ? 'bg-indigo-600 text-white' : 'bg-white text-indigo-600 shadow-sm ring-1 ring-slate-200'}`}>
              <svg className={`h-7 w-7 ${uploading ? 'animate-bounce' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.7"><path strokeLinecap="round" strokeLinejoin="round" d="M12 15.5V4m0 0 4.25 4.25M12 4 7.75 8.25M4 15.5v2.25A2.25 2.25 0 0 0 6.25 20h11.5A2.25 2.25 0 0 0 20 17.75V15.5" /></svg>
            </div>
            <p className="mt-6 text-lg font-semibold text-slate-900">{uploading ? 'Analyzing email…' : success ? 'Email analyzed successfully' : 'Drop your .eml file here'}</p>
            <p className="mt-2 text-sm text-slate-500">{uploading ? 'The backend is processing the forensic pipeline.' : success ? `SHA-256 ${success.sha256?.slice(0, 16)}…` : 'or click anywhere in this area to browse your files'}</p>
            {!uploading && !success && <span className="mt-6 rounded-2xl bg-slate-950 px-4 py-2.5 text-sm font-semibold text-white shadow-sm">Choose email file</span>}
            {uploading && <div className="mt-6 flex items-center gap-2 rounded-full bg-white px-4 py-2 text-xs font-semibold text-slate-600 shadow-sm"><span className="h-2 w-2 animate-pulse rounded-full bg-indigo-600" />Running analysis</div>}
          </div>
        </div>

        <div className="space-y-4">
          {capabilities.map(([title, description], index) => (
            <div key={title} className="surface-card p-5 transition hover:-translate-y-0.5">
              <div className="flex items-start gap-4">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl bg-slate-100 text-xs font-bold text-slate-500">0{index + 1}</div>
                <div>
                  <h3 className="font-semibold text-slate-900">{title}</h3>
                  <p className="mt-1 text-sm leading-6 text-slate-500">{description}</p>
                </div>
              </div>
            </div>
          ))}
          <div className="rounded-3xl border border-indigo-100 bg-indigo-50 p-5">
            <p className="section-label text-indigo-500">Evidence first</p>
            <p className="mt-2 text-sm leading-6 text-indigo-950">Every upload keeps its SHA-256 identity and feeds the existing analysis, evidence and audit workflows.</p>
          </div>
        </div>
      </div>

      {error && <div className="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-700">{error}</div>}
    </div>
  )
}
