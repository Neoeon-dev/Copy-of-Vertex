import { useEffect, useState } from 'react'
import { listCases, createCase, listEmails, assignEmailToCase } from '../api'

export default function CasesPage() {
  const [cases, setCases] = useState([])
  const [emails, setEmails] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showModal, setShowModal] = useState(false)
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [selectedCase, setSelectedCase] = useState(null)
  const [selectedEmailId, setSelectedEmailId] = useState('')
  const [assigning, setAssigning] = useState(false)
  const [assignMessage, setAssignMessage] = useState(null)

  const fetchData = () => Promise.all([listCases(), listEmails(0, 100)]).then(([casesData, emailsData]) => { setCases(casesData || []); setEmails(emailsData || []) }).catch((err) => setError(err.message)).finally(() => setLoading(false))
  useEffect(() => { fetchData() }, [])

  const handleCreateCase = async (event) => {
    event.preventDefault(); if (!title.trim()) return
    setSubmitting(true)
    try { await createCase({ title: title.trim(), description: description.trim() || null }); setTitle(''); setDescription(''); setShowModal(false); setLoading(true); await fetchData() }
    catch (err) { setError(err.response?.data?.detail || err.message) }
    finally { setSubmitting(false) }
  }

  const handleAssign = async () => {
    if (!selectedCase || !selectedEmailId) return
    setAssigning(true); setAssignMessage(null)
    try { await assignEmailToCase(selectedCase.id, parseInt(selectedEmailId, 10)); setAssignMessage({ type: 'success', text: `Email #${selectedEmailId} linked to case #${selectedCase.id}.` }); await fetchData() }
    catch (err) { setAssignMessage({ type: 'error', text: err.response?.data?.detail || err.message }) }
    finally { setAssigning(false) }
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div><p className="section-label">Case management</p><h1 className="mt-2 text-3xl font-bold tracking-tight text-slate-950">Investigation cases</h1><p className="mt-2 text-sm text-slate-500">Group suspicious emails into focused forensic dossiers.</p></div>
        <button onClick={() => setShowModal(true)} className="btn-primary">+ New case</button>
      </div>

      {error && <div className="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-700">{error}</div>}

      {loading ? <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">{[1,2,3].map((i) => <div key={i} className="surface-card h-44 animate-pulse bg-slate-100" />)}</div> : cases.length === 0 ? (
        <div className="surface-card flex min-h-[360px] flex-col items-center justify-center px-6 text-center"><div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 text-slate-500">◎</div><h2 className="mt-5 font-semibold text-slate-900">No investigation cases yet</h2><p className="mt-2 max-w-md text-sm text-slate-500">Create a case when you want a dedicated dossier for a campaign, sender or suspicious set of emails.</p><button onClick={() => setShowModal(true)} className="mt-5 btn-primary">Create first case</button></div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {cases.map((item) => <button key={item.id} onClick={() => setSelectedCase(item)} className={`surface-card text-left p-5 transition hover:-translate-y-0.5 hover:border-slate-300 ${selectedCase?.id === item.id ? 'border-indigo-300 ring-2 ring-indigo-100' : ''}`}>
            <div className="flex items-center justify-between"><span className="rounded-full bg-indigo-50 px-2.5 py-1 font-mono text-[10px] font-bold text-indigo-600">CASE #{item.id}</span><span className="text-[11px] text-slate-400">{new Date(item.created_at).toLocaleDateString()}</span></div>
            <h3 className="mt-4 text-lg font-semibold tracking-tight text-slate-900">{item.title}</h3>
            <p className="mt-2 line-clamp-3 text-sm leading-6 text-slate-500">{item.description || 'No description provided.'}</p>
            <div className="mt-5 flex items-center justify-between border-t border-slate-100 pt-4 text-xs text-slate-400"><span>{new Date(item.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span><span className="font-semibold text-indigo-600">Open dossier →</span></div>
          </button>)}
        </div>
      )}

      {selectedCase && <div className="surface-card p-5 sm:p-6"><div className="flex items-start justify-between gap-4"><div><p className="section-label text-indigo-500">Active dossier · #{selectedCase.id}</p><h2 className="mt-2 text-xl font-bold text-slate-950">{selectedCase.title}</h2><p className="mt-2 text-sm text-slate-500">{selectedCase.description || 'No description provided.'}</p></div><button onClick={() => setSelectedCase(null)} className="rounded-xl p-2 text-slate-400 hover:bg-slate-50 hover:text-slate-700">✕</button></div><div className="mt-6 border-t border-slate-100 pt-5"><p className="text-sm font-semibold text-slate-900">Link an analyzed email</p><div className="mt-3 flex flex-col gap-3 sm:flex-row"><select value={selectedEmailId} onChange={(e) => setSelectedEmailId(e.target.value)} className="min-w-0 flex-1 rounded-2xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-700 focus:border-indigo-500"><option value="">Select an analyzed email…</option>{emails.map((email) => <option key={email.id} value={email.id}>#{email.id} — {email.subject || '(no subject)'}</option>)}</select><button onClick={handleAssign} disabled={!selectedEmailId || assigning} className="btn-primary">{assigning ? 'Linking…' : 'Link to case'}</button></div>{assignMessage && <p className={`mt-3 text-xs font-medium ${assignMessage.type === 'success' ? 'text-emerald-600' : 'text-red-600'}`}>{assignMessage.text}</p>}</div></div>}

      {showModal && <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/30 p-4 backdrop-blur-sm"><div className="w-full max-w-md rounded-3xl border border-slate-200 bg-white p-6 shadow-2xl"><div className="flex items-center justify-between"><div><p className="section-label">New investigation</p><h2 className="mt-1 text-lg font-bold text-slate-950">Create case</h2></div><button onClick={() => setShowModal(false)} className="rounded-xl p-2 text-slate-400 hover:bg-slate-50">✕</button></div><form onSubmit={handleCreateCase} className="mt-5 space-y-4"><label className="block"><span className="mb-1.5 block text-xs font-semibold text-slate-600">Case title</span><input required value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Executive spoofing campaign" className="w-full rounded-2xl border border-slate-200 px-3 py-2.5 text-sm outline-none focus:border-indigo-500" /></label><label className="block"><span className="mb-1.5 block text-xs font-semibold text-slate-600">Description</span><textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={4} placeholder="Context, indicators, targeted teams…" className="w-full resize-none rounded-2xl border border-slate-200 px-3 py-2.5 text-sm outline-none focus:border-indigo-500" /></label><div className="flex justify-end gap-2 pt-2"><button type="button" onClick={() => setShowModal(false)} className="btn-secondary">Cancel</button><button type="submit" disabled={submitting || !title.trim()} className="btn-primary">{submitting ? 'Creating…' : 'Create case'}</button></div></form></div></div>}
    </div>
  )
}
