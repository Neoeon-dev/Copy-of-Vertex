import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { listEmails } from '../api'

function formatDate(dateStr) { return dateStr ? new Date(dateStr).toLocaleString() : '—' }
function truncate(value, length = 55) { if (!value) return '—'; return value.length > length ? `${value.slice(0, length)}…` : value }
function initials(value) { return (value || 'EM').split(/\s+/).map((part) => part[0]).join('').slice(0, 2).toUpperCase() }

export default function EmailListPage() {
  const [emails, setEmails] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let active = true
    listEmails().then((data) => { if (active) setEmails(data || []) }).catch((err) => { if (active) setError(err.message) }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [])

  const total = useMemo(() => emails.length, [emails])

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="section-label">Investigation inbox</p>
          <h1 className="mt-2 text-3xl font-bold tracking-tight text-slate-950">Analyzed emails</h1>
          <p className="mt-2 text-sm text-slate-500">{total} forensic email record{total === 1 ? '' : 's'} in this workspace.</p>
        </div>
        <Link to="/" className="btn-primary">+ Upload new email</Link>
      </div>

      {error && <div className="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-700">{error}</div>}

      {loading ? (
        <div className="space-y-3">{[1, 2, 3, 4].map((i) => <div key={i} className="surface-card h-28 animate-pulse bg-slate-100" />)}</div>
      ) : emails.length === 0 ? (
        <div className="surface-card flex min-h-[420px] flex-col items-center justify-center px-6 text-center">
          <div className="flex h-16 w-16 items-center justify-center rounded-3xl bg-slate-100 text-slate-400"><span className="text-2xl">✉</span></div>
          <h2 className="mt-5 text-lg font-semibold text-slate-900">No analyzed emails yet</h2>
          <p className="mt-2 max-w-md text-sm leading-6 text-slate-500">Upload your first <span className="font-mono text-slate-700">.eml</span> file to start building the forensic workspace.</p>
          <Link to="/" className="mt-6 btn-primary">Upload first email</Link>
        </div>
      ) : (
        <div className="space-y-3">
          {emails.map((email) => (
            <Link key={email.id} to={`/emails/${email.id}`} className="surface-card group block p-4 transition hover:-translate-y-0.5 hover:border-slate-300 sm:p-5">
              <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
                <div className="flex items-center gap-3 sm:w-[29%] sm:min-w-0">
                  <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-slate-100 text-xs font-bold text-slate-600">{initials(email.sender_name || email.sender)}</div>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-semibold text-slate-900">{email.sender_name || email.sender || 'Unknown sender'}</p>
                    <p className="truncate text-xs text-slate-400">{email.sender || '—'}</p>
                  </div>
                </div>
                <div className="min-w-0 flex-1">
                  <p className="truncate font-semibold text-slate-900 group-hover:text-indigo-600">{email.subject || '(no subject)'}</p>
                  <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-slate-400">
                    <span>{formatDate(email.date)}</span>
                    <span className="font-mono">#{email.id}</span>
                  </div>
                </div>
                <div className="flex items-center justify-between gap-3 sm:w-[27%] sm:justify-end">
                  <div className="min-w-0 text-right">
                    <p className="font-mono text-[10px] font-medium text-slate-400">SHA-256</p>
                    <p className="truncate font-mono text-xs text-slate-600">{truncate(email.sha256, 22)}</p>
                  </div>
                  <span className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-semibold text-slate-500">Open →</span>
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
