import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { listEmails } from '../api'

function formatDate(dateStr) {
  if (!dateStr) return '—'
  return new Date(dateStr).toLocaleString()
}

function truncate(str, len = 40) {
  if (!str) return '—'
  return str.length > len ? str.slice(0, len) + '…' : str
}

export default function EmailListPage() {
  const [emails, setEmails] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    listEmails()
      .then(setEmails)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-text">Analyzed Emails</h2>
          <p className="text-text-muted mt-1">{emails.length} email(s) analyzed</p>
        </div>
        <Link
          to="/"
          className="px-4 py-2 bg-primary text-white rounded-lg text-sm font-medium hover:bg-primary-dark transition-colors"
        >
          + Upload New
        </Link>
      </div>

      {loading && (
        <div className="text-center py-12 text-text-dim">Loading...</div>
      )}

      {error && (
        <div className="p-4 bg-danger-bg border border-danger/20 rounded-lg text-danger text-sm mb-4">
          {error}
        </div>
      )}

      {!loading && emails.length === 0 && (
        <div className="text-center py-16 bg-surface rounded-xl border border-border">
          <svg className="w-16 h-16 mx-auto text-text-dim mb-4" fill="none" viewBox="0 0 24 24" strokeWidth={1} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" />
          </svg>
          <p className="text-text-muted font-medium">No emails analyzed yet</p>
          <Link to="/" className="text-primary text-sm mt-2 inline-block hover:underline">
            Upload your first email →
          </Link>
        </div>
      )}

      {emails.length > 0 && (
        <div className="bg-surface rounded-xl border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-surface-alt">
                <th className="text-left px-4 py-3 font-medium text-text-muted">ID</th>
                <th className="text-left px-4 py-3 font-medium text-text-muted">Subject</th>
                <th className="text-left px-4 py-3 font-medium text-text-muted">From</th>
                <th className="text-left px-4 py-3 font-medium text-text-muted">Date</th>
                <th className="text-left px-4 py-3 font-medium text-text-muted">SHA-256</th>
              </tr>
            </thead>
            <tbody>
              {emails.map((email) => (
                <tr key={email.id} className="border-b border-border/50 hover:bg-surface-alt transition-colors">
                  <td className="px-4 py-3">
                    <Link to={`/emails/${email.id}`} className="text-primary font-mono text-xs hover:underline">
                      #{email.id}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <Link to={`/emails/${email.id}`} className="text-text hover:text-primary transition-colors">
                      {truncate(email.subject, 50)}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-text-muted">{truncate(email.sender, 30)}</td>
                  <td className="px-4 py-3 text-text-dim text-xs">{formatDate(email.date)}</td>
                  <td className="px-4 py-3 font-mono text-xs text-text-dim">{truncate(email.sha256, 16)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
