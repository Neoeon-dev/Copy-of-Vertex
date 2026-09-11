import { useState, useEffect } from 'react'
import { getAuditLogs, verifyAuditLog } from '../api'

export default function AuditTrailPage() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [verifying, setVerifying] = useState(false)
  const [verifyResult, setVerifyResult] = useState(null)

  const fetchLogs = () => {
    getAuditLogs(0, 100)
      .then((data) => {
        setLogs(data || [])
        setLoading(false)
      })
      .catch((err) => {
        setError(err.message)
        setLoading(false)
      })
  }

  useEffect(() => {
    fetchLogs()
  }, [])

  const handleVerify = async () => {
    setVerifying(true)
    setVerifyResult(null)
    try {
      const res = await verifyAuditLog()
      setVerifyResult(res)
    } catch (err) {
      setVerifyResult({ valid: false, error: err.message })
    } finally {
      setVerifying(false)
    }
  }

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-text">Audit & Evidence Chain Ledger</h2>
          <p className="text-text-muted mt-1">Cryptographically verifiable, append-only forensic audit trail</p>
        </div>
        <button
          onClick={handleVerify}
          disabled={verifying}
          className="px-4 py-2 bg-primary text-white rounded-lg text-sm font-medium hover:bg-primary-dark disabled:opacity-50 transition-colors flex items-center gap-2"
        >
          <svg className={`w-4 h-4 ${verifying ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
          </svg>
          {verifying ? 'Verifying Integrity...' : 'Verify Hash Chain Integrity'}
        </button>
      </div>

      {/* Verification Result Banner */}
      {verifyResult && (
        <div className={`p-4 rounded-xl border flex items-center justify-between ${
          verifyResult.valid
            ? 'bg-success-bg border-success/30 text-success'
            : 'bg-danger-bg border-danger/30 text-danger'
        }`}>
          <div className="flex items-center gap-3">
            <span className="text-xl">{verifyResult.valid ? '🛡️' : '⚠️'}</span>
            <div>
              <p className="font-semibold text-sm">
                {verifyResult.valid
                  ? 'Cryptographic Verification Passed — Hash Chain Intact'
                  : 'Verification Failed: Potential Ledger Tampering Detected'}
              </p>
              <p className="text-xs opacity-80 mt-0.5">
                {verifyResult.message || `Verified ${logs.length} immutable ledger entries via SHA-256 chained hashing.`}
              </p>
            </div>
          </div>
          <span className="text-xs font-mono uppercase px-2 py-1 bg-white/60 rounded">
            {verifyResult.valid ? 'VALID' : 'TAMPERED'}
          </span>
        </div>
      )}

      {error && (
        <div className="p-4 bg-danger-bg border border-danger/20 rounded-lg text-danger text-sm">
          {error}
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 bg-surface rounded-xl border border-border">
          <p className="text-xs text-text-dim font-medium">Total Ledger Events</p>
          <p className="text-2xl font-bold text-text mt-1">{logs.length}</p>
        </div>
        <div className="p-4 bg-surface rounded-xl border border-border">
          <p className="text-xs text-text-dim font-medium">Integrity Algorithm</p>
          <p className="text-2xl font-bold text-text mt-1 font-mono text-sm pt-1">SHA-256 Hash Chain</p>
        </div>
        <div className="p-4 bg-surface rounded-xl border border-border">
          <p className="text-xs text-text-dim font-medium">Chain State</p>
          <p className="text-2xl font-bold text-success mt-1 text-sm pt-1 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-success inline-block"></span> Tamper-Evident Active
          </p>
        </div>
      </div>

      {loading ? (
        <div className="text-center py-12 text-text-dim">Loading audit logs...</div>
      ) : logs.length === 0 ? (
        <div className="text-center py-16 bg-surface rounded-xl border border-border text-text-muted">
          No audit entries recorded yet. Upload or analyze an email to generate audit trail entries.
        </div>
      ) : (
        <div className="bg-surface rounded-xl border border-border overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-surface-alt">
                  <th className="text-left px-4 py-3 font-medium text-text-muted">Timestamp</th>
                  <th className="text-left px-4 py-3 font-medium text-text-muted">Action</th>
                  <th className="text-left px-4 py-3 font-medium text-text-muted">Entity</th>
                  <th className="text-left px-4 py-3 font-medium text-text-muted">Actor</th>
                  <th className="text-left px-4 py-3 font-medium text-text-muted">Entry Hash</th>
                  <th className="text-left px-4 py-3 font-medium text-text-muted">Previous Hash</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id} className="border-b border-border/50 hover:bg-surface-alt transition-colors font-mono text-xs">
                    <td className="px-4 py-3 text-text-dim font-sans text-xs">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded bg-primary/10 text-primary font-semibold text-[11px]">
                        {log.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-text">
                      {log.entity_type} {log.entity_id ? `#${log.entity_id}` : ''}
                    </td>
                    <td className="px-4 py-3 text-text-muted font-sans text-xs">
                      {log.actor}
                    </td>
                    <td className="px-4 py-3 text-text-dim" title={log.entry_hash}>
                      {log.entry_hash ? `${log.entry_hash.slice(0, 12)}…` : '—'}
                    </td>
                    <td className="px-4 py-3 text-text-dim" title={log.previous_hash}>
                      {log.previous_hash ? `${log.previous_hash.slice(0, 12)}…` : '(genesis)'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
