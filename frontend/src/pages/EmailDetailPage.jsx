import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  getEmail,
  runFullAnalysis,
  classifyEmail,
  computeRisk,
  verifyEvidence,
  getReportUrl,
  addEmailToGraph,
} from '../api'

function RiskBadge({ score, level }) {
  const pct = typeof score === 'number' ? Math.round(score) : Math.round(score * 100)
  const lvl = level || (pct >= 75 ? 'CRITICAL' : pct >= 50 ? 'HIGH' : pct >= 25 ? 'MEDIUM' : 'LOW')
  const colors = {
    LOW: 'bg-success/10 text-success border-success/20',
    MEDIUM: 'bg-warning/10 text-warning border-warning/20',
    HIGH: 'bg-danger/10 text-danger border-danger/20',
    CRITICAL: 'bg-danger/20 text-danger border-danger/30',
  }
  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold border ${colors[lvl] || colors.LOW}`}>
      <span className={`w-2 h-2 rounded-full ${colors[lvl]?.includes('success') ? 'bg-success' : colors[lvl]?.includes('warning') ? 'bg-warning' : 'bg-danger'}`} />
      {lvl} ({pct}/100)
    </span>
  )
}

function AuthBadge({ result }) {
  const colors = {
    PASS: 'bg-success/10 text-success',
    FAIL: 'bg-danger/10 text-danger',
    SOFTFAIL: 'bg-warning/10 text-warning',
    NONE: 'bg-text-dim/10 text-text-dim',
    NOT_CHECKED: 'bg-text-dim/10 text-text-dim',
    TEMPERROR: 'bg-warning/10 text-warning',
    PERMERROR: 'bg-danger/10 text-danger',
  }
  return (
    <span className={`inline-flex px-2 py-0.5 rounded text-xs font-medium ${colors[result] || 'bg-text-dim/10 text-text-dim'}`}>
      {result}
    </span>
  )
}

function Section({ title, children, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="bg-surface rounded-xl border border-border overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-surface-alt transition-colors"
      >
        <span className="font-semibold text-text text-sm">{title}</span>
        <svg className={`w-4 h-4 text-text-dim transition-transform ${open ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
        </svg>
      </button>
      {open && <div className="px-5 pb-5 border-t border-border">{children}</div>}
    </div>
  )
}

function KV({ label, value, mono = false }) {
  return (
    <div className="flex items-start gap-2 py-1.5">
      <span className="text-text-dim text-xs font-medium w-28 shrink-0">{label}</span>
      <span className={`text-sm text-text break-all ${mono ? 'font-mono text-xs' : ''}`}>{value ?? '—'}</span>
    </div>
  )
}

function SignalBar({ name, value, detail }) {
  const pct = Math.round(value * 100)
  const color = pct >= 60 ? 'bg-danger' : pct >= 30 ? 'bg-warning' : 'bg-success'
  const label = name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
  return (
    <div className="py-2">
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs font-medium text-text">{label}</span>
        <span className="text-xs text-text-dim">{pct}%</span>
      </div>
      <div className="h-1.5 bg-border rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      {detail && <p className="text-[11px] text-text-dim mt-1">{detail}</p>}
    </div>
  )
}

function CategoryBar({ name, score }) {
  const pct = Math.round(score)
  const color = pct >= 60 ? 'bg-danger' : pct >= 30 ? 'bg-warning' : pct >= 10 ? 'bg-info' : 'bg-border'
  const label = name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-text w-36 shrink-0">{label}</span>
      <div className="flex-1 h-2 bg-border rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-text-dim font-mono w-8 text-right">{pct}</span>
    </div>
  )
}

export default function EmailDetailPage() {
  const { id } = useParams()
  const [email, setEmail] = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [mlResult, setMlResult] = useState(null)
  const [riskResult, setRiskResult] = useState(null)
  const [loading, setLoading] = useState(true)
  const [analyzing, setAnalyzing] = useState(false)
  const [error, setError] = useState(null)
  const [verifyingEvidence, setVerifyingEvidence] = useState(false)
  const [evidenceVerification, setEvidenceVerification] = useState(null)
  const [correlating, setCorrelating] = useState(false)
  const [actionAlert, setActionAlert] = useState(null)

  useEffect(() => {
    let ignore = false
    getEmail(id)
      .then((data) => {
        if (!ignore) {
          setEmail(data)
          setLoading(false)
        }
      })
      .catch((err) => {
        if (!ignore) {
          setError(err.message)
          setLoading(false)
        }
      })
    return () => {
      ignore = true
    }
  }, [id])

  const runAnalysis = async () => {
    setAnalyzing(true)
    setError(null)
    try {
      const [fullResult, mlRes, riskRes] = await Promise.all([
        runFullAnalysis(id),
        classifyEmail(id),
        computeRisk(id),
      ])
      setAnalysis(fullResult)
      setMlResult(mlRes)
      setRiskResult(riskRes)
    } catch (err) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setAnalyzing(false)
    }
  }

  const handleDownloadReport = () => {
    window.open(getReportUrl(id), '_blank')
  }

  const handleVerifyEvidence = async () => {
    setVerifyingEvidence(true)
    setActionAlert(null)
    try {
      const res = await verifyEvidence(id)
      setEvidenceVerification(res)
    } catch (err) {
      setActionAlert({ type: 'error', text: err.response?.data?.detail || err.message })
    } finally {
      setVerifyingEvidence(false)
    }
  }

  const handleAddToGraph = async () => {
    setCorrelating(true)
    setActionAlert(null)
    try {
      await addEmailToGraph(id)
      setActionAlert({ type: 'success', text: `Email #${id} linked to Threat Correlation Graph.` })
    } catch (err) {
      setActionAlert({ type: 'error', text: err.response?.data?.detail || err.message })
    } finally {
      setCorrelating(false)
    }
  }

  if (loading) return <div className="p-8 text-center text-text-dim">Loading...</div>
  if (!email) return <div className="p-8 text-center text-danger">Email not found</div>

  const riskScore = riskResult?.score ?? analysis?.overall_risk_score ?? mlResult?.risk_score ?? 0
  const riskLevel = riskResult?.level

  return (
    <div className="p-8 max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <Link to="/emails" className="text-sm text-primary hover:underline mb-2 inline-block">← Back to list</Link>
          <h2 className="text-2xl font-bold text-text">{email.subject || '(no subject)'}</h2>
          <div className="flex items-center gap-4 mt-2 text-sm text-text-muted">
            <span>From: <strong>{email.sender}</strong></span>
            {email.sender_name && <span>({email.sender_name})</span>}
          </div>
        </div>
        <div className="text-right space-y-2">
          <RiskBadge score={riskScore} level={riskLevel} />
          <div className="flex flex-wrap items-center justify-end gap-2 pt-2">
            {!analysis && (
              <button
                onClick={runAnalysis}
                disabled={analyzing}
                className="px-3 py-1.5 bg-primary text-white rounded-lg text-xs font-medium hover:bg-primary-dark disabled:opacity-50 transition-colors"
              >
                {analyzing ? 'Analyzing...' : '⚡ Run Full Analysis'}
              </button>
            )}
            <button
              onClick={handleDownloadReport}
              className="px-3 py-1.5 bg-surface border border-border text-text rounded-lg text-xs font-medium hover:bg-surface-alt hover:border-primary/50 transition-colors"
            >
              📄 Export Report
            </button>
            <button
              onClick={handleVerifyEvidence}
              disabled={verifyingEvidence}
              className="px-3 py-1.5 bg-surface border border-border text-text rounded-lg text-xs font-medium hover:bg-surface-alt hover:border-primary/50 disabled:opacity-50 transition-colors"
            >
              🛡️ {verifyingEvidence ? 'Verifying...' : 'Verify Evidence'}
            </button>
            <button
              onClick={handleAddToGraph}
              disabled={correlating}
              className="px-3 py-1.5 bg-surface border border-border text-text rounded-lg text-xs font-medium hover:bg-surface-alt hover:border-primary/50 disabled:opacity-50 transition-colors"
            >
              🌐 {correlating ? 'Adding...' : 'Add to Graph'}
            </button>
          </div>
        </div>
      </div>

      {actionAlert && (
        <div className={`p-3 rounded-lg text-xs font-medium border ${
          actionAlert.type === 'success'
            ? 'bg-success-bg text-success border-success/30'
            : 'bg-danger-bg text-danger border-danger/30'
        }`}>
          {actionAlert.text}
        </div>
      )}

      {evidenceVerification && (
        <div className="p-4 bg-surface rounded-xl border border-border space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-text flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${evidenceVerification.valid ? 'bg-success' : 'bg-danger'}`}></span>
              Evidence Chain Integrity: {evidenceVerification.valid ? 'VERIFIED' : 'TAMPERED'}
            </span>
            <button
              onClick={() => setEvidenceVerification(null)}
              className="text-text-dim hover:text-text text-xs"
            >
              ✕ Dismiss
            </button>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs pt-1">
            <div>
              <span className="text-text-dim block">Chain Entries:</span>
              <span className="font-semibold text-text">{evidenceVerification.entries?.length || 0}</span>
            </div>
            <div>
              <span className="text-text-dim block">Raw File SHA-256:</span>
              <span className="font-mono text-text">{email.sha256?.slice(0, 12)}…</span>
            </div>
            <div>
              <span className="text-text-dim block">Verification Result:</span>
              <span className={`font-semibold ${evidenceVerification.valid ? 'text-success' : 'text-danger'}`}>
                {evidenceVerification.valid ? '100% Intact' : 'Integrity Broken'}
              </span>
            </div>
            <div>
              <span className="text-text-dim block">Custody Status:</span>
              <span className="font-semibold text-text">Tamper-Evident Active</span>
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="p-4 bg-danger-bg border border-danger/20 rounded-lg text-danger text-sm">{error}</div>
      )}

      {/* Risk Engine Breakdown */}
      {riskResult && (
        <Section title="Risk Assessment">
          <div className="grid grid-cols-3 gap-6 mb-4">
            <div className="text-center">
              <div className="text-4xl font-bold text-text">{Math.round(riskResult.score)}</div>
              <div className="text-xs text-text-dim mt-1">Risk Score (0–100)</div>
            </div>
            <div className="text-center">
              <RiskBadge score={riskResult.score} level={riskResult.level} />
              <div className="text-xs text-text-dim mt-2">Risk Level</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-semibold text-text">{riskResult.contributions.length}</div>
              <div className="text-xs text-text-dim mt-1">Contributing Signals</div>
            </div>
          </div>

          {/* Category breakdown */}
          <div className="mb-4">
            <p className="text-xs text-text-dim font-medium mb-3">Category Breakdown</p>
            <div className="space-y-2">
              {Object.entries(riskResult.category_scores).map(([cat, score]) => (
                <CategoryBar key={cat} name={cat} score={score} />
              ))}
            </div>
          </div>

          {/* Summary */}
          {riskResult.summary && (
            <div className="p-3 bg-surface-alt rounded-lg text-sm text-text mb-3">
              {riskResult.summary}
            </div>
          )}

          {/* Top contributions */}
          <div>
            <p className="text-xs text-text-dim font-medium mb-2">Top Contributing Signals</p>
            <div className="space-y-1">
              {riskResult.contributions
                .filter(c => c.contribution > 0)
                .sort((a, b) => b.contribution - a.contribution)
                .slice(0, 8)
                .map((c, i) => (
                  <div key={i} className="flex items-center gap-2 p-2 bg-surface-alt rounded text-xs">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                      c.confidence === 'fact' ? 'bg-info/10 text-info' :
                      c.confidence === 'inference' ? 'bg-warning/10 text-warning' :
                      'bg-text-dim/10 text-text-dim'
                    }`}>{c.confidence}</span>
                    <span className="text-text flex-1">{c.description}</span>
                    <span className="text-text-dim font-mono">+{c.contribution.toFixed(1)}</span>
                  </div>
                ))}
            </div>
          </div>

          {/* Limitations */}
          {riskResult.limitations?.length > 0 && (
            <div className="mt-4 pt-3 border-t border-border">
              <p className="text-[10px] text-text-dim font-medium mb-1">Limitations</p>
              <ul className="text-[10px] text-text-dim space-y-0.5">
                {riskResult.limitations.map((l, i) => <li key={i}>• {l}</li>)}
              </ul>
            </div>
          )}
        </Section>
      )}

      {/* Email Metadata */}
      <Section title="Email Metadata">
        <div className="grid grid-cols-2 gap-x-8">
          <KV label="Subject" value={email.subject} />
          <KV label="From" value={email.sender} />
          <KV label="Sender Name" value={email.sender_name} />
          <KV label="Reply-To" value={email.reply_to} />
          <KV label="Message-ID" value={email.message_id} mono />
          <KV label="Date" value={email.date} />
          <KV label="SHA-256" value={email.sha256} mono />
          <KV label="Size" value={`${email.size} bytes`} />
        </div>
        {email.to?.length > 0 && (
          <div className="mt-3 pt-3 border-t border-border">
            <p className="text-xs text-text-dim mb-1">To:</p>
            <div className="flex flex-wrap gap-1">
              {email.to.map((r, i) => (
                <span key={i} className="px-2 py-0.5 bg-surface-alt rounded text-xs text-text">{r.address || r.name}</span>
              ))}
            </div>
          </div>
        )}
      </Section>

      {/* ML Classification */}
      {mlResult && (
        <Section title="AI Classification">
          <div className="grid grid-cols-2 gap-6">
            <div>
              <KV label="Classification" value={mlResult.label.toUpperCase()} />
              <KV label="Confidence" value={`${Math.round(mlResult.confidence * 100)}%`} />
              <KV label="Risk Score" value={`${Math.round(mlResult.risk_score * 100)}%`} />
            </div>
            <div>
              <p className="text-xs text-text-dim font-medium mb-2">Probabilities</p>
              {Object.entries(mlResult.probabilities).map(([label, prob]) => (
                <div key={label} className="flex items-center gap-2 mb-1">
                  <span className="text-xs text-text w-20">{label}</span>
                  <div className="flex-1 h-1.5 bg-border rounded-full overflow-hidden">
                    <div className="h-full bg-primary rounded-full" style={{ width: `${Math.round(prob * 100)}%` }} />
                  </div>
                  <span className="text-[10px] text-text-dim w-8 text-right">{Math.round(prob * 100)}%</span>
                </div>
              ))}
            </div>
          </div>
          <div className="mt-4 pt-4 border-t border-border">
            <p className="text-xs text-text-dim font-medium mb-3">Explainable Signals</p>
            {Object.entries(mlResult.signals).map(([name, value]) => (
              <SignalBar key={name} name={name} value={value} detail={mlResult.signal_details?.[name]} />
            ))}
          </div>
        </Section>
      )}

      {/* Authentication */}
      {analysis && (
        <Section title="Authentication (SPF / DKIM / DMARC)">
          <div className="grid grid-cols-3 gap-4">
            {['spf', 'dkim', 'dmarc'].map((mech) => {
              const r = analysis[mech]
              return (
                <div key={mech} className="p-4 bg-surface-alt rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold text-sm text-text uppercase">{mech}</span>
                    <AuthBadge result={r?.result || 'NOT_CHECKED'} />
                  </div>
                  <KV label="Domain" value={r?.domain} />
                  <KV label="Details" value={r?.details} />
                </div>
              )
            })}
          </div>
        </Section>
      )}

      {/* Received Headers */}
      {analysis && (
        <Section title={`Received Path (${analysis.total_hops} hops)`}>
          <div className="flex gap-4 mb-3 text-xs">
            <span className="text-text-dim">Public IPs: <strong className="text-text">{analysis.public_ips.length}</strong></span>
            <span className="text-text-dim">Private IPs: <strong className="text-text">{analysis.private_ips.length}</strong></span>
          </div>
          {analysis.received_anomalies.length > 0 && (
            <div className="mb-3 p-3 bg-warning-bg rounded-lg text-warning text-xs">
              Anomalies: {analysis.received_anomalies.join(', ')}
            </div>
          )}
          <div className="space-y-1">
            {analysis.ip_analysis?.filter(ip => ip.is_public).map((ip) => (
              <div key={ip.ip} className="flex items-center gap-3 p-2 bg-surface-alt rounded text-xs">
                <span className="font-mono text-text font-medium">{ip.ip}</span>
                {ip.geo && <span className="text-text-muted">{ip.geo.city}, {ip.geo.country_name}</span>}
                {ip.asn && <span className="text-text-dim">AS{ip.asn.asn} {ip.asn.organization}</span>}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Domains */}
      {analysis?.domain_analysis?.length > 0 && (
        <Section title="Domain Intelligence">
          <div className="space-y-2">
            {analysis.domain_analysis.map((d) => (
              <div key={d.domain} className="flex items-center gap-3 p-3 bg-surface-alt rounded-lg">
                <span className="font-mono text-sm text-text">{d.domain}</span>
                {d.suspicious_tld && <AuthBadge result="SUSPICIOUS" />}
                {d.has_homoglyphs && <span className="text-xs text-danger">Homoglyphs</span>}
                {d.lookalikes?.length > 0 && (
                  <span className="text-xs text-warning">
                    Lookalike of {d.lookalikes.map(l => l.brand_domain).join(', ')}
                  </span>
                )}
                {d.risk_score > 0 && (
                  <span className="ml-auto text-xs text-text-dim">Risk: {Math.round(d.risk_score * 100)}%</span>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* URLs */}
      {analysis?.urls?.length > 0 && (
        <Section title={`URLs (${analysis.total_urls} found)`}>
          <div className="space-y-1">
            {analysis.urls.map((u) => (
              <div key={u.url} className="flex items-center gap-2 p-2 bg-surface-alt rounded text-xs">
                <span className="font-mono text-text break-all flex-1">{u.url}</span>
                {u.is_ip_url && <AuthBadge result="IP_URL" />}
                {u.is_shortener && <AuthBadge result="SHORTENER" />}
                {u.suspicious_path && <AuthBadge result="SUSPICIOUS" />}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Attachments */}
      {analysis?.attachment_analysis?.length > 0 && (
        <Section title="Attachments">
          <div className="space-y-2">
            {analysis.attachment_analysis.map((a) => (
              <div key={a.sha256} className="p-3 bg-surface-alt rounded-lg">
                <div className="flex items-center gap-3">
                  <span className="font-medium text-sm text-text">{a.filename || '(unnamed)'}</span>
                  <span className="text-xs text-text-dim">{a.content_type}</span>
                  <span className="text-xs text-text-dim">{a.size} bytes</span>
                  {a.is_dangerous_extension && <AuthBadge result="DANGEROUS" />}
                  {a.has_double_extension && <AuthBadge result="DOUBLE_EXT" />}
                </div>
                <p className="font-mono text-[10px] text-text-dim mt-1 break-all">{a.sha256}</p>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Headers */}
      {email.headers?.length > 0 && (
        <Section title={`All Headers (${email.headers.length})`} defaultOpen={false}>
          <div className="font-mono text-[11px] text-text-muted space-y-0.5 max-h-64 overflow-y-auto">
            {email.headers.map((h) => (
              <div key={h.position} className="py-0.5">
                <span className="text-text font-medium">{h.name}:</span>{' '}
                <span className="break-all">{h.value}</span>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Body */}
      {(email.body_text || email.body_html) && (
        <Section title="Email Body" defaultOpen={false}>
          <div className="bg-surface-alt rounded-lg p-4 max-h-48 overflow-y-auto">
            <pre className="text-xs text-text-muted whitespace-pre-wrap font-sans">
              {email.body_text || email.body_html}
            </pre>
          </div>
        </Section>
      )}
    </div>
  )
}
