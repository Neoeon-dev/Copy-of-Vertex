import { useState, useEffect } from 'react'
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

  const fetchCasesAndEmails = () => {
    Promise.all([listCases(), listEmails(0, 100)])
      .then(([casesData, emailsData]) => {
        setCases(casesData || [])
        setEmails(emailsData || [])
        setLoading(false)
      })
      .catch((err) => {
        setError(err.message)
        setLoading(false)
      })
  }

  useEffect(() => {
    fetchCasesAndEmails()
  }, [])

  const handleCreateCase = async (e) => {
    e.preventDefault()
    if (!title.trim()) return
    setSubmitting(true)
    try {
      await createCase({ title: title.trim(), description: description.trim() || null })
      setTitle('')
      setDescription('')
      setShowModal(false)
      fetchCasesAndEmails()
    } catch (err) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setSubmitting(false)
    }
  }

  const handleAssign = async () => {
    if (!selectedCase || !selectedEmailId) return
    setAssigning(true)
    setAssignMessage(null)
    try {
      await assignEmailToCase(selectedCase.id, parseInt(selectedEmailId, 10))
      setAssignMessage({ type: 'success', text: `Email #${selectedEmailId} successfully linked to case #${selectedCase.id}` })
      fetchCasesAndEmails()
    } catch (err) {
      setAssignMessage({ type: 'error', text: err.response?.data?.detail || err.message })
    } finally {
      setAssigning(false)
    }
  }

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-text">Investigation Cases</h2>
          <p className="text-text-muted mt-1">Organize and group suspicious emails into forensic cases</p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="px-4 py-2 bg-primary text-white rounded-lg text-sm font-medium hover:bg-primary-dark transition-colors"
        >
          + New Case
        </button>
      </div>

      {error && (
        <div className="p-4 bg-danger-bg border border-danger/20 rounded-lg text-danger text-sm">
          {error}
        </div>
      )}

      {loading ? (
        <div className="text-center py-12 text-text-dim">Loading cases...</div>
      ) : cases.length === 0 ? (
        <div className="text-center py-16 bg-surface rounded-xl border border-border">
          <p className="text-text-muted font-medium">No investigation cases created yet.</p>
          <button
            onClick={() => setShowModal(true)}
            className="mt-3 text-primary text-sm font-medium hover:underline"
          >
            Create your first case →
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {cases.map((c) => (
            <div
              key={c.id}
              className={`p-6 bg-surface rounded-xl border transition-all cursor-pointer ${
                selectedCase?.id === c.id
                  ? 'border-primary ring-2 ring-primary/20 shadow-sm'
                  : 'border-border hover:border-primary/50'
              }`}
              onClick={() => setSelectedCase(c)}
            >
              <div className="flex items-start justify-between">
                <span className="text-xs font-mono text-primary font-semibold">CASE #{c.id}</span>
                <span className="text-[10px] text-text-dim">
                  {new Date(c.created_at).toLocaleDateString()}
                </span>
              </div>
              <h3 className="text-lg font-semibold text-text mt-2">{c.title}</h3>
              <p className="text-sm text-text-muted mt-1 line-clamp-2">
                {c.description || 'No description provided.'}
              </p>
              <div className="mt-4 pt-4 border-t border-border flex items-center justify-between text-xs text-text-dim">
                <span>Created {new Date(c.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                <span className="text-primary font-medium hover:underline">Manage Dossier →</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Selected Case Detail & Email Linker */}
      {selectedCase && (
        <div className="p-6 bg-surface rounded-xl border border-border space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs font-mono text-primary font-bold">CASE DOSSIER #{selectedCase.id}</span>
              <h3 className="text-xl font-bold text-text mt-1">{selectedCase.title}</h3>
              <p className="text-sm text-text-muted mt-1">{selectedCase.description}</p>
            </div>
            <button
              onClick={() => setSelectedCase(null)}
              className="text-text-dim hover:text-text text-sm"
            >
              ✕ Close
            </button>
          </div>

          <div className="pt-4 border-t border-border">
            <h4 className="text-sm font-semibold text-text mb-2">Link Analyzed Email to this Case</h4>
            <div className="flex flex-wrap items-center gap-3">
              <select
                value={selectedEmailId}
                onChange={(e) => setSelectedEmailId(e.target.value)}
                className="px-3 py-2 bg-surface-alt border border-border rounded-lg text-sm text-text focus:outline-none focus:border-primary flex-1 max-w-md"
              >
                <option value="">Select an analyzed email to assign...</option>
                {emails.map((em) => (
                  <option key={em.id} value={em.id}>
                    #{em.id} — {em.subject || '(no subject)'} ({em.sender})
                  </option>
                ))}
              </select>
              <button
                onClick={handleAssign}
                disabled={!selectedEmailId || assigning}
                className="px-4 py-2 bg-primary text-white text-sm font-medium rounded-lg hover:bg-primary-dark disabled:opacity-50 transition-colors"
              >
                {assigning ? 'Linking...' : 'Link to Case'}
              </button>
            </div>
            {assignMessage && (
              <p className={`text-xs mt-2 ${assignMessage.type === 'success' ? 'text-success' : 'text-danger'}`}>
                {assignMessage.text}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Create Case Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/40 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-surface rounded-xl border border-border shadow-xl max-w-md w-full p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-bold text-text">Create Investigation Case</h3>
              <button
                onClick={() => setShowModal(false)}
                className="text-text-dim hover:text-text text-sm"
              >
                ✕
              </button>
            </div>
            <form onSubmit={handleCreateCase} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-text-muted mb-1">Case Title</label>
                <input
                  type="text"
                  required
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="e.g. Executive Spoofing Campaign Q3"
                  className="w-full px-3 py-2 bg-surface-alt border border-border rounded-lg text-sm text-text focus:outline-none focus:border-primary"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-text-muted mb-1">Description</label>
                <textarea
                  rows={3}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Details about attack indicators, targeted departments, or context..."
                  className="w-full px-3 py-2 bg-surface-alt border border-border rounded-lg text-sm text-text focus:outline-none focus:border-primary"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 border border-border rounded-lg text-sm text-text-muted hover:bg-surface-alt"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting || !title.trim()}
                  className="px-4 py-2 bg-primary text-white rounded-lg text-sm font-medium hover:bg-primary-dark disabled:opacity-50"
                >
                  {submitting ? 'Creating...' : 'Create Case'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
