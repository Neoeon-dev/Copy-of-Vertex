import { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { uploadEmail } from '../api'

export default function UploadPage() {
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState(null)
  const [success, setSuccess] = useState(null)
  const fileRef = useRef()
  const navigate = useNavigate()

  const handleFile = async (file) => {
    if (!file) return
    if (!file.name.endsWith('.eml')) {
      setError('Only .eml files are accepted')
      return
    }
    setError(null)
    setUploading(true)
    try {
      const result = await uploadEmail(file)
      setSuccess(result)
      setTimeout(() => navigate(`/emails/${result.id}`), 800)
    } catch (err) {
      setError(err.response?.data?.detail || 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  const onDrop = (e) => {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files[0]
    handleFile(file)
  }

  const onDragOver = (e) => {
    e.preventDefault()
    setDragging(true)
  }

  const onDragLeave = () => setDragging(false)

  return (
    <div className="p-8 max-w-2xl mx-auto">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-text">Analyze Email</h2>
        <p className="text-text-muted mt-1">Upload a .eml file for forensic analysis</p>
      </div>

      <div
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onClick={() => fileRef.current?.click()}
        className={`
          border-2 border-dashed rounded-xl p-12 text-center cursor-pointer
          transition-all duration-200
          ${dragging
            ? 'border-primary bg-primary/5 scale-[1.01]'
            : 'border-border hover:border-primary/50 hover:bg-surface-alt'
          }
        `}
      >
        <input
          ref={fileRef}
          type="file"
          accept=".eml"
          className="hidden"
          onChange={(e) => handleFile(e.target.files[0])}
        />

        <div className="mb-4">
          <svg className="w-12 h-12 mx-auto text-text-dim" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
          </svg>
        </div>

        {uploading ? (
          <p className="text-primary font-medium">Uploading & analyzing...</p>
        ) : success ? (
          <div>
            <p className="text-success font-medium">Email analyzed successfully!</p>
            <p className="text-sm text-text-muted mt-1">SHA-256: {success.sha256?.slice(0, 16)}...</p>
          </div>
        ) : (
          <>
            <p className="text-text font-medium">
              Drop a .eml file here or click to browse
            </p>
            <p className="text-sm text-text-dim mt-2">
              Maximum file size: 10 MB
            </p>
          </>
        )}
      </div>

      {error && (
        <div className="mt-4 p-4 bg-danger-bg border border-danger/20 rounded-lg text-danger text-sm">
          {error}
        </div>
      )}

      <div className="mt-8 grid grid-cols-3 gap-4 text-center">
        {[
          { label: 'MIME Parsing', desc: 'Full header extraction' },
          { label: 'SPF/DKIM/DMARC', desc: 'Authentication analysis' },
          { label: 'Risk Scoring', desc: 'Multi-signal assessment' },
        ].map((item) => (
          <div key={item.label} className="p-4 bg-surface rounded-lg border border-border">
            <p className="font-medium text-sm text-text">{item.label}</p>
            <p className="text-xs text-text-dim mt-1">{item.desc}</p>
          </div>
        ))}
      </div>
    </div>
  )
}
