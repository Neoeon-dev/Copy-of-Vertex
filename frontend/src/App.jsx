import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import UploadPage from './pages/UploadPage'
import EmailListPage from './pages/EmailListPage'
import EmailDetailPage from './pages/EmailDetailPage'
import CasesPage from './pages/CasesPage'
import CorrelationGraphPage from './pages/CorrelationGraphPage'
import AuditTrailPage from './pages/AuditTrailPage'
import { checkHealth } from './api'

function Sidebar() {
  const [online, setOnline] = useState(true)

  useEffect(() => {
    checkHealth()
      .then(() => setOnline(true))
      .catch(() => setOnline(false))
  }, [])

  const linkClass = ({ isActive }) =>
    `flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors ${
      isActive
        ? 'bg-primary/10 text-primary font-semibold'
        : 'text-text-muted hover:bg-surface-alt hover:text-text'
    }`

  return (
    <aside className="w-64 bg-surface border-r border-border flex flex-col min-h-screen">
      <div className="p-6 border-b border-border">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-primary text-white flex items-center justify-center font-bold text-sm">
            MT
          </div>
          <div>
            <h1 className="text-lg font-bold text-text tracking-tight leading-none">
              <span className="text-primary">Mail</span>Trace
            </h1>
            <p className="text-[10px] text-text-dim uppercase tracking-wider font-semibold mt-1">Forensic Intelligence</p>
          </div>
        </div>
      </div>
      <nav className="flex-1 p-4 space-y-1">
        <NavLink to="/" className={linkClass} end>
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
          </svg>
          Upload Email
        </NavLink>
        <NavLink to="/emails" className={linkClass}>
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" />
          </svg>
          Analyzed Emails
        </NavLink>
        <NavLink to="/cases" className={linkClass}>
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 14.15v4.25c0 1.094-.787 2.036-1.872 2.18-2.087.277-4.216.42-6.378.42s-4.291-.143-6.378-.42c-1.085-.144-1.872-1.086-1.872-2.18v-4.25m16.5 0a2.18 2.18 0 00.75-1.661V8.706c0-1.081-.768-2.015-1.837-2.175a48.114 48.114 0 00-3.413-.387m4.5 8.006c-.194.165-.42.295-.673.38A23.978 23.978 0 0112 15.75c-2.648 0-5.195-.429-7.577-1.22a2.016 2.016 0 01-.673-.38m0 0A2.18 2.18 0 013 12.489V8.706c0-1.081.768-2.015 1.837-2.175a48.111 48.111 0 013.413-.387m7.5 0V5.25A2.25 2.25 0 0013.5 3h-3a2.25 2.25 0 00-2.25 2.25v.894m7.5 0a48.667 48.667 0 00-7.5 0M12 12.75h.008v.008H12v-.008z" />
          </svg>
          Investigation Cases
        </NavLink>
        <NavLink to="/graph" className={linkClass}>
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 14.25v2.25m3-4.5v4.5m3-6.75v6.75m3-9v9M6 20.25h12A2.25 2.25 0 0020.25 18V6A2.25 2.25 0 0018 3.75H6A2.25 2.25 0 003.75 6v12A2.25 2.25 0 006 20.25z" />
          </svg>
          Threat Correlation
        </NavLink>
        <NavLink to="/audit" className={linkClass}>
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
          </svg>
          Audit Ledger
        </NavLink>
      </nav>
      <div className="p-4 border-t border-border space-y-2">
        <div className="flex items-center justify-between text-xs text-text-dim px-2">
          <span>Backend</span>
          <span className="flex items-center gap-1.5 font-medium text-text">
            <span className={`w-2 h-2 rounded-full ${online ? 'bg-success' : 'bg-danger'}`}></span>
            {online ? 'Online' : 'Offline'}
          </span>
        </div>
        <div className="flex items-center justify-between text-xs text-text-dim px-2">
          <span>Database</span>
          <span className="font-medium text-text">PostgreSQL</span>
        </div>
        <p className="text-[10px] text-text-dim text-center pt-2 border-t border-border">
          SIH 2026 — Forensic Platform
        </p>
      </div>
    </aside>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-surface-alt">
        <Sidebar />
        <main className="flex-1 overflow-auto">
          <Routes>
            <Route path="/" element={<UploadPage />} />
            <Route path="/emails" element={<EmailListPage />} />
            <Route path="/emails/:id" element={<EmailDetailPage />} />
            <Route path="/cases" element={<CasesPage />} />
            <Route path="/graph" element={<CorrelationGraphPage />} />
            <Route path="/audit" element={<AuditTrailPage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
