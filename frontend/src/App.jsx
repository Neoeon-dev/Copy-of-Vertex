import { useEffect, useState } from 'react'
import { BrowserRouter, NavLink, Route, Routes, useLocation } from 'react-router-dom'
import UploadPage from './pages/UploadPage'
import EmailListPage from './pages/EmailListPage'
import EmailDetailPage from './pages/EmailDetailPage'
import CasesPage from './pages/CasesPage'
import CorrelationGraphPage from './pages/CorrelationGraphPage'
import AuditTrailPage from './pages/AuditTrailPage'
import { checkHealth } from './api'

const navItems = [
  { to: '/', label: 'Upload', icon: 'upload', end: true },
  { to: '/emails', label: 'Analyzed Emails', icon: 'mail' },
  { to: '/cases', label: 'Investigation Cases', icon: 'case' },
  { to: '/graph', label: 'Threat Correlation', icon: 'graph' },
  { to: '/audit', label: 'Audit Ledger', icon: 'shield' },
]

function Icon({ name, className = 'h-5 w-5' }) {
  const paths = {
    upload: 'M12 16V4m0 0 4.5 4.5M12 4 7.5 8.5M4 15.5v2.25A2.25 2.25 0 0 0 6.25 20h11.5A2.25 2.25 0 0 0 20 17.75V15.5',
    mail: 'M4 6.5A2.5 2.5 0 0 1 6.5 4h11A2.5 2.5 0 0 1 20 6.5v11a2.5 2.5 0 0 1-2.5 2.5h-11A2.5 2.5 0 0 1 4 17.5v-11ZM5 7l6.2 4.3a1.4 1.4 0 0 0 1.6 0L19 7',
    case: 'M4.5 7.25A2.25 2.25 0 0 1 6.75 5h3l1.5 1.75h6A2.25 2.25 0 0 1 19.5 9v7.75A2.25 2.25 0 0 1 17.25 19h-10A2.25 2.25 0 0 1 5 16.75V9.5',
    graph: 'M5 18.5 10 13l4 3 5-7M6.5 5.5h-.01M12 10h-.01M18 6h-.01',
    shield: 'M12 3.75a11 11 0 0 1 7.75 3.05A11.2 11.2 0 0 1 20 10c0 5.5-3.35 9.05-8 10.25C7.35 19.05 4 15.5 4 10a11.2 11.2 0 0 1 .25-3.2A11 11 0 0 1 12 3.75Z',
    menu: 'M4 7h16M4 12h16M4 17h16',
    close: 'm6 6 12 12M18 6 6 18',
  }
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.7"><path strokeLinecap="round" strokeLinejoin="round" d={paths[name]} /></svg>
}

function Header() {
  const location = useLocation()
  const active = navItems.find((item) => item.end ? location.pathname === item.to : location.pathname.startsWith(item.to))
  return (
    <header className="sticky top-0 z-20 border-b border-slate-200/80 bg-white/90 backdrop-blur-xl">
      <div className="flex h-16 items-center justify-between gap-4 px-4 sm:px-6 lg:px-8">
        <div className="min-w-0">
          <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-400">Forensic workspace</p>
          <h2 className="truncate text-sm font-semibold text-slate-900 sm:text-base">{active?.label || 'VERTEX'}</h2>
        </div>
        <div className="hidden items-center gap-2 sm:flex">
          <span className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-500">SIH 2026</span>
          <span className="rounded-full border border-indigo-100 bg-indigo-50 px-3 py-1.5 text-xs font-semibold text-indigo-600">VERTEX</span>
        </div>
      </div>
    </header>
  )
}

function Sidebar({ open, setOpen }) {
  const [online, setOnline] = useState(true)
  useEffect(() => {
    checkHealth().then(() => setOnline(true)).catch(() => setOnline(false))
  }, [])

  return (
    <>
      {open && <button aria-label="Close navigation" className="fixed inset-0 z-30 bg-slate-950/30 backdrop-blur-[2px] lg:hidden" onClick={() => setOpen(false)} />}
      <aside className={`fixed inset-y-0 left-0 z-40 flex w-[272px] -translate-x-full flex-col border-r border-slate-200 bg-white transition-transform duration-200 lg:relative lg:z-auto lg:translate-x-0 ${open ? 'translate-x-0' : ''}`}>
        <div className="flex h-20 items-center justify-between border-b border-slate-100 px-5">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-slate-950 text-sm font-bold tracking-wide text-white shadow-sm">VX</div>
            <div>
              <h1 className="text-base font-bold tracking-tight text-slate-950">VERTEX</h1>
              <p className="text-[10px] font-semibold uppercase tracking-[0.17em] text-slate-400">Forensic intelligence</p>
            </div>
          </div>
          <button aria-label="Close navigation" onClick={() => setOpen(false)} className="rounded-xl p-2 text-slate-400 hover:bg-slate-50 hover:text-slate-700 lg:hidden"><Icon name="close" className="h-5 w-5" /></button>
        </div>

        <nav className="flex-1 space-y-1 px-3 py-5">
          <p className="px-3 pb-2 text-[10px] font-bold uppercase tracking-[0.18em] text-slate-400">Workspace</p>
          {navItems.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end} onClick={() => setOpen(false)} className={({ isActive }) => `group flex items-center gap-3 rounded-2xl px-3.5 py-3 text-sm font-medium transition ${isActive ? 'bg-slate-950 text-white shadow-sm' : 'text-slate-500 hover:bg-slate-50 hover:text-slate-900'}`}>
              <Icon name={item.icon} className="h-[18px] w-[18px]" />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-slate-100 p-4">
          <div className="rounded-2xl bg-slate-50 p-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium text-slate-500">Backend</span>
              <span className="flex items-center gap-1.5 font-semibold text-slate-700"><span className={`h-2 w-2 rounded-full ${online ? 'bg-emerald-500' : 'bg-red-500'}`} />{online ? 'Online' : 'Offline'}</span>
            </div>
            <div className="mt-2 flex items-center justify-between text-xs">
              <span className="font-medium text-slate-500">Storage</span>
              <span className="font-semibold text-slate-700">PostgreSQL</span>
            </div>
          </div>
          <p className="px-2 pt-3 text-center text-[10px] leading-4 text-slate-400">Evidence-first email forensics workspace</p>
        </div>
      </aside>
    </>
  )
}

function Shell() {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 lg:flex">
      <Sidebar open={sidebarOpen} setOpen={setSidebarOpen} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center border-b border-slate-200/80 bg-white px-4 py-2 lg:hidden">
          <button aria-label="Open navigation" onClick={() => setSidebarOpen(true)} className="rounded-xl p-2 text-slate-500 hover:bg-slate-50"><Icon name="menu" className="h-5 w-5" /></button>
          <span className="ml-2 text-sm font-bold tracking-tight">VERTEX</span>
        </div>
        <Header />
        <main className="min-h-[calc(100vh-4rem)] px-4 py-5 sm:px-6 sm:py-7 lg:px-8">
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
    </div>
  )
}

export default function App() {
  return <BrowserRouter><Shell /></BrowserRouter>
}
