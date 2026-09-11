'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { AnimatePresence, motion } from 'motion/react'
import {
  Activity,
  ArrowLeft,
  Bell,
  CaseSensitive,
  FileSearch,
  FolderKanban,
  GitBranch,
  LayoutDashboard,
  Menu,
  ShieldCheck,
  Upload,
  X,
} from 'lucide-react'
import { checkHealth } from '../lib/api'

const nav = [
  { href: '/', label: 'Analyze', icon: Upload, end: true },
  { href: '/emails', label: 'Email feed', icon: FileSearch },
  { href: '/cases', label: 'Cases', icon: FolderKanban },
  { href: '/graph', label: 'Correlation', icon: GitBranch },
  { href: '/audit', label: 'Audit ledger', icon: ShieldCheck },
]

function isActive(pathname, item) {
  if (item.end) return pathname === '/'
  return pathname === item.href || pathname.startsWith(`${item.href}/`)
}

export default function AppShell({ children }) {
  const pathname = usePathname()
  const [mobileOpen, setMobileOpen] = useState(false)
  const [online, setOnline] = useState(null)

  useEffect(() => {
    let alive = true
    checkHealth().then(() => alive && setOnline(true)).catch(() => alive && setOnline(false))
    const timer = setInterval(() => {
      checkHealth().then(() => alive && setOnline(true)).catch(() => alive && setOnline(false))
    }, 30000)
    return () => { alive = false; clearInterval(timer) }
  }, [])

  useEffect(() => setMobileOpen(false), [pathname])

  const title = useMemo(() => nav.find((item) => isActive(pathname, item))?.label || 'Workspace', [pathname])

  return (
    <div className="min-h-screen bg-bg">
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-[248px] border-r border-border bg-white lg:flex lg:flex-col">
        <SidebarContent pathname={pathname} online={online} />
      </aside>

      <AnimatePresence>
        {mobileOpen && (
          <>
            <motion.button
              aria-label="Close navigation"
              className="fixed inset-0 z-40 bg-slate-950/25 backdrop-blur-[2px] lg:hidden"
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              onClick={() => setMobileOpen(false)}
            />
            <motion.aside
              className="fixed inset-y-0 left-0 z-50 flex w-[280px] flex-col border-r border-border bg-white lg:hidden"
              initial={{ x: -30, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: -30, opacity: 0 }}
              transition={{ duration: .2 }}
            >
              <div className="flex items-center justify-between border-b border-border p-4">
                <Brand />
                <button className="rounded-xl p-2 text-text-secondary hover:bg-surface-muted" onClick={() => setMobileOpen(false)}><X size={18} /></button>
              </div>
              <SidebarNav pathname={pathname} />
              <SidebarFooter online={online} />
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      <main className="lg:pl-[248px]">
        <header className="sticky top-0 z-30 border-b border-border bg-white/85 backdrop-blur-xl">
          <div className="flex h-[68px] items-center justify-between px-4 sm:px-6 lg:px-8">
            <div className="flex items-center gap-3">
              <button className="rounded-xl border border-border bg-white p-2 text-text-secondary shadow-sm hover:bg-surface-muted lg:hidden" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu size={18} /></button>
              <div className="hidden items-center gap-2 text-sm text-text-tertiary sm:flex">
                <span>VERTEX</span><span>/</span><span className="text-text-secondary">{title}</span>
              </div>
              <div className="flex items-center gap-2 sm:hidden">
                <Brand compact />
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="hidden items-center gap-2 rounded-full border border-border bg-white px-3 py-1.5 text-xs font-medium text-text-secondary sm:flex">
                <span className={`h-2 w-2 rounded-full ${online === false ? 'bg-danger' : 'bg-success'}`} />
                {online === false ? 'API offline' : 'API operational'}
              </div>
              <button aria-label="Notifications" className="rounded-xl border border-border bg-white p-2 text-text-secondary shadow-sm hover:bg-surface-muted"><Bell size={17} /></button>
            </div>
          </div>
        </header>

        <AnimatePresence mode="wait">
          <motion.div
            key={pathname}
            initial={{ opacity: 0, y: 7 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: .18, ease: 'easeOut' }}
            className="min-h-[calc(100vh-68px)]"
          >
            {children}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  )
}

function SidebarContent({ pathname, online }) {
  return <><div className="p-5"><Brand /></div><SidebarNav pathname={pathname} /><SidebarFooter online={online} /></>
}

function Brand({ compact = false }) {
  return (
    <Link href="/" className="flex items-center gap-3">
      <div className="grid h-10 w-10 place-items-center rounded-2xl bg-slate-950 text-sm font-black tracking-tight text-white shadow-[0_8px_24px_rgba(15,23,42,.16)]">V</div>
      {!compact && <div><div className="text-[15px] font-extrabold tracking-tight text-text">VERTEX</div><div className="text-[10px] font-semibold uppercase tracking-[.15em] text-text-tertiary">Forensic intelligence</div></div>}
    </Link>
  )
}

function SidebarNav({ pathname }) {
  return (
    <nav className="flex-1 px-3 py-2">
      <div className="mb-2 px-2 text-[10px] font-bold uppercase tracking-[.16em] text-text-tertiary">Workspace</div>
      <div className="space-y-1">
        {nav.map((item) => {
          const active = isActive(pathname, item)
          const Icon = item.icon
          return (
            <Link key={item.href} href={item.href} className={`group relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition ${active ? 'bg-primary-soft text-primary' : 'text-text-secondary hover:bg-surface-muted hover:text-text'}`}>
              <Icon size={17} strokeWidth={1.9} />
              <span>{item.label}</span>
              {active && <motion.span layoutId="nav-pill" className="absolute right-2 h-5 w-1 rounded-full bg-primary" transition={{ type: 'spring', stiffness: 400, damping: 30 }} />}
            </Link>
          )
        })}
      </div>
      <div className="mt-7 px-2 text-[10px] font-bold uppercase tracking-[.16em] text-text-tertiary">System</div>
      <div className="mt-2 rounded-2xl border border-border bg-surface-muted p-3">
        <div className="flex items-center gap-2 text-xs font-semibold text-text"><Activity size={14} /> Runtime status</div>
        <div className="mt-2 flex items-center justify-between text-xs text-text-secondary"><span>API</span><span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-success" /> Active</span></div>
        <div className="mt-1 flex items-center justify-between text-xs text-text-secondary"><span>Storage</span><span>PostgreSQL</span></div>
      </div>
    </nav>
  )
}

function SidebarFooter({ online }) {
  return <div className="border-t border-border p-4"><div className="rounded-xl border border-border bg-white p-3"><div className="text-[10px] font-bold uppercase tracking-[.16em] text-text-tertiary">Platform</div><div className="mt-1 text-xs font-semibold text-text">Production workspace</div><div className="mt-2 flex items-center gap-1.5 text-[11px] text-text-secondary"><span className={`h-2 w-2 rounded-full ${online === false ? 'bg-danger' : 'bg-success'}`} />{online === false ? 'Backend unavailable' : 'Backend healthy'}</div></div></div>
}
