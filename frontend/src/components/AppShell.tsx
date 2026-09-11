'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { AnimatePresence, motion } from 'motion/react'
import { Activity, FileSearch, FolderKanban, GitBranch, Menu, Moon, PanelLeftClose, PanelLeftOpen, ShieldCheck, Sun, Upload, X } from 'lucide-react'
import { checkHealth } from '../lib/api'
import { cn } from '../lib/utils'

const nav = [
  { href: '/', label: 'Analyze email', icon: Upload, end: true },
  { href: '/emails', label: 'Email feed', icon: FileSearch },
  { href: '/cases', label: 'Cases', icon: FolderKanban },
  { href: '/graph', label: 'Correlation', icon: GitBranch },
  { href: '/audit', label: 'Audit ledger', icon: ShieldCheck },
]

function active(path: string, item: typeof nav[number]) { return item.end ? path === '/' : path === item.href || path.startsWith(`${item.href}/`) }

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const [open, setOpen] = useState(false)
  const [compact, setCompact] = useState(false)
  const [online, setOnline] = useState<boolean | null>(null)
  const [dark, setDark] = useState(false)

  useEffect(() => {
    const stored = localStorage.getItem('vertex-theme')
    const prefersDark = window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false
    const next = stored ? stored === 'dark' : prefersDark
    setDark(next)
    document.documentElement.classList.toggle('dark', next)
  }, [])

  function toggleTheme() {
    const next = !dark
    setDark(next)
    localStorage.setItem('vertex-theme', next ? 'dark' : 'light')
    document.documentElement.classList.toggle('dark', next)
  }

  useEffect(() => {
    let mounted = true
    const ping = () => checkHealth().then(() => mounted && setOnline(true)).catch(() => mounted && setOnline(false))
    ping()
    const interval = setInterval(ping, 30000)
    return () => { mounted = false; clearInterval(interval) }
  }, [])

  const title = useMemo(() => nav.find((item) => active(pathname, item))?.label ?? 'Workspace', [pathname])

  return <div className="min-h-screen bg-bg text-text">
    <aside className={cn('fixed inset-y-0 left-0 z-40 hidden border-r border-border bg-surface lg:flex lg:flex-col', compact ? 'w-[80px]' : 'w-[240px]')}>
      <Sidebar compact={compact} setCompact={setCompact} pathname={pathname} online={online} dark={dark} />
    </aside>

    <AnimatePresence>{open ? <>
      <motion.button className="fixed inset-0 z-40 bg-black/30 backdrop-blur-[2px] lg:hidden" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setOpen(false)} aria-label="Close navigation" />
      <motion.aside className="fixed inset-y-0 left-0 z-50 flex w-[290px] flex-col border-r border-border bg-surface lg:hidden" initial={{ x: -20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: -20, opacity: 0 }}>
        <div className="flex h-16 items-center justify-between border-b border-border px-4"><Brand /><button onClick={() => setOpen(false)} className="focus-ring rounded-xl border border-border p-2 text-text-secondary hover:bg-surface-soft" aria-label="Close menu"><X size={17}/></button></div>
        <Nav pathname={pathname} compact={false} />
        <StatusBlock online={online} compact={false} />
      </motion.aside>
    </> : null}</AnimatePresence>

    <main className={compact ? 'lg:pl-[80px]' : 'lg:pl-[240px]'}>
      <header className="sticky top-0 z-30 h-16 border-b border-border bg-surface/95 backdrop-blur-xl">
        <div className="flex h-full items-center justify-between px-4 sm:px-6 lg:px-8">
          <div className="flex min-w-0 items-center gap-3"><button className="focus-ring rounded-xl border border-border bg-surface p-2 text-text-secondary hover:bg-surface-soft lg:hidden" onClick={() => setOpen(true)} aria-label="Open menu"><Menu size={18}/></button><div className="truncate text-xs font-semibold text-text-secondary"><span className="text-text-tertiary">VERTEX</span><span className="px-2 text-text-tertiary">/</span>{title}</div></div>
          <div className="flex items-center gap-2 text-xs font-semibold">
            <ThemeToggle dark={dark} onToggle={toggleTheme} />
            <span className="hidden rounded-full border border-border px-3 py-1.5 text-text-secondary sm:inline-flex"><span className={cn('mr-2 mt-0.5 h-2 w-2 rounded-full', online === false ? 'bg-danger' : online === null ? 'bg-warning' : 'bg-success')} />{online === false ? 'API offline' : online === null ? 'Checking API' : 'API online'}</span>
            <span className="hidden rounded-full border border-border px-3 py-1.5 text-text-tertiary sm:inline-flex">v1.2</span>
          </div>
        </div>
      </header>
      <AnimatePresence mode="wait"><motion.div key={pathname} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -3 }} transition={{ duration: .18 }} className="min-h-[calc(100vh-4rem)]">{children}</motion.div></AnimatePresence>
    </main>
  </div>
}

function ThemeToggle({ dark, onToggle }: { dark: boolean; onToggle: () => void }) {
  return <button onClick={onToggle} className="focus-ring inline-grid h-9 w-9 place-items-center rounded-full border border-border bg-surface text-text-secondary shadow-sm transition hover:bg-surface-soft" title={dark ? 'Switch to light mode' : 'Switch to dark mode'} aria-label={dark ? 'Switch to light mode' : 'Switch to dark mode'}>{dark ? <Sun size={15}/> : <Moon size={15}/>}</button>
}

function Sidebar({ compact, setCompact, pathname, online, dark }: { compact: boolean; setCompact: (value: boolean) => void; pathname: string; online: boolean | null; dark: boolean }) {
  return <>
    <div className={cn('flex h-16 items-center border-b border-border px-3', compact ? 'justify-center' : 'justify-between')}><Brand compact={compact}/>{!compact ? <button onClick={() => setCompact(true)} className="focus-ring rounded-xl border border-border p-1.5 text-text-tertiary hover:bg-surface-soft" title="Collapse navigation"><PanelLeftClose size={15}/></button> : <button onClick={() => setCompact(false)} className="focus-ring rounded-xl border border-border p-1.5 text-text-tertiary hover:bg-surface-soft" title="Expand navigation"><PanelLeftOpen size={15}/></button>}</div>
    <Nav pathname={pathname} compact={compact}/>
    <StatusBlock online={online} compact={compact}/>
  </>
}

function Brand({ compact = false }: { compact?: boolean }) { return <Link href="/" className="flex items-center gap-2.5"><div className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-slate-950 text-sm font-black text-white shadow-sm dark:bg-white dark:text-slate-950">V</div>{!compact ? <div><div className="text-[14px] font-black tracking-[-.02em]">VERTEX</div><div className="text-[9px] font-bold uppercase tracking-[.16em] text-text-tertiary">Forensic intelligence</div></div> : null}</Link> }
function Nav({ pathname, compact }: { pathname: string; compact: boolean }) { return <nav className={cn('flex-1 px-2.5 py-4', compact ? 'space-y-1' : '')}><div className={cn('mb-2 px-2 text-[9px] font-black uppercase tracking-[.16em] text-text-tertiary', compact && 'sr-only')}>Workspace</div>{nav.map((item) => { const Icon = item.icon; const is = active(pathname, item); return <Link key={item.href} href={item.href} title={compact ? item.label : undefined} className={cn('focus-ring group relative my-1 flex h-10 items-center gap-3 rounded-xl px-3 text-sm font-semibold transition', compact ? 'justify-center' : '', is ? 'bg-slate-950 text-white shadow-sm dark:bg-white dark:text-slate-950' : 'text-text-secondary hover:bg-surface-soft hover:text-text')}><Icon size={17} strokeWidth={2} />{!compact ? <span>{item.label}</span> : null}</Link>})}</nav> }
function StatusBlock({ online, compact }: { online: boolean | null; compact: boolean }) { return compact ? <div className="border-t border-border p-3"><div className="grid h-10 place-items-center rounded-xl border border-border bg-surface-soft" title="API status"><span className={cn('h-2.5 w-2.5 rounded-full', online === false ? 'bg-danger' : online === null ? 'bg-warning' : 'bg-success')} /></div></div> : <div className="border-t border-border p-3"><div className="rounded-2xl border border-border bg-surface-soft p-3"><div className="flex items-center gap-2 text-xs font-bold"><Activity size={14}/> Runtime</div><div className="mt-2 flex items-center justify-between text-[11px] text-text-secondary"><span>API</span><span className="flex items-center gap-1.5 font-semibold"><span className={cn('h-2 w-2 rounded-full', online === false ? 'bg-danger' : online === null ? 'bg-warning' : 'bg-success')} />{online === false ? 'Offline' : online === null ? 'Checking' : 'Online'}</span></div><div className="mt-1 flex items-center justify-between text-[11px] text-text-secondary"><span>Database</span><span>PostgreSQL</span></div></div></div> }
