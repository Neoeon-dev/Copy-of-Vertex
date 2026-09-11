'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { AnimatePresence, motion } from 'motion/react'
import { Activity, FileSearch, FolderKanban, GitBranch, Menu, PanelLeftClose, PanelLeftOpen, ShieldCheck, Upload, X } from 'lucide-react'
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

  useEffect(() => {
    let mounted = true
    const ping = () => checkHealth().then(() => mounted && setOnline(true)).catch(() => mounted && setOnline(false))
    ping()
    const interval = setInterval(ping, 30000)
    return () => { mounted = false; clearInterval(interval) }
  }, [])

  const title = useMemo(() => nav.find((item) => active(pathname, item))?.label ?? 'Workspace', [pathname])

  return <div className="min-h-screen bg-bg text-text">
    <aside className={cn('fixed inset-y-0 left-0 z-40 hidden border-r border-border bg-white lg:flex lg:flex-col', compact ? 'w-[76px]' : 'w-[232px]')}>
      <Sidebar compact={compact} setCompact={setCompact} pathname={pathname} online={online} />
    </aside>

    <AnimatePresence>{open ? <><motion.button className="fixed inset-0 z-40 bg-black/25 lg:hidden" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setOpen(false)} aria-label="Close navigation" /><motion.aside className="fixed inset-y-0 left-0 z-50 flex w-[280px] flex-col border-r border-border bg-white lg:hidden" initial={{ x: -20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: -20, opacity: 0 }}><div className="flex h-16 items-center justify-between border-b border-border px-4"><Brand /><button onClick={() => setOpen(false)} className="border border-border p-2 text-text-secondary hover:bg-surface-soft" aria-label="Close menu"><X size={17}/></button></div><Nav pathname={pathname} compact={false} /><StatusBlock online={online} compact={false} /></motion.aside></> : null}</AnimatePresence>

    <main className={compact ? 'lg:pl-[76px]' : 'lg:pl-[232px]'}>
      <header className="sticky top-0 z-30 h-16 border-b border-border bg-white/95 backdrop-blur">
        <div className="flex h-full items-center justify-between px-4 sm:px-6 lg:px-8">
          <div className="flex min-w-0 items-center gap-3"><button className="border border-border bg-white p-2 text-text-secondary hover:bg-surface-soft lg:hidden" onClick={() => setOpen(true)} aria-label="Open menu"><Menu size={18}/></button><div className="truncate text-xs font-semibold text-text-secondary"><span className="text-text-tertiary">VERTEX</span><span className="px-2 text-text-tertiary">/</span>{title}</div></div>
          <div className="flex items-center gap-3 text-xs font-semibold"><span className="hidden border border-border px-2.5 py-1.5 text-text-secondary sm:inline-flex"><span className={cn('mr-2 mt-0.5 h-2 w-2', online === false ? 'bg-danger' : 'bg-success')} />{online === false ? 'API offline' : online === null ? 'Checking API' : 'API online'}</span><span className="hidden border border-border px-2.5 py-1.5 text-text-tertiary sm:inline-flex">v1.1</span></div>
        </div>
      </header>
      <AnimatePresence mode="wait"><motion.div key={pathname} initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -3 }} transition={{ duration: .16 }} className="min-h-[calc(100vh-4rem)]">{children}</motion.div></AnimatePresence>
    </main>
  </div>
}

function Sidebar({ compact, setCompact, pathname, online }: { compact: boolean; setCompact: (value: boolean) => void; pathname: string; online: boolean | null }) {
  return <><div className={cn('flex h-16 items-center border-b border-border px-3', compact ? 'justify-center' : 'justify-between')}><Brand compact={compact}/>{!compact ? <button onClick={() => setCompact(true)} className="border border-border p-1.5 text-text-tertiary hover:bg-surface-soft" title="Collapse navigation"><PanelLeftClose size={15}/></button> : <button onClick={() => setCompact(false)} className="border border-border p-1.5 text-text-tertiary hover:bg-surface-soft" title="Expand navigation"><PanelLeftOpen size={15}/></button>}</div><Nav pathname={pathname} compact={compact}/><StatusBlock online={online} compact={compact}/></>
}

function Brand({ compact = false }: { compact?: boolean }) { return <Link href="/" className="flex items-center gap-2.5"><div className="grid h-8 w-8 shrink-0 place-items-center bg-slate-950 text-sm font-black text-white">V</div>{!compact ? <div><div className="text-[14px] font-black tracking-[-.02em]">VERTEX</div><div className="text-[9px] font-bold uppercase tracking-[.16em] text-text-tertiary">Forensic intelligence</div></div> : null}</Link> }
function Nav({ pathname, compact }: { pathname: string; compact: boolean }) { return <nav className={cn('flex-1 px-2 py-4', compact ? 'space-y-1' : '')}><div className={cn('mb-2 px-2 text-[9px] font-black uppercase tracking-[.16em] text-text-tertiary', compact && 'sr-only')}>Workspace</div>{nav.map((item) => { const Icon = item.icon; const is = active(pathname, item); return <Link key={item.href} href={item.href} title={compact ? item.label : undefined} className={cn('group relative flex h-10 items-center gap-3 px-3 text-sm font-semibold transition', compact ? 'justify-center' : '', is ? 'bg-slate-950 text-white' : 'text-text-secondary hover:bg-surface-soft hover:text-text')}><Icon size={17} strokeWidth={2} />{!compact ? <span>{item.label}</span> : null}</Link>})}</nav> }
function StatusBlock({ online, compact }: { online: boolean | null; compact: boolean }) { return compact ? <div className="border-t border-border p-3"><div className="grid h-10 place-items-center border border-border bg-surface-soft" title="API status"><span className={cn('h-2.5 w-2.5', online === false ? 'bg-danger' : 'bg-success')} /></div></div> : <div className="border-t border-border p-3"><div className="border border-border bg-surface-soft p-3"><div className="flex items-center gap-2 text-xs font-bold"><Activity size={14}/> Runtime</div><div className="mt-2 flex items-center justify-between text-[11px] text-text-secondary"><span>API</span><span className="flex items-center gap-1.5 font-semibold"><span className={cn('h-2 w-2', online === false ? 'bg-danger' : 'bg-success')} />{online === false ? 'Offline' : 'Online'}</span></div><div className="mt-1 flex items-center justify-between text-[11px] text-text-secondary"><span>Database</span><span>PostgreSQL</span></div></div></div> }
