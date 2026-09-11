import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { ArrowLeft, Inbox, LoaderCircle } from 'lucide-react'
import Link from 'next/link'

export function cn(...values: Array<string | false | null | undefined>): string { return values.filter(Boolean).join(' ') }

export function Button({ className, variant = 'primary', busy = false, children, disabled, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'ghost' | 'danger'; busy?: boolean }) {
  return (
    <button {...props} disabled={disabled || busy} className={cn(
      'inline-flex h-10 items-center justify-center gap-2 rounded-md border px-3.5 text-sm font-semibold transition disabled:pointer-events-none disabled:opacity-45',
      variant === 'primary' && 'border-slate-950 bg-slate-950 text-white hover:bg-slate-800',
      variant === 'secondary' && 'border-border-strong bg-white text-text hover:bg-surface-soft',
      variant === 'ghost' && 'border-transparent bg-transparent text-text-secondary hover:border-border hover:bg-surface-soft hover:text-text',
      variant === 'danger' && 'border-red-200 bg-red-50 text-danger hover:bg-red-100',
      className,
    )}>{busy ? <LoaderCircle size={15} className="animate-spin" /> : null}{children}</button>
  )
}

export function Badge({ children, tone = 'neutral', className }: { children: ReactNode; tone?: 'neutral' | 'primary' | 'success' | 'warning' | 'danger' | 'info'; className?: string }) {
  return <span className={cn('inline-flex items-center gap-1.5 border px-2 py-1 text-[10px] font-bold uppercase tracking-[.08em]', tone === 'neutral' && 'border-border bg-surface-soft text-text-secondary', tone === 'primary' && 'border-indigo-200 bg-indigo-50 text-primary', tone === 'success' && 'border-green-200 bg-green-50 text-success', tone === 'warning' && 'border-amber-200 bg-amber-50 text-warning', tone === 'danger' && 'border-red-200 bg-red-50 text-danger', tone === 'info' && 'border-blue-200 bg-blue-50 text-info', className)}>{children}</span>
}

export function Card({ children, className }: { children: ReactNode; className?: string }) { return <section className={cn('border border-border bg-white', className)}>{children}</section> }

export function Page({ children, className }: { children: ReactNode; className?: string }) { return <div className={cn('mx-auto w-full max-w-[1440px] px-4 py-5 sm:px-6 lg:px-8 lg:py-7', className)}>{children}</div> }

export function PageHeader({ eyebrow, title, description, back, actions }: { eyebrow?: string; title: string; description?: string; back?: { href: string; label: string }; actions?: ReactNode }) {
  return <div className="mb-6 flex flex-col gap-4 border-b border-border pb-5 lg:flex-row lg:items-end lg:justify-between">
    <div className="min-w-0">
      {back ? <Link href={back.href} className="mb-3 inline-flex items-center gap-1.5 text-xs font-semibold text-text-secondary hover:text-text"><ArrowLeft size={13} />{back.label}</Link> : null}
      {eyebrow ? <div className="mb-1 text-[10px] font-bold uppercase tracking-[.14em] text-text-tertiary">{eyebrow}</div> : null}
      <h1 className="text-[28px] font-black tracking-[-0.03em] text-text sm:text-[32px]">{title}</h1>
      {description ? <p className="mt-1.5 max-w-3xl text-sm leading-6 text-text-secondary">{description}</p> : null}
    </div>
    {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
  </div>
}

export function Alert({ children, tone = 'danger', className }: { children: ReactNode; tone?: 'danger' | 'success' | 'warning' | 'info'; className?: string }) {
  return <div className={cn('border px-4 py-3 text-sm', tone === 'danger' && 'border-red-200 bg-red-50 text-red-900', tone === 'success' && 'border-green-200 bg-green-50 text-green-900', tone === 'warning' && 'border-amber-200 bg-amber-50 text-amber-950', tone === 'info' && 'border-blue-200 bg-blue-50 text-blue-950', className)}>{children}</div>
}

export function Skeleton({ className }: { className?: string }) { return <div className={cn('skeleton', className)} /> }

export function EmptyState({ title, description, action }: { icon?: unknown; title: string; description: string; action?: ReactNode }) {
  return <div className="border border-dashed border-border-strong bg-white px-6 py-14 text-center"><div className="mx-auto mb-4 grid h-11 w-11 place-items-center border border-border bg-surface-soft text-text-secondary"><Inbox size={18} /></div><h3 className="text-base font-bold text-text">{title}</h3><p className="mx-auto mt-1 max-w-md text-sm leading-6 text-text-secondary">{description}</p>{action ? <div className="mt-5 flex justify-center">{action}</div> : null}</div>
}
