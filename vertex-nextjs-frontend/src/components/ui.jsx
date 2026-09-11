'use client'

import { motion } from 'motion/react'

export function Page({ children, className = '' }) {
  return <div className={`mx-auto w-full max-w-[1440px] px-4 py-6 sm:px-6 sm:py-8 lg:px-8 ${className}`}>{children}</div>
}

export function PageHeader({ eyebrow, title, description, actions, back }) {
  return (
    <div className="mb-7 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
      <div>
        {back && <a href={back.href} className="mb-2 inline-flex items-center gap-1.5 text-xs font-semibold text-text-tertiary hover:text-text"><span>←</span>{back.label}</a>}
        {eyebrow && <div className="mb-2 text-[10px] font-bold uppercase tracking-[.18em] text-text-tertiary">{eyebrow}</div>}
        <h1 className="text-[28px] font-extrabold tracking-[-.03em] text-text sm:text-[32px]">{title}</h1>
        {description && <p className="mt-1.5 max-w-2xl text-sm leading-6 text-text-secondary">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export function Card({ children, className = '', hover = false }) {
  return <motion.div whileHover={hover ? { y: -2 } : undefined} transition={{ duration: .16 }} className={`rounded-2xl border border-border bg-white shadow-[0_1px_2px_rgba(15,23,42,.03)] ${className}`}>{children}</motion.div>
}

export function Button({ children, variant = 'primary', className = '', ...props }) {
  const variants = {
    primary: 'bg-slate-950 text-white hover:bg-slate-800 shadow-sm',
    secondary: 'border border-border bg-white text-text hover:bg-surface-muted',
    soft: 'bg-primary-soft text-primary hover:bg-indigo-100',
    danger: 'bg-danger-soft text-danger hover:bg-red-100',
  }
  return <button className={`inline-flex items-center justify-center gap-2 rounded-xl px-3.5 py-2.5 text-xs font-semibold transition disabled:cursor-not-allowed disabled:opacity-50 ${variants[variant]} ${className}`} {...props}>{children}</button>
}

export function Badge({ children, tone = 'neutral' }) {
  const tones = {
    neutral: 'border-border bg-surface-muted text-text-secondary',
    success: 'border-emerald-200 bg-success-soft text-success',
    warning: 'border-amber-200 bg-warning-soft text-warning',
    danger: 'border-red-200 bg-danger-soft text-danger',
    info: 'border-blue-200 bg-info-soft text-info',
    primary: 'border-indigo-200 bg-primary-soft text-primary',
  }
  return <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-bold ${tones[tone]}`}>{children}</span>
}

export function MetricCard({ label, value, hint, icon: Icon, tone = 'neutral' }) {
  const iconTone = { neutral: 'bg-slate-100 text-slate-700', success: 'bg-emerald-50 text-emerald-600', warning: 'bg-amber-50 text-amber-600', danger: 'bg-red-50 text-red-600', primary: 'bg-indigo-50 text-indigo-600' }[tone]
  return <Card className="p-4 sm:p-5"><div className="flex items-start justify-between gap-3"><div><div className="text-[10px] font-bold uppercase tracking-[.15em] text-text-tertiary">{label}</div><div className="mt-2 text-2xl font-extrabold tracking-tight text-text">{value}</div>{hint && <div className="mt-1 text-xs text-text-secondary">{hint}</div>}</div>{Icon && <div className={`rounded-xl p-2.5 ${iconTone}`}><Icon size={17} /></div>}</div></Card>
}

export function Skeleton({ className = '' }) { return <div className={`shimmer rounded-xl ${className}`} /> }

export function EmptyState({ icon: Icon, title, description, action }) {
  return <Card className="p-10 text-center"><div className="mx-auto grid h-12 w-12 place-items-center rounded-2xl bg-surface-muted text-text-tertiary">{Icon ? <Icon size={22} /> : null}</div><h3 className="mt-4 text-sm font-bold text-text">{title}</h3><p className="mx-auto mt-1 max-w-md text-xs leading-5 text-text-secondary">{description}</p>{action && <div className="mt-5">{action}</div>}</Card>
}

export function Alert({ tone = 'danger', children }) {
  const cls = { danger: 'border-red-200 bg-danger-soft text-danger', success: 'border-emerald-200 bg-success-soft text-success', warning: 'border-amber-200 bg-warning-soft text-warning', info: 'border-blue-200 bg-info-soft text-info' }[tone]
  return <div className={`rounded-2xl border p-4 text-sm ${cls}`}>{children}</div>
}
