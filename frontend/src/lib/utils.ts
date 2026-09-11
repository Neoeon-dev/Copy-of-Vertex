export function cn(...values: Array<string | false | null | undefined>): string { return values.filter(Boolean).join(' ') }
export function formatBytes(value?: number | null): string {
  if (!value || value <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1)
  return `${(value / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`
}
export function formatDate(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}
export function riskTone(level?: string): 'success' | 'warning' | 'danger' | 'neutral' {
  if (level === 'LOW') return 'success'
  if (level === 'MEDIUM') return 'warning'
  if (level === 'HIGH' || level === 'CRITICAL') return 'danger'
  return 'neutral'
}
export function humanize(value: string): string { return value.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) }
