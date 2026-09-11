import './globals.css'
import AppShell from '../components/AppShell'

export const metadata = { title: 'VERTEX — Forensic Intelligence', description: 'Email threat detection and forensic intelligence workspace.' }

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const themeScript = `(() => { try { const s = localStorage.getItem('vertex-theme'); const d = s ? s === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches; document.documentElement.classList.toggle('dark', d); } catch {} })()`
  return <html lang="en" suppressHydrationWarning><head><script dangerouslySetInnerHTML={{ __html: themeScript }} /></head><body><AppShell>{children}</AppShell></body></html>
}
