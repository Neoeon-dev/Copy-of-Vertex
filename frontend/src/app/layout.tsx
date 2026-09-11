import './globals.css'
import AppShell from '../components/AppShell'

export const metadata = { title: 'VERTEX — Forensic Intelligence', description: 'Email threat detection and forensic intelligence workspace.' }

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body><AppShell>{children}</AppShell></body></html>
}
