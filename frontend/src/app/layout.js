import './globals.css'
import AppShell from '../components/AppShell'

export const metadata = {
  title: 'VERTEX — Forensic Intelligence',
  description: 'Production forensic email intelligence platform',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  )
}
