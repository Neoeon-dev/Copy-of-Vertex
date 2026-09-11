import Link from 'next/link'
import { Page, Button } from '../components/ui'
export default function NotFound() { return <Page className="grid min-h-[70vh] place-items-center"><div className="text-center"><div className="text-[72px] font-black tracking-[-.06em]">404</div><p className="mt-2 text-sm text-text-secondary">That VERTEX workspace does not exist.</p><Link href="/" className="mt-5 inline-flex"><Button>Back to workspace</Button></Link></div></Page> }
