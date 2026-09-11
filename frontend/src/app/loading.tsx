import { Page, Skeleton } from '../components/ui'
export default function Loading() { return <Page><div className="space-y-4"><Skeleton className="h-10 w-2/3"/><Skeleton className="h-24 w-full"/><Skeleton className="h-72 w-full"/></div></Page> }
