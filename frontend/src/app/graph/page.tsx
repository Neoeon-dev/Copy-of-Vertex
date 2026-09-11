'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { GitBranch, Mail, Globe2, Server, FolderKanban, Hash, Search } from 'lucide-react'
import { Button, Card, EmptyState, Page, PageHeader, Badge, Skeleton } from '../../components/ui'
import { apiError, getCorrelationGraph, getSharedInfrastructure } from '../../lib/api'
import type { GraphEdge, GraphNode } from '../../types/api'

export default function GraphPage() {
  const [nodes, setNodes] = useState<GraphNode[]>([])
  const [edges, setEdges] = useState<GraphEdge[]>([])
  const [shared, setShared] = useState<Record<string, unknown>>({})
  const [filter, setFilter] = useState('ALL')
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<GraphNode | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    Promise.all([getCorrelationGraph(), getSharedInfrastructure()])
      .then(([g, s]) => {
        const ns: GraphNode[] = g.elements?.nodes
          ? g.elements.nodes.flatMap((item) => (item.data ? [item.data] : []))
          : (g.nodes ?? [])
        const es: GraphEdge[] = g.elements?.edges
          ? g.elements.edges.flatMap((item) => (item.data ? [item.data] : []))
          : (g.links ?? [])
        setNodes(ns)
        setEdges(es)
        setShared(s.shared ?? {})
      })
      .catch((e) => setError(apiError(e)))
      .finally(() => setLoading(false))
  }, [])

  const filtered = useMemo(()=>nodes.filter((node)=>{const type=(node.nodeType||node.type||'ENTITY').toUpperCase(); const q=query.toLowerCase(); return (filter==='ALL'||type===filter)&&(!q||`${node.label||''} ${node.id}`.toLowerCase().includes(q))}),[nodes,filter,query])
  const positions = useMemo(()=>{ const map = new Map<string,{x:number;y:number}>(); const n=Math.max(filtered.length,1); filtered.slice(0,30).forEach((node,i)=>{const angle=i/n*Math.PI*2-Math.PI/2; const radius=34+(i%3)*4; map.set(node.id,{x:50+Math.cos(angle)*radius,y:50+Math.sin(angle)*radius})}); return map },[filtered])
  const sharedKeys=Object.keys(shared)

  return <Page><PageHeader eyebrow="Campaign intelligence" title="Threat correlation" description="Explore the in-memory graph generated from analyzed emails, extracted infrastructure, URLs and cases."/><div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">{loading?<Skeleton className="h-[620px]"/>:<Card className="overflow-hidden"><div className="flex flex-col gap-3 border-b border-border p-4 sm:flex-row sm:items-center sm:justify-between"><div className="flex flex-wrap items-center gap-1.5">{['ALL','EMAIL','IP','DOMAIN','SENDER','CASE'].map((x)=><button key={x} onClick={()=>setFilter(x)} className={`rounded-full px-3 py-1.5 text-[10px] font-black transition ${filter===x?'bg-slate-950 text-white shadow-sm dark:bg-white dark:text-slate-950':'bg-surface-soft text-text-secondary hover:bg-border/70'}`}>{x}</button>)}</div><div className="relative w-full sm:w-56"><Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-tertiary"/><input value={query} onChange={(e)=>setQuery(e.target.value)} placeholder="Find a node" className="focus-ring h-9 w-full rounded-full border border-border bg-surface-soft pl-8 pr-3 text-xs outline-none focus:border-slate-400"/></div></div><div className="relative min-h-[540px] overflow-hidden rounded-b-2xl bg-bg p-3"><svg className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none"><defs><pattern id="grid" width="4" height="4" patternUnits="userSpaceOnUse"><path d="M 4 0 L 0 0 0 4" fill="none" stroke="#ececef" strokeWidth=".1"/></pattern></defs><rect width="100" height="100" fill="url(#grid)"/>{edges.map((edge,index)=>{const s=positions.get(String(edge.source));const t=positions.get(String(edge.target)); if(!s||!t)return null; return <line key={edge.id||index} x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke="#cfd1d6" strokeWidth=".18"/>})}</svg>{filtered.slice(0,30).map((node)=>{const p=positions.get(node.id)||{x:50,y:50};const type=(node.nodeType||node.type||'ENTITY').toLowerCase();return <button key={node.id} onClick={()=>setSelected(node)} className="absolute -translate-x-1/2 -translate-y-1/2 text-left" style={{left:`${p.x}%`,top:`${p.y}%`}}><div className={`grid h-11 w-11 place-items-center rounded-full border bg-surface shadow-sm transition ${type==='email'?'border-indigo-200 text-primary':type==='ip'?'border-amber-200 text-warning':type==='domain'||type==='sender'?'border-blue-200 text-info':type==='case'?'border-slate-300 text-text':'border-border text-text-secondary'}`}>{type==='email'?<Mail size={16}/>:type==='ip'?<Server size={16}/>:type==='domain'||type==='sender'?<Globe2 size={16}/>:type==='case'?<FolderKanban size={16}/>:<Hash size={16}/>}</div><div className="mt-1 max-w-32 truncate rounded-full bg-surface px-2 py-1 text-center text-[9px] font-bold text-text shadow-sm ring-1 ring-border">{String(node.label||node.id)}</div></button>})}{filtered.length===0?<div className="absolute inset-0 grid place-items-center"><EmptyState title="No matching nodes" description="Add emails to the graph from an investigation page."/></div>:null}</div><div className="grid border-t border-border sm:grid-cols-3"><Stat label="Nodes" value={nodes.length}/><Stat label="Relationships" value={edges.length}/><Stat label="Shared indicators" value={sharedKeys.length}/></div></Card>}{error?<AlertBox text={error}/>:null}<div className="space-y-5"><Card className="p-5"><div className="text-sm font-black">Shared infrastructure</div><p className="mt-1 text-xs leading-5 text-text-secondary">Repeated IPs or domains across more than one email.</p><div className="mt-4 space-y-2">{sharedKeys.length?sharedKeys.map((key)=><div key={key} className="border border-border bg-surface-soft p-3"><div className="flex items-center justify-between gap-2"><span className="font-mono text-[11px] font-bold">{key}</span><Badge tone="warning">shared</Badge></div><div className="mt-1 text-[10px] leading-4 text-text-secondary">{Array.isArray(shared[key])?shared[key].join(', '):JSON.stringify(shared[key])}</div></div>):<div className="border border-dashed border-border p-4 text-xs text-text-tertiary">No shared indicators detected.</div>}</div></Card><Card className="p-5"><div className="text-sm font-black">Node details</div>{selected?<div className="mt-4 space-y-3"><div><div className="text-[10px] font-black uppercase tracking-wider text-text-tertiary">Type</div><div className="mt-1 text-xs font-bold">{selected.nodeType||selected.type||'ENTITY'}</div></div><div><div className="text-[10px] font-black uppercase tracking-wider text-text-tertiary">Label</div><div className="mt-1 break-all text-sm font-semibold">{selected.label||selected.id}</div></div><div><div className="text-[10px] font-black uppercase tracking-wider text-text-tertiary">Identifier</div><div className="mt-1 break-all font-mono text-[10px] text-text-secondary">{selected.id}</div></div>{selected.email_id?<Link href={`/emails/${selected.email_id}`}><Button className="mt-2 w-full">Open email</Button></Link>:null}</div>:<div className="mt-4 text-xs leading-5 text-text-tertiary">Select a node in the workspace to inspect it.</div>}</Card></div></div></Page>
}

function Stat({label,value}:{label:string;value:number}){return <div className="border-r border-border p-4 last:border-0"><div className="text-[10px] font-black uppercase tracking-wider text-text-tertiary">{label}</div><div className="mt-1 text-xl font-black">{value}</div></div>}
function AlertBox({text}:{text:string}){return <div className="border border-red-200 bg-red-50 p-4 text-sm text-danger">{text}</div>}
