import React from 'react';
import { ShieldCheck, LayoutDashboard, ScanLine, ListFilter, Route, FlaskConical, FileText, UploadCloud, RefreshCw, ArrowUpRight, Activity } from 'lucide-react';
import { ActiveTab, HealthResponse, Investigation } from '../types';
interface Props { activeTab: ActiveTab; onTabChange: (tab: ActiveTab) => void; health: HealthResponse | null; healthLoading: boolean; onRefresh: () => void; investigation: Investigation | null; onLoadDemo: () => void }
const navigation = [
  {id:'overview', label:'Overview', icon:LayoutDashboard}, {id:'findings', label:'Security findings', icon:ListFilter},
  {id:'replay', label:'Session replay', icon:Route}, {id:'discovery', label:'Client intelligence', icon:ScanLine},
  {id:'simulator', label:'Hardening lab', icon:FlaskConical}, {id:'report', label:'Evidence report', icon:FileText},
] as const;
export const Header: React.FC<Props> = ({activeTab,onTabChange,health,healthLoading,onRefresh,investigation,onLoadDemo}) => <>
  <aside className="workspace-sidebar">
    <a href="#" onClick={e=>{e.preventDefault();onTabChange('overview')}} className="brand"><span className="brand-icon"><ShieldCheck size={23}/></span><span>SecureMail<span className="text-emerald-300">Scope</span><small>EMAIL SECURITY WORKSPACE</small></span></a>
    <div className="workspace-label">INVESTIGATION</div>
    <nav aria-label="Main navigation">{navigation.map(({id,label,icon:Icon})=><button key={id} aria-current={activeTab===id?'page':undefined} onClick={()=>onTabChange(id)} className={`nav-item ${activeTab===id?'selected':''}`}><Icon size={18}/><span>{label}</span>{id==='findings'&&investigation&&<em>{investigation.findings.filter(f=>f.status==='FAIL').length}</em>}</button>)}</nav>
    <button className={`upload-nav ${activeTab==='upload'?'selected':''}`} onClick={()=>onTabChange('upload')}><UploadCloud size={18}/> Analyze a capture <ArrowUpRight size={15}/></button>
    <div className="sidebar-bottom"><div className="local-status"><span className={health?.tshark_available?'status-dot':'status-dot offline'}/><strong>{health?.tshark_available?'Analysis engine ready':'Engine unavailable'}</strong><button aria-label="Check engine health" onClick={onRefresh}><RefreshCw size={14} className={healthLoading?'animate-spin':''}/></button></div><p>Local processing · Passive analysis</p><div className="sih-label"><ShieldCheck size={15}/> SIH <span>PS 26159</span></div></div>
  </aside>
  <header className="workspace-topbar"><div><span className="text-slate-500">Workspace</span><span className="text-slate-600 mx-3">/</span>{activeTab==='upload'?'Analyze a capture':navigation.find(n=>n.id===activeTab)?.label}</div><div className="flex items-center gap-4"><span className={`source-pill ${investigation?.is_simulated?'demo':''}`}><Activity size={13}/>{!investigation?'Connecting':investigation.is_simulated?'Illustrative demo':'PCAP evidence'}</span>{investigation&&!investigation.is_simulated&&<button className="text-xs text-slate-400 hover:text-white" onClick={onLoadDemo}>Open demo</button>}<span className="analyst-avatar" title="Local analyst workspace">SA</span></div></header>
</>;
