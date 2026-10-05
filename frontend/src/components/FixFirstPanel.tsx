import {FixFirst} from '../types';

export function FixFirstPanel({value,onSelect}:{value?:FixFirst;onSelect?:(id:string)=>void}) {
  if(!value?.rows)return null;
  return <section className="panel p-5 space-y-4">
    <div><h2 className="text-lg font-semibold text-white">Fix first</h2><p className="text-sm text-amber-200 mt-1">[RULE] {value.label}</p></div>
    <details className="text-xs text-slate-400"><summary className="cursor-pointer">Explain ordering and weights</summary>
      <p className="mt-2 leading-relaxed">Severity × {value.weights.severity}; affected sessions × {value.weights.affected_sessions}; anomaly points × {value.weights.anomaly_tiebreak}. Severity values: Critical 5, High 4, Medium 3, Low 2, Info 1.</p>
      <p className="mt-2">{value.formula}</p><p className="mt-2">Isolation Forest: {value.anomaly_status}. {value.anomaly_population===0?'[COVERAGE_GAP] ML abstained or was unavailable; no anomaly tie-break is applied.':'Anomaly is used only when severity and affected-session count tie.'}</p>
    </details>
    {value.rows.length?value.rows.map(row=><button key={row.rule_id+row.severity} onClick={()=>onSelect?.(row.finding_ids[0])} className="w-full text-left border border-slate-700 rounded-lg p-3 hover:bg-slate-800/50 flex gap-3 items-start">
      <span className="text-emerald-300 font-mono">{String(row.rank).padStart(2,'0')}</span><div className="min-w-0 flex-1"><strong className="text-sm text-slate-100">{row.title}</strong>
      <p className="text-xs text-slate-400 mt-1">[RULE] {row.severity} · [OBSERVED] {row.affected_sessions} affected sessions · {row.anomaly_rank===null?'[COVERAGE_GAP] No anomaly rank':`[RULE] Anomaly tie-break rank ${row.anomaly_rank}`}</p>
      <p className="text-xs text-slate-500 break-all mt-1">{row.client_ids.join(', ')}</p></div>
    </button>):<p className="text-sm text-slate-400">No FAIL/WARN findings to prioritise. Review coverage gaps separately.</p>}
  </section>;
}
