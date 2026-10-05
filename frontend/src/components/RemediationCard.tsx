import {Remediation} from '../types';

export function RemediationCard({remediation,fallback}:{remediation?:Remediation;fallback?:string}) {
  return <div className="mt-3 rounded-lg border border-emerald-800/70 bg-emerald-950/20 p-3 text-xs text-emerald-100 space-y-2">
    <strong>[RULE] Recommended fix</strong>
    <ol className="list-decimal pl-4 space-y-1 leading-relaxed">{(remediation?.steps||[fallback||'Review evidence before changing configuration.']).map((step,i)=><li key={i}>{step}</li>)}</ol>
    {remediation?.snippet&&<details onClick={e=>e.stopPropagation()} className="pt-2">
      <summary className="cursor-pointer text-amber-200">{remediation.snippet.software} — {remediation.snippet.warning}</summary>
      <p className="my-2 text-slate-300 leading-relaxed">{remediation.snippet.scope}</p>
      <pre className="rounded bg-slate-950 p-3 whitespace-pre-wrap break-words text-slate-100">{remediation.snippet.config}</pre>
    </details>}
  </div>;
}
