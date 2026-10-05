import React from 'react';
import { Investigation, SecurityFinding } from '../types';
import { FindingsTable } from '../components/FindingsTable';
import { HonestyBanner } from '../components/HonestyBanner';
import { ShieldAlert, AlertTriangle, Info } from 'lucide-react';

interface FindingsPageProps {
  investigation: Investigation;
  onSelectFinding: (finding: SecurityFinding) => void;
  onNavigateToSimulator?: (policyId: string) => void;
  onNavigateToReplay?: (ruleId: string) => void;
}

export const FindingsPage: React.FC<FindingsPageProps> = ({
  investigation,
  onSelectFinding,
  onNavigateToSimulator,
  onNavigateToReplay,
}) => {
  const criticalCount = investigation.findings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = investigation.findings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = investigation.findings.filter((f) => f.severity === 'MEDIUM').length;
  const infoCount = investigation.findings.filter((f) => f.severity === 'INFO').length;

  return (
    <div className="space-y-6">
      <HonestyBanner investigation={investigation} />

      {/* Summary KPI Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-slate-900/90 border border-rose-900/30 rounded-xl p-3.5 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-rose-400">Critical</span>
            <div className="text-2xl font-extrabold text-white mt-0.5">{criticalCount}</div>
          </div>
          <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900/90 border border-orange-900/30 rounded-xl p-3.5 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-orange-400">High</span>
            <div className="text-2xl font-extrabold text-white mt-0.5">{highCount}</div>
          </div>
          <div className="p-2 rounded-lg bg-orange-500/10 text-orange-400">
            <AlertTriangle className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900/90 border border-amber-900/30 rounded-xl p-3.5 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-amber-400">Medium</span>
            <div className="text-2xl font-extrabold text-white mt-0.5">{mediumCount}</div>
          </div>
          <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400">
            <AlertTriangle className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900/90 border border-sky-900/30 rounded-xl p-3.5 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-sky-400">Info</span>
            <div className="text-2xl font-extrabold text-white mt-0.5">{infoCount}</div>
          </div>
          <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400">
            <Info className="w-5 h-5" />
          </div>
        </div>
      </div>

      <FindingsTable
        findings={investigation.findings}
        onSelectFinding={onSelectFinding}
        onNavigateToSimulator={onNavigateToSimulator}
        onNavigateToReplay={onNavigateToReplay}
      />
    </div>
  );
};
