import {RemediationCard} from './RemediationCard';
import React, { useState } from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Info, 
  ChevronRight, 
  Filter, 
  FileText,
  CheckCircle2,
  BookOpen,
  Play,
  Sliders
} from 'lucide-react';
import { SecurityFinding, SecuritySeverity } from '../types';

interface FindingsTableProps {
  findings: SecurityFinding[];
  onSelectFinding: (finding: SecurityFinding) => void;
  onNavigateToSimulator?: (policyId: string) => void;
  onNavigateToReplay?: (ruleId: string) => void;
}

export const FindingsTable: React.FC<FindingsTableProps> = ({
  findings,
  onSelectFinding,
  onNavigateToSimulator,
  onNavigateToReplay,
}) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');

  const getPolicyForFinding = (ruleId: string): { id: string; label: string } | null => {
    switch (ruleId) {
      case 'SMS-TLSVER-001':
      case 'SMS-TLSVER-002':
        return { id: 'SMS-POLICY-TLS12', label: 'Evaluate TLS 1.2+ Policy' };
      case 'SMS-TLS-001':
      case 'SMS-STARTTLS-001':
      case 'SMS-AUTH-001':
        return { id: 'SMS-POLICY-REQUIRE-TLS', label: 'Evaluate Require TLS Policy' };
      case 'SMS-CIPHER-001':
        return { id: 'SMS-POLICY-NO-WEAK-CIPHER', label: 'Evaluate No Weak Cipher Policy' };
      case 'SMS-PFS-001':
        return { id: 'SMS-POLICY-PFS', label: 'Evaluate PFS Policy' };
      default:
        return null;
    }
  };

  const filteredFindings = findings.filter((f) => {
    if (filterSeverity === 'ALL') return true;
    return f.severity === filterSeverity;
  });

  const getSeverityBadge = (severity: SecuritySeverity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-500/15 text-rose-300 border-rose-500/40';
      case 'HIGH':
        return 'bg-orange-500/15 text-orange-300 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-amber-500/15 text-amber-300 border-amber-500/40';
      case 'LOW':
        return 'bg-sky-500/15 text-sky-300 border-sky-500/40';
      case 'INFO':
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getSeverityIcon = (severity: SecuritySeverity) => {
    switch (severity) {
      case 'CRITICAL':
        return <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />;
      case 'HIGH':
      case 'MEDIUM':
        return <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />;
      case 'INFO':
      default:
        return <Info className="w-3.5 h-3.5 text-sky-400" />;
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-sm">
      {/* Table Header & Filters */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
        <div>
          <div className="flex items-center space-x-2">
            <span className="p-1.5 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/30">
              <FileText className="w-4 h-4" />
            </span>
            <h3 className="text-base font-bold text-white tracking-tight">
              Transport Security Findings
            </h3>
            <span className="text-xs font-medium px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
              {filteredFindings.length} evaluated
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic cryptographic findings generated from observed packet metadata.
          </p>
        </div>

        {/* Severity Filter buttons */}
        <div className="flex items-center space-x-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
          <Filter className="w-3.5 h-3.5 text-slate-500 ml-1.5 mr-1" />
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'INFO'].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              className={`px-2.5 py-1 rounded transition text-xs font-medium ${
                filterSeverity === sev
                  ? 'bg-sky-500 text-slate-950 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Findings List */}
      <div className="mt-4 divide-y divide-slate-800/80">
        {filteredFindings.map((finding) => {
          const simPolicy = getPolicyForFinding(finding.rule_id);
          return (
            <div
              key={finding.id}
              onClick={() => onSelectFinding(finding)}
              className="py-5 px-3 sm:px-4 rounded-xl hover:bg-slate-800/40 transition cursor-pointer group"
            >
              <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                {/* Left column: Hierarchy & Explanation */}
                <div className="flex-1 space-y-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded text-xs font-bold uppercase border ${getSeverityBadge(
                        finding.severity
                      )}`}
                    >
                      {getSeverityIcon(finding.severity)}
                      <span>{finding.severity}</span>
                    </span>

                    <span className="text-xs font-mono font-medium text-sky-300 bg-sky-950/60 px-2 py-0.5 rounded border border-sky-800/50">
                      {finding.rule_id}
                    </span>

                    <span className="text-xs text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                      Session: <strong className="text-slate-200 font-mono">{finding.location}</strong>
                    </span>
                  </div>

                  <div className="text-base font-bold text-white group-hover:text-sky-300 transition">
                    {finding.title}
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed font-sans">
                    {finding.plain_explanation}
                  </p>

                  {/* Impact preview */}
                  <div className="text-xs text-slate-400 flex items-start space-x-1.5 pt-0.5">
                    <span className="text-sky-400 font-semibold shrink-0">Impact:</span>
                    <span>{finding.why_it_matters}</span>
                  </div>

                  {/* Standards references */}
                  {finding.references && finding.references.length > 0 && (
                    <div className="flex items-center space-x-2 text-xs text-slate-400 pt-1">
                      <BookOpen className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                      <span className="text-slate-500">Standards:</span>
                      <div className="flex flex-wrap gap-1">
                        {finding.references.map((ref, idx) => (
                          <span key={idx} className="bg-slate-950 px-1.5 py-0.5 rounded text-sky-300 border border-slate-800 font-mono text-[11px]">
                            {ref}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Action bridges */}
                  <div className="pt-2 flex items-center gap-2 flex-wrap">
                    {onNavigateToReplay && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onNavigateToReplay(finding.rule_id);
                        }}
                        className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-xs font-medium transition"
                      >
                        <Play className="w-3.5 h-3.5" />
                        <span>View in Security Replay</span>
                      </button>
                    )}

                    {simPolicy && onNavigateToSimulator && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onNavigateToSimulator(simPolicy.id);
                        }}
                        className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 text-sky-300 border border-sky-500/30 text-xs font-medium transition"
                      >
                        <Sliders className="w-3.5 h-3.5" />
                        <span>{simPolicy.label}</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* Right column: Evidence & Remediation */}
                <div className="lg:w-80 shrink-0 space-y-2.5 text-xs bg-slate-950/70 p-4 rounded-xl border border-slate-800">
                  <div>
                    <span className="text-slate-500 block text-[11px] font-semibold uppercase tracking-wider">
                      Supporting Evidence:
                    </span>
                    {finding.evidence_items && finding.evidence_items.length > 0 ? (
                      <div className="space-y-1.5 mt-1.5">
                        {finding.evidence_items.map((ev, idx) => (
                          <div key={idx} className="flex items-start space-x-1.5 text-slate-300 text-xs">
                            {ev.type === 'OBSERVED' ? (
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                            ) : ev.type === 'COVERAGE_GAP' ? (
                              <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                            ) : (
                              <Info className="w-3.5 h-3.5 text-sky-400 shrink-0 mt-0.5" />
                            )}
                            <span className="line-clamp-2">{ev.description}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="text-slate-300 block mt-1 line-clamp-2">
                        {finding.evidence}
                      </span>
                    )}
                  </div>

                  <div className="pt-2.5 border-t border-slate-800">
                    <span className="text-slate-500 block text-[11px] font-semibold uppercase tracking-wider">
                      Remediation:
                    </span>
                    <RemediationCard remediation={finding.remediation} fallback={finding.recommendation}/>
                  </div>

                  <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs text-sky-400 group-hover:text-sky-300">
                    <span>Inspect session parameters</span>
                    <ChevronRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition" />
                  </div>
                </div>
              </div>
            </div>
          );
        })}

        {filteredFindings.length === 0 && (
          <div className="py-12 text-center text-slate-500 text-xs">
            No security findings match the selected severity filter.
          </div>
        )}
      </div>
    </div>
  );
};
