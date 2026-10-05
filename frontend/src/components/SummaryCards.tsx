import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, Activity, FileCode, CheckCircle2 } from 'lucide-react';
import { SummaryStats, SecurityPosture } from '../types';
import { CumulativeAnalytics } from '../services/analytics';

interface SummaryCardsProps {
  summary: SummaryStats;
  securityPosture?: SecurityPosture;
  filename: string;
  captureDate: string;
  sha256Short?: string | null;
  isSimulated?: boolean;
  cumulativeAnalytics: CumulativeAnalytics;
}

export const SummaryCards: React.FC<SummaryCardsProps> = ({
  summary,
  securityPosture,
  filename,
  captureDate,
  sha256Short,
  isSimulated,
  cumulativeAnalytics,
}) => {
  // Use cumulative totals across analyzed captures
  const total = cumulativeAnalytics.totalSessionsAnalyzed;
  const secure = cumulativeAnalytics.secureSessions;
  const warning = cumulativeAnalytics.warningSessions;
  const critical = cumulativeAnalytics.criticalSessions;

  // Compute dynamic percentages with consistent rounding
  const securePercent = total > 0 ? Math.round((secure / total) * 100) : 0;
  const warningPercent = total > 0 ? Math.round((warning / total) * 100) : 0;
  const criticalPercent = total > 0 ? Math.max(0, 100 - securePercent - warningPercent) : 0;

  const currentCaptureSessions = summary.sessions_analyzed > 0 ? summary.sessions_analyzed : 1;

  const getPostureBadge = (status?: string) => {
    switch (status) {
      case 'CRITICAL':
        return 'bg-rose-500/15 text-rose-300 border-rose-500/40';
      case 'HIGH_RISK':
        return 'bg-orange-500/15 text-orange-300 border-orange-500/40';
      case 'NEEDS_ATTENTION':
        return 'bg-amber-500/15 text-amber-300 border-amber-500/40';
      case 'ACCEPTABLE':
        return 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40';
      case 'UNKNOWN':
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="space-y-4 mb-8">
      {/* Capture info metadata strip */}
      <div className="flex flex-wrap items-center justify-between text-xs text-slate-400 bg-slate-900/60 px-4 py-2.5 rounded-xl border border-slate-800 gap-3">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
          <div className="flex items-center space-x-1.5 text-slate-300">
            <FileCode className="w-3.5 h-3.5 text-sky-400" />
            <span className="text-slate-400">Capture:</span>
            <span className="font-medium text-slate-100 bg-slate-800 px-2 py-0.5 rounded border border-slate-700 font-mono text-[11px]">
              {filename}
            </span>
          </div>

          {sha256Short && (
            <div className="flex items-center space-x-1">
              <span className="text-slate-500">SHA-256:</span>
              <span className="text-slate-300 font-mono text-[11px]">{sha256Short}</span>
            </div>
          )}

          <div className="flex items-center space-x-1">
            <span className="text-slate-500">Analysed:</span>
            <span className="text-slate-300 font-mono text-[11px]">{captureDate}</span>
          </div>

          <div className="flex items-center space-x-1">
            <span className="text-slate-500">Current Scope:</span>
            <span className="text-slate-300 font-medium">
              {currentCaptureSessions} {currentCaptureSessions === 1 ? 'session' : 'sessions'}
            </span>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          {securityPosture && (
            <div className="flex items-center space-x-1.5">
              <span className="text-slate-500">Posture:</span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase border font-sans ${getPostureBadge(securityPosture.status)}`}>
                {securityPosture.status.replace('_', ' ')}
              </span>
            </div>
          )}

          <div className="flex items-center space-x-1.5">
            {isSimulated ? (
              <span className="text-amber-400 font-medium text-xs">
                Simulated Dataset
              </span>
            ) : (
              <span className="text-emerald-400 font-medium text-xs flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" />
                <span>Verified Extraction</span>
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Summary Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Sessions Analysed */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm hover:border-slate-700 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">
              Sessions analysed
            </span>
            <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-extrabold text-white tracking-tight font-sans">
              {total}
            </span>
            <span className="text-xs text-slate-400 font-medium">
              Cumulative total
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-400">
            Recorded across unique captures
          </div>
        </div>

        {/* Secure */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm hover:border-emerald-900/50 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-emerald-400">
              Secure
            </span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-extrabold text-emerald-400 tracking-tight font-sans">
              {secure}
            </span>
            <span className="text-xs font-semibold px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/40">
              {securePercent}%
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-400">
            TLS 1.2 / TLS 1.3 with modern AEAD
          </div>
        </div>

        {/* Warnings */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm hover:border-amber-900/50 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-amber-400">
              Warnings
            </span>
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-extrabold text-amber-400 tracking-tight font-sans">
              {warning}
            </span>
            <span className="text-xs font-semibold px-2 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-800/40">
              {warningPercent}%
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-400">
            Opportunistic gaps / Missing strict policy
          </div>
        </div>

        {/* Critical */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm hover:border-rose-900/50 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-rose-400">
              Critical
            </span>
            <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-extrabold text-rose-400 tracking-tight font-sans">
              {critical}
            </span>
            <span className="text-xs font-semibold px-2 py-0.5 rounded bg-rose-950/60 text-rose-300 border border-rose-800/40">
              {criticalPercent}%
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-400">
            Cleartext auth / Deprecated protocols
          </div>
        </div>
      </div>

      {/* Cumulative Transport Security Distribution Bar */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
        <div className="flex justify-between items-center text-xs text-slate-300 mb-2.5">
          <span className="font-semibold text-white">Transport security distribution</span>
          <span className="text-slate-400">{total} sessions analysed</span>
        </div>
        <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden flex">
          <div
            style={{ width: `${securePercent}%` }}
            className="bg-emerald-500 transition-all duration-500"
            title={`Secure: ${secure} (${securePercent}%)`}
          />
          <div
            style={{ width: `${warningPercent}%` }}
            className="bg-amber-500 transition-all duration-500"
            title={`Warnings: ${warning} (${warningPercent}%)`}
          />
          <div
            style={{ width: `${criticalPercent}%` }}
            className="bg-rose-500 transition-all duration-500"
            title={`Critical: ${critical} (${criticalPercent}%)`}
          />
        </div>
        <div className="flex items-center justify-between text-xs text-slate-400 mt-2.5">
          <div className="flex items-center space-x-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
            <span>Secure ({secure})</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2 h-2 rounded-full bg-amber-500"></span>
            <span>Warnings ({warning})</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2 h-2 rounded-full bg-rose-500"></span>
            <span>Critical ({critical})</span>
          </div>
        </div>
      </div>
    </div>
  );
};
