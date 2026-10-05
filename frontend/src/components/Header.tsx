import React from 'react';
import { RefreshCw, CheckCircle2, Sparkles, FileText, UploadCloud } from 'lucide-react';
import { ActiveTab, HealthResponse, Investigation } from '../types';

interface HeaderProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  health: HealthResponse | null;
  healthLoading: boolean;
  onRefresh: () => void;
  investigation: Investigation | null;
  onLoadDemo: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onTabChange,
  health,
  healthLoading,
  onRefresh,
  investigation,
  onLoadDemo,
}) => {
  const isReal = investigation && (!investigation.is_simulated || investigation.data_source === 'REAL_CAPTURE');

  return (
    <header className="bg-slate-900/90 backdrop-blur border-b border-slate-800 sticky top-0 z-30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand & Subtitle */}
          <div className="flex items-center space-x-3 shrink-0">
            <div className="w-9 h-9 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
              <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" strokeLinecap="round" strokeLinejoin="round" />
                <path d="m9 12 2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-lg font-bold tracking-tight text-white">SecureMailScope</span>
                <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  v1.0
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                Cryptographic Security Posture Assessment
              </p>
            </div>
          </div>

          {/* Primary Navigation */}
          <nav className="flex items-center space-x-1 bg-slate-950/70 p-1 rounded-lg border border-slate-800/80">
            <button
              onClick={() => onTabChange('overview')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                activeTab === 'overview'
                  ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              Overview
            </button>

            <button
              onClick={() => onTabChange('findings')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                activeTab === 'findings'
                  ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              Findings
            </button>

            <button
              onClick={() => onTabChange('replay')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === 'replay'
                  ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <span>Security Replay</span>
              {investigation?.replays && investigation.replays.length > 0 && (
                <span className="w-1.5 h-1.5 rounded-full bg-indigo-400"></span>
              )}
            </button>

            <button
              onClick={() => onTabChange('simulator')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                activeTab === 'simulator'
                  ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              Simulator
            </button>

            <button
              onClick={() => onTabChange('discovery')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === 'discovery'
                  ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <span>Client Discovery</span>
              {investigation?.discovery?.summary && investigation.discovery.summary.needs_review_count > 0 && (
                <span className="px-1.5 py-0.2 rounded-full text-[9px] bg-purple-500/30 text-purple-300 font-mono font-bold">
                  {investigation.discovery.summary.needs_review_count}
                </span>
              )}
            </button>

            <button
              onClick={() => onTabChange('report')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === 'report'
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Report</span>
            </button>

            <button
              onClick={() => onTabChange('upload')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors flex items-center gap-1.5 ${
                activeTab === 'upload'
                  ? 'bg-sky-500 text-slate-950 shadow-sm'
                  : 'bg-sky-500/15 text-sky-300 hover:bg-sky-500/25 border border-sky-500/30'
              }`}
            >
              <UploadCloud className="w-3.5 h-3.5" />
              <span>Upload Capture</span>
            </button>
          </nav>

          {/* Secondary Status & Demo Toggle */}
          <div className="flex items-center space-x-2.5">
            {/* Provenance Pill */}
            {isReal ? (
              <span className="hidden sm:inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-[11px] bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-medium">
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                <span>REAL CAPTURE</span>
              </span>
            ) : (
              <span className="hidden sm:inline-flex items-center px-2 py-0.5 rounded-md text-[11px] bg-amber-500/10 text-amber-300 border border-amber-500/30 font-medium">
                SIMULATED DEMO
              </span>
            )}

            {/* Switch back to demo CTA if in real mode */}
            {isReal && (
              <button
                onClick={onLoadDemo}
                className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-md text-[11px] bg-slate-800 hover:bg-slate-700 text-sky-300 border border-slate-700 transition"
                title="Switch back to simulated demonstration"
              >
                <Sparkles className="w-3 h-3 text-sky-400" />
                <span>Demo Mode</span>
              </button>
            )}

            {/* Subtle Engine Health */}
            <div className="hidden lg:flex items-center space-x-1.5 text-[11px] text-slate-500">
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  health?.status === 'ok' ? 'bg-emerald-400' : 'bg-rose-400'
                }`}
              />
              <span>{health?.tshark_available ? 'Engine Ready' : 'Standby'}</span>
            </div>

            <button
              onClick={onRefresh}
              title="Refresh Investigation Data"
              className="p-1.5 rounded-md bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-slate-200 border border-slate-700/80 transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${healthLoading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
