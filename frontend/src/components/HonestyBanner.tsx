import React from 'react';
import { Info, Shield, HardDrive, CheckCircle2 } from 'lucide-react';
import { Investigation } from '../types';

interface HonestyBannerProps {
  investigation?: Investigation | null;
}

export const HonestyBanner: React.FC<HonestyBannerProps> = ({ investigation }) => {
  const isReal = investigation && (!investigation.is_simulated || investigation.data_source === 'REAL_CAPTURE');

  if (isReal) {
    return (
      <div className="bg-slate-900/70 border border-emerald-500/30 rounded-xl p-4 mb-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-3">
            <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/40">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span>{investigation?.capture_origin==='SYNTHETIC_LAB'?'LAB PCAP':'PCAP EVIDENCE'}</span>
            </span>
            <div className="space-y-0.5">
              <div className="text-xs font-semibold text-slate-100 font-mono">
                {investigation?.filename}
              </div>
              <p className="text-xs text-slate-400">
                {investigation?.capture_origin==='SYNTHETIC_LAB'?'Synthetic traffic analyzed through the packet engine.':'Analysis of uploaded capture bytes; origin not independently verified.'}
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-4 text-xs text-slate-400 shrink-0 sm:border-l sm:border-slate-800 sm:pl-4">
            <div className="flex items-center space-x-1.5">
              <HardDrive className="w-3.5 h-3.5 text-sky-400" />
              <span>Offline Dissection</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <Shield className="w-3.5 h-3.5 text-emerald-400" />
              <span>Metadata Results</span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 mb-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-md text-xs font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30">
            <Info className="w-3.5 h-3.5 text-amber-400" />
            <span>SIMULATED DEMO</span>
          </span>
          <div className="space-y-0.5">
            <div className="text-xs font-semibold text-slate-200">
              Demonstration Dataset
            </div>
            <p className="text-xs text-slate-400">
              Generated mail-security scenarios demonstrating multi-hop cryptographic analysis.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-4 text-xs text-slate-400 shrink-0 sm:border-l sm:border-slate-800 sm:pl-4">
          <div className="flex items-center space-x-1.5">
            <HardDrive className="w-3.5 h-3.5 text-sky-400" />
            <span>Offline-First</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
            <span>Metadata-Only Privacy</span>
          </div>
        </div>
      </div>
    </div>
  );
};
