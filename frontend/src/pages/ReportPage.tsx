import React from 'react';
import { Investigation } from '../types';
import { HonestyBanner } from '../components/HonestyBanner';
import { EvidenceReport } from '../components/EvidenceReport';
import { FileText, Upload } from 'lucide-react';

interface ReportPageProps {
  investigation: Investigation | null;
  onNavigateToSimulator?: (policyId: string) => void;
  onNavigateToReplay?: (ruleIdOrEventId: string, sessionId?: string) => void;
  onNavigateToFindings?: () => void;
  onNavigateToDiscovery?: () => void;
  onNavigateToUpload?: () => void;
}

export const ReportPage: React.FC<ReportPageProps> = ({
  investigation,
  onNavigateToSimulator,
  onNavigateToReplay,
  onNavigateToFindings,
  onNavigateToDiscovery,
  onNavigateToUpload,
}) => {
  if (!investigation) {
    return (
      <div className="py-20 max-w-xl mx-auto text-center space-y-4">
        <div className="w-14 h-14 rounded-2xl bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400 mx-auto">
          <FileText className="w-7 h-7" />
        </div>
        <div className="space-y-1">
          <h2 className="text-lg font-bold text-white font-mono">No Investigation Loaded</h2>
          <p className="text-xs text-slate-400 leading-relaxed font-mono">
            Upload an authorized PCAP capture or load the simulated demonstration fleet to generate a comprehensive cryptographic security report.
          </p>
        </div>
        {onNavigateToUpload && (
          <button
            onClick={onNavigateToUpload}
            className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 text-xs font-bold font-mono transition"
          >
            <Upload className="w-4 h-4" />
            <span>Upload Network Capture</span>
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <HonestyBanner investigation={investigation} />

      <EvidenceReport
        investigation={investigation}
        onNavigateToSimulator={onNavigateToSimulator}
        onNavigateToReplay={onNavigateToReplay}
        onNavigateToFindings={onNavigateToFindings}
        onNavigateToDiscovery={onNavigateToDiscovery}
      />
    </div>
  );
};
