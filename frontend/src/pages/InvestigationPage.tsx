import React from 'react';
import { Investigation, NetworkConnection } from '../types';
import { MailSecurityJourney } from '../components/MailSecurityJourney';
import { HonestyBanner } from '../components/HonestyBanner';
import { Server } from 'lucide-react';

interface InvestigationPageProps {
  investigation: Investigation;
  selectedConnection: NetworkConnection | null;
  onSelectConnection: (connection: NetworkConnection) => void;
}

export const InvestigationPage: React.FC<InvestigationPageProps> = ({
  investigation,
  selectedConnection,
  onSelectConnection,
}) => {
  return (
    <div className="space-y-6">
      <HonestyBanner investigation={investigation} />

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight font-mono uppercase">
            Interactive Security Investigation
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Hop-by-hop transport security analysis and protocol posture inspection.
          </p>
        </div>
        <div className="text-xs font-mono text-slate-400 bg-slate-900 px-3 py-1 rounded-lg border border-slate-800">
          Capture: <span className="text-sky-300 font-semibold">{investigation.filename}</span>
        </div>
      </div>

      {/* Hero Security Journey */}
      <MailSecurityJourney
        nodes={investigation.nodes}
        connections={investigation.connections}
        selectedConnectionId={selectedConnection?.id || null}
        onSelectConnection={onSelectConnection}
      />

      {/* Node Directory Grid */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-sm">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800 mb-4">
          <div className="flex items-center space-x-2">
            <Server className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-bold text-white uppercase font-mono tracking-wider">
              Discovered Topology Nodes ({investigation.nodes.length})
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Internal & Perimeter Mail Infrastructure
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {investigation.nodes.map((node) => (
            <div
              key={node.id}
              className={`p-4 rounded-xl border bg-slate-950/80 ${
                node.security_posture === 'critical'
                  ? 'border-rose-800/80 bg-rose-950/10'
                  : node.security_posture === 'warning'
                  ? 'border-amber-800/80 bg-amber-950/10'
                  : 'border-slate-800'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-slate-200">{node.label}</span>
                <span
                  className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold ${
                    node.security_posture === 'critical'
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                      : node.security_posture === 'warning'
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                      : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  }`}
                >
                  {node.security_posture}
                </span>
              </div>
              <div className="text-xs text-slate-400 font-mono truncate">{node.hostname}</div>
              <div className="text-[11px] text-slate-500 font-mono mt-1">IP: {node.ip_address}</div>
              <div className="text-[11px] text-slate-400 mt-2 line-clamp-2 border-t border-slate-800/60 pt-2">
                {node.role}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
