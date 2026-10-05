import React from 'react';
import { 
  Lock, 
  Unlock, 
  AlertOctagon, 
  ArrowRight, 
  ArrowDown, 
  Server, 
  Globe, 
  ChevronRight,
  Layers
} from 'lucide-react';
import { NetworkNode, NetworkConnection } from '../types';

interface MailSecurityJourneyProps {
  nodes: NetworkNode[];
  connections: NetworkConnection[];
  selectedConnectionId: string | null;
  onSelectConnection: (connection: NetworkConnection) => void;
}

export const MailSecurityJourney: React.FC<MailSecurityJourneyProps> = ({
  nodes,
  connections,
  selectedConnectionId,
  onSelectConnection,
}) => {
  const getNode = (nodeId: string) => nodes.find((n) => n.id === nodeId);

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 sm:p-7 shadow-sm mb-8 relative overflow-hidden">
      {/* Background subtle styling */}
      <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:16px_16px] opacity-20 pointer-events-none" />

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-5 border-b border-slate-800 gap-3 relative z-10">
        <div>
          <div className="flex items-center space-x-2">
            <span className="p-1.5 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/30">
              <Layers className="w-4 h-4" />
            </span>
            <h2 className="text-base font-bold text-white tracking-tight">
              Mail Security Journey
            </h2>
            <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-sky-300 border border-slate-700">
              End-to-End Hop Analysis
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Reconstructed delivery path mapping cryptographic posture across each hop. Click any connection hop to inspect packet evidence.
          </p>
        </div>

        <div className="flex items-center space-x-3 text-xs">
          <span className="flex items-center space-x-1.5 text-slate-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span>Secure Hop</span>
          </span>
          <span className="flex items-center space-x-1.5 text-slate-400">
            <span className="w-2 h-2 rounded-full bg-rose-500"></span>
            <span className="text-rose-400 font-semibold">Critical Downgrade</span>
          </span>
        </div>
      </div>

      {/* Main Journey Layout */}
      <div className="mt-6 relative z-10">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 lg:gap-2">
          {connections.map((conn, index) => {
            const sourceNode = getNode(conn.source_node_id);
            const targetNode = getNode(conn.target_node_id);
            const isSelected = selectedConnectionId === conn.id;
            const isCritical = conn.security_status === 'CRITICAL';
            const isWarning = conn.security_status === 'WARNING';

            return (
              <React.Fragment key={conn.id}>
                {/* SOURCE NODE (Rendered for the first connection) */}
                {index === 0 && sourceNode && (
                  <div className="flex-1 max-w-xs">
                    <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 shadow-sm hover:border-slate-700 transition">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <div className="p-1.5 rounded-md bg-slate-800 text-sky-400 border border-slate-700">
                            {sourceNode.is_external ? <Globe className="w-4 h-4" /> : <Server className="w-4 h-4" />}
                          </div>
                          <span className="text-xs font-semibold text-slate-400">
                            Hop 01 • Origin
                          </span>
                        </div>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-sky-950/80 text-sky-300 border border-sky-800/60 font-medium">
                          External
                        </span>
                      </div>

                      <div className="font-semibold text-slate-100 text-sm tracking-tight">
                        {sourceNode.label}
                      </div>
                      <div className="text-xs text-slate-400 font-mono truncate mt-0.5">
                        {sourceNode.hostname}
                      </div>
                      <div className="text-[11px] text-slate-500 font-mono mt-1">
                        IP: {sourceNode.ip_address}
                      </div>
                    </div>
                  </div>
                )}

                {/* INTERACTIVE CONNECTION LINK */}
                <div className="flex-1 flex flex-col items-center">
                  <div
                    onClick={() => onSelectConnection(conn)}
                    className={`w-full cursor-pointer transition-all rounded-xl p-4 border relative ${
                      isSelected
                        ? isCritical
                          ? 'bg-rose-950/40 border-rose-500 ring-1 ring-rose-500/50 shadow-sm'
                          : 'bg-sky-950/40 border-sky-500 ring-1 ring-sky-500/50 shadow-sm'
                        : isCritical
                        ? 'bg-rose-950/20 border-rose-800/80 hover:bg-rose-900/30 hover:border-rose-600'
                        : isWarning
                        ? 'bg-amber-950/20 border-amber-800/80 hover:bg-amber-900/30 hover:border-amber-600'
                        : 'bg-slate-950/90 border-slate-800 hover:border-slate-700 hover:bg-slate-900/80'
                    }`}
                  >
                    {/* Header badge inside connection */}
                    <div className="flex items-center justify-between text-xs mb-2">
                      <div className="flex items-center space-x-1.5">
                        {isCritical ? (
                          <Unlock className="w-4 h-4 text-rose-400" />
                        ) : (
                          <Lock className="w-4 h-4 text-emerald-400" />
                        )}
                        <span className="font-semibold text-slate-200">
                          {conn.protocol}
                        </span>
                        <span className="text-xs text-slate-400">
                          ({conn.transport_mode})
                        </span>
                      </div>

                      <span
                        className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                          isCritical
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                            : isWarning
                            ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                            : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        }`}
                      >
                        {conn.security_status}
                      </span>
                    </div>

                    {/* TLS Version Pill */}
                    <div className="my-2 text-center">
                      <div
                        className={`inline-flex items-center space-x-1.5 px-3 py-1 rounded-lg text-xs font-semibold ${
                          isCritical
                            ? 'bg-rose-950/80 text-rose-200 border border-rose-600'
                            : isWarning
                            ? 'bg-amber-950/80 text-amber-200 border border-amber-600'
                            : 'bg-emerald-950/80 text-emerald-200 border border-emerald-600'
                        }`}
                      >
                        {isCritical && <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />}
                        <span className="font-mono">{conn.tls_version}</span>
                        {isCritical && <span className="text-[9px] uppercase px-1 rounded bg-rose-900 text-rose-100 font-bold">DEPRECATED</span>}
                      </div>
                    </div>

                    {/* Cipher summary */}
                    <div className="text-[11px] font-mono text-slate-400 text-center truncate px-1">
                      {conn.cipher_suite}
                    </div>

                    {/* Plain Language Headline */}
                    <div className="mt-2.5 pt-2.5 border-t border-slate-800 text-center">
                      <p className={`text-xs leading-tight line-clamp-2 ${
                        isCritical ? 'text-rose-300 font-medium' : 'text-slate-300'
                      }`}>
                        {conn.explanation.headline}
                      </p>
                    </div>

                    {/* Action prompt footer */}
                    <div className="mt-2 flex items-center justify-center space-x-1 text-xs text-sky-400 group-hover:text-sky-300">
                      <span>Click to inspect details</span>
                      <ChevronRight className="w-3.5 h-3.5" />
                    </div>

                    {/* Directional arrow */}
                    <div className="hidden lg:block absolute -right-3 top-1/2 -translate-y-1/2 translate-x-1/2 z-20 pointer-events-none">
                      <div className={`p-1 rounded-full bg-slate-900 border ${
                        isCritical ? 'border-rose-500 text-rose-400' : 'border-slate-700 text-slate-400'
                      }`}>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </div>
                    </div>
                  </div>

                  {/* Vertical Arrow for Mobile */}
                  <div className="lg:hidden my-2 text-slate-500">
                    <ArrowDown className="w-4 h-4 mx-auto" />
                  </div>
                </div>

                {/* TARGET NODE */}
                {targetNode && (
                  <div className="flex-1 max-w-xs">
                    <div className={`bg-slate-950 border rounded-xl p-4 shadow-sm hover:border-slate-700 transition ${
                      targetNode.security_posture === 'critical'
                        ? 'border-rose-900/60 bg-rose-950/10'
                        : 'border-slate-800'
                    }`}>
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <div className={`p-1.5 rounded-md border ${
                            targetNode.security_posture === 'critical'
                              ? 'bg-rose-950/40 text-rose-400 border-rose-800'
                              : 'bg-slate-800 text-sky-400 border-slate-700'
                          }`}>
                            <Server className="w-4 h-4" />
                          </div>
                          <span className="text-xs font-semibold text-slate-400">
                            Hop 0{index + 2} • {index === connections.length - 1 ? 'Destination' : 'Relay'}
                          </span>
                        </div>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                          targetNode.security_posture === 'critical'
                            ? 'bg-rose-950/80 text-rose-300 border-rose-800/60 font-medium'
                            : 'bg-slate-900 text-slate-300 border-slate-800 font-medium'
                        }`}>
                          Internal
                        </span>
                      </div>

                      <div className="font-semibold text-slate-100 text-sm tracking-tight flex items-center justify-between">
                        <span>{targetNode.label}</span>
                        {targetNode.security_posture === 'critical' && (
                          <span className="text-[10px] text-rose-400 font-bold bg-rose-950 px-1.5 py-0.5 rounded border border-rose-800">
                            VULNERABLE
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-slate-400 font-mono truncate mt-0.5">
                        {targetNode.hostname}
                      </div>
                      <div className="text-[11px] text-slate-500 font-mono mt-1">
                        IP: {targetNode.ip_address}
                      </div>
                    </div>
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>
    </div>
  );
};
