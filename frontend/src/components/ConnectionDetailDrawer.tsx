import {RemediationCard} from './RemediationCard';
import React, {useEffect, useRef} from 'react';
import { 
  X, 
  Terminal, 
  Lock, 
  Unlock, 
  CheckCircle2, 
  AlertTriangle, 
  BookOpen, 
  Info 
} from 'lucide-react';
import { NetworkConnection, NetworkNode, SecurityFinding } from '../types';

interface ConnectionDetailDrawerProps {
  connection: NetworkConnection | null;
  nodes: NetworkNode[];
  onClose: () => void;
  onSelectHop?: (connectionId: string) => void;
  allConnections?: NetworkConnection[];
  findings?: SecurityFinding[];
  isSimulated?: boolean;
  onNavigateToSimulator?: (policyId: string) => void;
}

export const ConnectionDetailDrawer: React.FC<ConnectionDetailDrawerProps> = ({
  connection,
  nodes,
  onClose,
  onSelectHop,
  allConnections,
  findings = [],
  isSimulated = true,
  onNavigateToSimulator,
}) => {
  const drawer = useRef<HTMLDivElement>(null);
  useEffect(()=>{
    if(!connection)return;
    const before=document.activeElement as HTMLElement|null;
    drawer.current?.focus();
    const key=(e:KeyboardEvent)=>{
      if(e.key==='Escape')onClose();
      if(e.key==='Tab'){
        const items=drawer.current?.querySelectorAll<HTMLElement>('button, a[href], input, select, [tabindex="0"]');
        if(!items?.length)return;
        const first=items[0],last=items[items.length-1];
        if(e.shiftKey&&(document.activeElement===first||document.activeElement===drawer.current)){e.preventDefault();last.focus()}
        else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus()}
      }
    };
    document.addEventListener('keydown',key);
    return ()=>{document.removeEventListener('keydown',key);before?.focus()};
  },[connection?.id]);
  if (!connection) return null;

  const isCritical = connection.security_status === 'CRITICAL';
  const isWarning = connection.security_status === 'WARNING';
  const sourceNode = nodes.find((n) => n.id === connection.source_node_id);
  const targetNode = nodes.find((n) => n.id === connection.target_node_id);

  const connFindings = findings.filter(
    (f) => f.affected_connection_id === connection.id || (f.affected_connection_id === null && connection.id.includes('real'))
  );

  return (
    <div ref={drawer} role="dialog" aria-modal="true" aria-label="Connection analysis" tabIndex={-1} className="fixed inset-y-0 right-0 w-full sm:max-w-xl bg-slate-900 border-l border-slate-800 shadow-2xl z-50 overflow-y-auto flex flex-col">
      {/* Header */}
      <div className="p-6 border-b border-slate-800 bg-slate-950 sticky top-0 z-20">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="text-xs uppercase px-2 py-0.5 rounded bg-slate-800 text-sky-400 border border-slate-700 font-semibold">
              Connection Analysis
            </span>
            <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
              isSimulated
                ? 'bg-amber-500/10 text-amber-300 border border-amber-500/30'
                : 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30'
            }`}>
              {isSimulated ? 'SIMULATED DATA' : 'PCAP EVIDENCE'}
            </span>
          </div>
          <button
            onClick={onClose}
            aria-label="Close connection details"
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="mt-3 flex items-center justify-between">
          <h3 className="text-lg font-bold text-white tracking-tight flex items-center space-x-2">
            <span>{connection.source_label}</span>
            <span className="text-slate-500">→</span>
            <span>{connection.target_label}</span>
          </h3>

          <span
            className={`text-xs uppercase px-2.5 py-1 rounded-md font-bold tracking-wider ${
              isCritical
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/50'
                : isWarning
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50'
                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50'
            }`}
          >
            {connection.security_status}
          </span>
        </div>

        {/* Hop Switcher */}
        {allConnections && onSelectHop && (
          <div className="mt-4 flex items-center space-x-2">
            <span className="text-xs text-slate-400">Sessions:</span>
            <div className="flex space-x-1.5 overflow-x-auto py-1">
              {allConnections.map((c, idx) => (
                <button
                  key={c.id}
                  onClick={() => onSelectHop(c.id)}
                  className={`px-2.5 py-1 rounded text-xs whitespace-nowrap transition ${
                    c.id === connection.id
                      ? 'bg-sky-500 text-slate-950 font-bold'
                      : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Session {idx + 1}: {c.source_label.split(' ')[0]} → {c.target_label.split(' ')[0]}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Body Content */}
      <div className="p-6 space-y-6 flex-1">
        {!isSimulated&&<section className="rounded-lg border border-slate-700 p-4 space-y-3"><h4 className="text-sm font-semibold text-emerald-200">Certificate & handshake evidence</h4><p className="text-xs text-slate-400">ServerHello frame: {connection.server_hello_frame||'Not captured'} · TCP gaps: {connection.capture_gaps?'Detected':'None detected'}</p><p className="text-xs text-slate-400">STARTTLS: {connection.starttls_used?'Accepted, followed by ServerHello':connection.starttls_requested?'Requested; upgrade not verified':'No request observed'}</p>{connection.certificates?.length?connection.certificates.map(cert=><div key={cert.sha256} className="border-t border-slate-700 pt-3 space-y-2 text-xs"><strong className="text-slate-200 break-all">{cert.subject}</strong><p className="text-slate-400 break-all">Issuer: {cert.issuer}</p><p className="text-slate-300">{cert.public_key_algorithm} {cert.public_key_bits||''} · {cert.signature_hash} · Frame {cert.frame}</p><p className="text-slate-400">Valid {cert.not_before.slice(0,10)} to {cert.not_after.slice(0,10)}</p>{cert.issues.map(issue=><p className="text-rose-300" key={issue}>{issue}</p>)}<p className="text-amber-200 leading-relaxed">{cert.chain_detail}</p><p className="font-mono text-[10px] text-slate-500 break-all">SHA-256 {cert.sha256}</p></div>):<p className="text-xs text-amber-200 leading-relaxed">Certificate not visible. TLS 1.3 encrypts certificates; truncated or resumed handshakes can also omit them. Trust cannot be established from TLS version alone.</p>}</section>}
        {connection.quantum_readiness&&<section className="rounded-lg border border-slate-700 p-4 text-xs text-slate-300 space-y-2">
          <h4 className="font-semibold text-sky-200">INFO · Quantum-readiness observation</h4>
          <p>[{connection.quantum_readiness.type}] {connection.quantum_readiness.label}</p>
          <p>{connection.quantum_readiness.group_name||connection.quantum_readiness.group||'Group not visible'} · ServerHello frame {connection.quantum_readiness.frame||'UNKNOWN'}</p>
          <p className="text-slate-400 leading-relaxed">{connection.quantum_readiness.detail}</p>
        </section>}
        {/* Technical Transport Matrix */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 shadow-sm">
          <h4 className="text-xs uppercase tracking-wider text-slate-400 mb-3 flex items-center justify-between font-semibold">
            <span>Transport Cryptography Metadata</span>
            <span className="text-[10px] text-sky-400 font-normal">Extracted Handshake Parameters</span>
          </h4>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Protocol:</span>
              <span className="text-slate-200 font-bold font-mono">{connection.protocol}</span>
            </div>

            <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Transport Mode:</span>
              <span className="text-slate-200 font-semibold">{connection.transport_mode}</span>
            </div>

            <div className={`p-2.5 rounded-lg border ${
              isCritical
                ? 'bg-rose-950/30 border-rose-800 text-rose-200'
                : 'bg-slate-900/80 border-slate-800 text-slate-200'
            }`}>
              <span className="text-slate-500 block text-[10px]">Negotiated TLS:</span>
              <span className={`font-bold flex items-center space-x-1 font-mono ${isCritical ? 'text-rose-400' : 'text-emerald-400'}`}>
                {isCritical ? <Unlock className="w-3.5 h-3.5" /> : <Lock className="w-3.5 h-3.5" />}
                <span>{connection.tls_version}</span>
              </span>
            </div>

            <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Session Identifier:</span>
              <span className="text-sky-300 font-mono font-semibold">{connection.session_id}</span>
            </div>

            <div className="col-span-2 bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Cipher Suite:</span>
              <span className={`font-mono font-semibold break-all ${isCritical ? 'text-rose-400' : 'text-slate-200'}`}>
                {connection.cipher_suite}
              </span>
            </div>

            <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400">STARTTLS Advertised:</span>
              <span className={connection.starttls_advertised ? 'text-emerald-400 font-bold' : 'text-slate-400 font-bold'}>
                {connection.starttls_advertised ? 'YES' : 'NO'}
              </span>
            </div>

            <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400">STARTTLS Used:</span>
              <span className={connection.starttls_used ? 'text-emerald-400 font-bold' : connection.starttls_advertised ? 'text-rose-400 font-bold' : 'text-slate-400 font-bold'}>
                {connection.starttls_used ? 'YES' : connection.starttls_advertised ? 'NO (Available But Unused)' : 'NO'}
              </span>
            </div>

            {connection.auth_observed && (
              <div className="col-span-2 bg-slate-900/80 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between">
                <span className="text-slate-400">Authentication Timing:</span>
                <span className={connection.auth_before_tls ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                  {connection.auth_before_tls ? 'BEFORE TLS (Plaintext Credential Exposure)' : 'PROTECTED INSIDE TLS'}
                </span>
              </div>
            )}

            <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400">Forward Secrecy (PFS):</span>
              <span className={connection.has_pfs ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                {connection.has_pfs ? 'ENABLED (ECDHE/DHE)' : 'DISABLED (Static RSA / None)'}
              </span>
            </div>

            <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400">AEAD Authenticated:</span>
              <span className={connection.has_aead ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                {connection.has_aead ? 'YES' : 'NO (CBC / None)'}
              </span>
            </div>
          </div>

          {/* Endpoint Details */}
          <div className="mt-3 pt-3 border-t border-slate-800/80 grid grid-cols-2 gap-2 text-xs text-slate-400">
            <div>
              <span className="text-slate-500">Source: </span>
              <span className="text-slate-300 font-mono">{sourceNode?.ip_address}</span>
            </div>
            <div>
              <span className="text-slate-500">Target: </span>
              <span className="text-slate-300 font-mono">{targetNode?.ip_address}</span>
            </div>
          </div>
        </div>

        {/* DETERMINISTIC FINDINGS */}
        {connFindings.length > 0 && (
          <div className="space-y-3">
            <h4 className="text-xs uppercase tracking-wider text-slate-400 flex items-center justify-between font-semibold">
              <span>Security Assessment Rules</span>
              <span className="text-xs text-sky-400 font-normal">{connFindings.length} Evaluated Rules</span>
            </h4>

            {connFindings.map((finding) => (
              <div
                key={finding.id}
                className={`border rounded-xl p-4 shadow-sm space-y-3 ${
                  finding.severity === 'CRITICAL'
                    ? 'bg-rose-950/20 border-rose-900/60'
                    : finding.severity === 'HIGH'
                    ? 'bg-orange-950/20 border-orange-900/60'
                    : finding.severity === 'MEDIUM'
                    ? 'bg-amber-950/20 border-amber-900/60'
                    : 'bg-slate-950 border-slate-800'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center space-x-2">
                    <span
                      className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${
                        finding.severity === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/50'
                          : finding.severity === 'HIGH'
                          ? 'bg-orange-500/20 text-orange-300 border-orange-500/50'
                          : finding.severity === 'MEDIUM'
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/50'
                          : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50'
                      }`}
                    >
                      {finding.severity}
                    </span>
                    <span className="text-xs font-mono text-slate-400">{finding.rule_id}</span>
                  </div>

                  {finding.status && (
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                      finding.status === 'PASS'
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        : finding.status === 'WARN'
                        ? 'bg-amber-950 text-amber-300 border border-amber-800'
                        : finding.status === 'UNKNOWN'
                        ? 'bg-slate-800 text-slate-300 border border-slate-700'
                        : 'bg-rose-950 text-rose-300 border border-rose-800'
                    }`}>
                      {finding.status}
                    </span>
                  )}
                </div>

                <div className="text-sm font-semibold text-white">
                  {finding.title}
                </div>

                <p className="text-xs text-slate-300 leading-relaxed font-sans">
                  {finding.plain_explanation}
                </p>

                {/* Evidence Section */}
                <div className="bg-black/50 p-2.5 rounded-lg border border-slate-800/80 space-y-1.5 text-xs font-mono">
                  <span className="text-slate-400 text-[10px] uppercase block font-sans">Observed Evidence:</span>
                  {finding.evidence_items && finding.evidence_items.length > 0 ? (
                    finding.evidence_items.map((ev, eIdx) => (
                      <div key={eIdx} className="flex items-start space-x-1.5 text-slate-300">
                        {ev.type === 'OBSERVED' ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                        ) : ev.type === 'COVERAGE_GAP' ? (
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                        ) : (
                          <Info className="w-3.5 h-3.5 text-sky-400 shrink-0 mt-0.5" />
                        )}
                        <span className="font-sans">{ev.description}</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-slate-300 font-sans">{finding.evidence}</div>
                  )}
                </div>

                {/* Standards & References */}
                {finding.references && finding.references.length > 0 && (
                  <div className="flex items-center space-x-2 text-xs text-slate-400 pt-1">
                    <BookOpen className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                    <span className="text-slate-500">Standards:</span>
                    <div className="flex flex-wrap gap-1">
                      {finding.references.map((ref, rIdx) => (
                        <span key={rIdx} className="bg-slate-900 px-1.5 py-0.5 rounded text-sky-300 border border-slate-800 font-mono text-[11px]">
                          {ref}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Remediation */}
                <div className="bg-emerald-950/20 p-2.5 rounded-lg border border-emerald-900/40 text-xs text-slate-200 space-y-2">
                  <div>
                    <span className="text-emerald-400 text-[10px] uppercase block mb-0.5 font-semibold">Remediation:</span>
                    <RemediationCard remediation={finding.remediation} fallback={finding.recommendation}/>
                  </div>

                  {onNavigateToSimulator && (
                    <div className="pt-1 border-t border-emerald-900/30">
                      <button
                        onClick={() => {
                          let polId = 'SMS-POLICY-TLS12';
                          if (finding.rule_id === 'SMS-CIPHER-001') polId = 'SMS-POLICY-NO-WEAK-CIPHER';
                          else if (finding.rule_id === 'SMS-PFS-001') polId = 'SMS-POLICY-PFS';
                          else if (['SMS-TLS-001', 'SMS-STARTTLS-001', 'SMS-AUTH-001'].includes(finding.rule_id)) polId = 'SMS-POLICY-REQUIRE-TLS';
                          onClose();
                          onNavigateToSimulator(polId);
                        }}
                        className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded bg-sky-500/10 hover:bg-sky-500/20 text-sky-300 border border-sky-500/30 text-xs transition font-medium"
                      >
                        <span>[ Evaluate Policy in Simulator ]</span>
                      </button>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* EVIDENCE TERMINAL */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-slate-400" />
              <h4 className="text-xs uppercase tracking-wider text-slate-300 font-bold">
                Packet & Session Evidence
              </h4>
            </div>
            <span className={`text-[10px] px-2 py-0.5 rounded border ${
              isSimulated
                ? 'bg-slate-900 text-amber-300 border-slate-800'
                : 'bg-emerald-950 text-emerald-300 border-emerald-800'
            }`}>
              {isSimulated ? 'Simulated Evidence' : 'Extracted Packet Metadata'}
            </span>
          </div>

          <div className="text-xs text-slate-300 mb-2 font-sans">
            {connection.explanation.evidence_summary}
          </div>

          <div className="bg-black/90 rounded-lg p-3 border border-slate-800 font-mono text-[11px] text-emerald-400 space-y-1 overflow-x-auto">
            <div className="text-slate-500"># Session Log ({connection.evidence.session_id})</div>
            <div><span className="text-slate-400">Stream:</span> {connection.evidence.ports} | {connection.evidence.packet_count} packets</div>
            <div><span className="text-slate-400">Handshake:</span> {connection.evidence.handshake_record}</div>
            {connection.evidence.cipher_suite_hex && (
              <div><span className="text-slate-400">Cipher Hex:</span> {connection.evidence.cipher_suite_hex}</div>
            )}
            {connection.evidence.protocol_version_hex && (
              <div><span className="text-slate-400">Version Hex:</span> {connection.evidence.protocol_version_hex}</div>
            )}
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="p-4 border-t border-slate-800 bg-slate-950 flex items-center justify-between text-xs text-slate-400">
        <span className="text-[11px]">SecureMailScope Rule Engine • SIH26159</span>
        <button
          onClick={onClose}
          className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium transition"
        >
          Close
        </button>
      </div>
    </div>
  );
};
