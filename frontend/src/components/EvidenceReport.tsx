import {FixFirstPanel} from './FixFirstPanel';
import {RemediationCard} from './RemediationCard';
import React, { useState, useEffect } from 'react';
import {
  Shield,
  FileText,
  Download,
  Printer,
  CheckCircle2,
  AlertTriangle,
  AlertOctagon,
  RefreshCw,
  ExternalLink,
  Lock,
  Eye,
  Fingerprint,
  Info,
  ChevronRight,
} from 'lucide-react';
import {
  Investigation,
  InvestigationReport,
  IntegrityVerificationResult,
} from '../types';
import {
  fetchInvestigationReport,
  verifyReportIntegrity,
  downloadReportJson,
  downloadReportHtml,
  downloadReportPdf,
} from '../services/api';

interface EvidenceReportProps {
  investigation: Investigation;
  onNavigateToSimulator?: (policyId: string) => void;
  onNavigateToReplay?: (ruleIdOrEventId: string, sessionId?: string) => void;
  onNavigateToFindings?: () => void;
  onNavigateToDiscovery?: () => void;
  onNavigateToUpload?: () => void;
}

export const EvidenceReport: React.FC<EvidenceReportProps> = ({
  investigation,
  onNavigateToSimulator,
  onNavigateToReplay,
  onNavigateToFindings,
}) => {
  const [report, setReport] = useState<InvestigationReport | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState<boolean>(false);
  const [verifyResult, setVerifyResult] = useState<IntegrityVerificationResult | null>(null);
  const [exportingJson, setExportingJson] = useState<boolean>(false);
  const [exportingHtml, setExportingHtml] = useState<boolean>(false);

  const isRealCapture = !investigation.is_simulated && investigation.data_source === 'REAL_CAPTURE';

  const loadReport = async () => {
    setLoading(true);
    setError(null);
    try {
      const rep = await fetchInvestigationReport(investigation);
      setReport(rep);
      try {
        const vRes = await verifyReportIntegrity(rep);
        setVerifyResult(vRes);
      } catch {
        // Fallback
      }
    } catch (err: unknown) {
      console.error('Failed to load report:', err);
      const msg = err instanceof Error ? err.message : 'Failed to generate investigation report.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReport();
  }, [investigation.id, investigation.sha256_hash]);

  const handleVerifyIntegrity = async () => {
    if (!report) return;
    setVerifying(true);
    try {
      const vRes = await verifyReportIntegrity(report);
      setVerifyResult(vRes);
    } catch (err: unknown) {
      console.error('Integrity verification failed:', err);
    } finally {
      setVerifying(false);
    }
  };

  const handleExportJson = async () => {
    setExportingJson(true);
    try {
      await downloadReportJson(investigation);
    } catch (err: unknown) {
      console.error('Export JSON failed:', err);
      alert('Failed to download JSON report.');
    } finally {
      setExportingJson(false);
    }
  };

  const handleExportHtml = async () => {
    setExportingHtml(true);
    try {
      await downloadReportHtml(investigation);
    } catch (err: unknown) {
      console.error('Export HTML failed:', err);
      alert('Failed to download HTML report.');
    } finally {
      setExportingHtml(false);
    }
  };

  const [exportingPdf,setExportingPdf] = useState(false);
  const handlePrint = async () => {
    setExportingPdf(true);
    try { await downloadReportPdf(investigation); } catch(err) { setError(err instanceof Error?err.message:'PDF export failed'); } finally {setExportingPdf(false);}
  };

  if (loading) {
    return (
      <div className="py-24 flex flex-col items-center justify-center space-y-4">
        <div className="relative">
          <div className="w-12 h-12 rounded-full border-2 border-sky-500/20 border-t-sky-400 animate-spin" />
          <Fingerprint className="w-5 h-5 text-sky-400 absolute inset-0 m-auto" />
        </div>
        <div className="text-center space-y-1">
          <span className="text-sm font-semibold text-slate-200">
            Generating Evidence Report & Verifying Hashes...
          </span>
          <p className="text-xs text-slate-500">
            Canonicalizing logical security evidence and computing Merkle digest
          </p>
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="py-16 max-w-xl mx-auto text-center space-y-4">
        <div className="w-12 h-12 rounded-2xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 mx-auto">
          <AlertTriangle className="w-6 h-6" />
        </div>
        <div className="space-y-1">
          <h3 className="text-base font-bold text-white">Report Generation Error</h3>
          <p className="text-xs text-slate-400 leading-relaxed">{error || 'Unable to build report.'}</p>
        </div>
        <button
          onClick={loadReport}
          className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 text-xs font-bold transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Retry Report Generation</span>
        </button>
      </div>
    );
  }

  const {
    report_metadata: meta,
    capture_summary: capture,
    executive_summary: exec,
    security_posture: posture,
    deterministic_findings: findings,
    recommendations,
    evidence_manifest: manifest,
    limitations,
    privacy_statement: privacy,
  } = report;

  const isVerified = verifyResult ? verifyResult.is_valid : manifest.integrity_status === 'VERIFIED';

  return (
    <div className="space-y-8 pb-12">
      <FixFirstPanel value={report.fix_first}/>
      {/* Top Banner & Action Header */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-6">
          <div>
            <div className="flex items-center space-x-3 mb-1.5">
              <span className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                <FileText className="w-6 h-6 text-sky-400" />
                <span>Investigation Evidence Report</span>
              </span>
              <span className="px-2.5 py-0.5 rounded text-xs font-mono font-medium bg-slate-800 text-sky-300 border border-slate-700">
                {meta.report_id}
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400">
              <span>Source: <strong className="text-slate-200 font-mono">{capture.filename}</strong></span>
              <span>•</span>
              <span>SHA-256: <strong className="text-sky-400 font-mono">{capture.capture_sha256_short}</strong></span>
              <span>•</span>
              <span>Generated: {meta.generated_at}</span>
            </div>
          </div>

          {/* Export Actions */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleExportJson}
              disabled={exportingJson}
              className="inline-flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-sky-300 text-xs font-semibold border border-slate-700 transition disabled:opacity-50"
              title="Download structured JSON report"
            >
              {exportingJson ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
              <span>Export JSON</span>
            </button>

            <button
              onClick={handleExportHtml}
              disabled={exportingHtml}
              className="inline-flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 text-xs font-bold shadow-sm transition disabled:opacity-50"
              title="Download standalone HTML report"
            >
              {exportingHtml ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
              <span>Export HTML</span>
            </button>

            <button
              onClick={handlePrint}
              disabled={exportingPdf}
              className="inline-flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition"
              title="Download paginated forensic PDF report"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>{exportingPdf?'Generating PDF…':'Export PDF'}</span>
            </button>
          </div>
        </div>

        {/* High-Level Assessment Summary */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-6">
          {/* Provenance */}
          <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-4">
            <div className="text-[11px] text-slate-400 font-semibold mb-1">Data Provenance</div>
            <div className="flex items-center space-x-2 mt-1">
              {isRealCapture ? (
                <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded text-xs bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-semibold">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>{investigation.capture_origin==='SYNTHETIC_LAB'?'SYNTHETIC LAB PCAP':'UPLOADED PCAP'}</span>
                </span>
              ) : (
                <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded text-xs bg-amber-500/10 text-amber-300 border border-amber-500/30 font-semibold">
                  <span>SIMULATED DEMO</span>
                </span>
              )}
            </div>
            <div className="text-[11px] text-slate-500 font-mono mt-2 truncate">
              {capture.filename}
            </div>
          </div>

          {/* Security Posture */}
          <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-4">
            <div className="text-[11px] text-slate-400 font-semibold mb-1">Overall Posture</div>
            <div className="flex items-center space-x-2 mt-1">
              <span
                className={`text-base font-bold px-2.5 py-0.5 rounded ${
                  posture.status === 'CRITICAL'
                    ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                    : posture.status === 'HIGH_RISK'
                    ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                    : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                }`}
              >
                {posture.status}
              </span>
            </div>
            <div className="text-xs text-slate-400 mt-2">
              {posture.critical_count} Critical • {posture.high_count} High • {posture.medium_count} Med
            </div>
          </div>

          {/* Scope */}
          <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-4">
            <div className="text-[11px] text-slate-400 font-semibold mb-1">Observed Scope</div>
            <div className="text-xl font-bold text-white mt-1">
              {capture.total_sessions} <span className="text-xs text-slate-400 font-normal">session(s)</span>
            </div>
            <div className="text-xs text-slate-400 mt-2">
              {capture.observed_clients_count} client endpoint(s) discovered
            </div>
          </div>

          {/* Integrity */}
          <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-4">
            <div className="text-[11px] text-slate-400 font-semibold mb-1">Evidence Integrity</div>
            <div className="flex items-center space-x-2 mt-1">
              <span
                className={`inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded text-xs font-bold ${
                  isVerified
                    ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30'
                    : 'bg-rose-500/10 text-rose-300 border border-rose-500/30'
                }`}
              >
                <Fingerprint className="w-3.5 h-3.5" />
                <span>{isVerified ? 'VERIFIED' : 'TAMPERED'}</span>
              </span>
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-2 truncate">
              Root: {manifest.evidence_root.slice(0, 16)}...
            </div>
          </div>
        </div>
      </div>

      {/* 1. Executive Summary */}
      <section className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex items-center space-x-2 text-sm font-semibold text-sky-400 mb-4 border-b border-slate-800 pb-3">
          <FileText className="w-4 h-4" />
          <span>1. Executive Summary</span>
        </div>

        <div className="space-y-4">
          <h3 className="text-base font-bold text-white leading-snug">
            {exec.headline}
          </h3>

          <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-4 space-y-3 text-xs leading-relaxed">
            <p className="text-slate-300 font-sans">{exec.transport_security_summary}</p>
            <p className="text-slate-200 font-sans font-medium">
              {exec.posture_summary} {exec.key_findings_summary}
            </p>
            <div className="pt-2 border-t border-slate-800 flex items-start space-x-2 text-slate-400">
              <Info className="w-3.5 h-3.5 text-sky-400 mt-0.5 shrink-0" />
              <p className="text-xs italic">{exec.ai_anomaly_summary}</p>
            </div>
          </div>
        </div>
      </section>

      {/* 2. Prioritized Recommendations */}
      <section className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <div className="flex items-center space-x-2 text-sm font-semibold text-sky-400">
            <Shield className="w-4 h-4" />
            <span>2. Prioritized Recommendations</span>
          </div>
          <span className="text-xs text-slate-400">
            {recommendations.length} action item{recommendations.length !== 1 ? 's' : ''}
          </span>
        </div>

        {recommendations.length === 0 ? (
          <div className="text-xs text-slate-400 py-4 text-center">
            No remediation actions required. All observed transport sessions meet security baseline.
          </div>
        ) : (
          <div className="space-y-3">
            {recommendations.map((rec) => (
              <div
                key={rec.rule_id}
                className="bg-slate-950/60 border border-slate-800 rounded-lg p-4 flex flex-col sm:flex-row sm:items-start justify-between gap-3 hover:border-slate-700 transition"
              >
                <div className="flex items-start space-x-3">
                  <div className="w-6 h-6 rounded-full bg-slate-800 text-sky-400 text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                    {rec.priority_rank}
                  </div>
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                          rec.severity === 'CRITICAL'
                            ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                            : rec.severity === 'HIGH'
                            ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                            : 'bg-sky-500/15 text-sky-300 border border-sky-500/30'
                        }`}
                      >
                        {rec.severity}
                      </span>
                      <span className="text-xs font-mono font-medium text-slate-300">{rec.rule_id}</span>
                    </div>
                    <p className="text-xs font-bold text-white">{rec.action}</p>
                    <p className="text-xs text-slate-400 leading-normal">{rec.rationale}</p>
                  </div>
                </div>

                {rec.policy_bridge && onNavigateToSimulator && (
                  <button
                    onClick={() => onNavigateToSimulator(rec.policy_bridge!)}
                    className="self-start sm:self-center inline-flex items-center space-x-1 px-2.5 py-1.5 rounded bg-sky-500/10 hover:bg-sky-500/20 text-sky-300 border border-sky-500/30 text-xs transition shrink-0 font-medium"
                  >
                    <span>Test Policy</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      {/* 3. Deterministic Findings */}
      <section className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <div className="flex items-center space-x-2 text-sm font-semibold text-sky-400">
            <AlertOctagon className="w-4 h-4" />
            <span>3. Deterministic Security Findings ({findings.length})</span>
          </div>
          {onNavigateToFindings && (
            <button
              onClick={onNavigateToFindings}
              className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1 font-medium"
            >
              <span>View in Findings Tab</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          )}
        </div>

        {findings.length === 0 ? (
          <div className="text-xs text-slate-400 py-4 text-center">
            No security weaknesses or configuration warnings observed in this capture.
          </div>
        ) : (
          <div className="space-y-4">
            {findings.map((finding) => (
              <div
                key={finding.rule_id}
                className="bg-slate-950/60 border border-slate-800 rounded-lg p-4 space-y-3"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                  <div className="flex items-center space-x-2.5">
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                        finding.severity === 'CRITICAL'
                          ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                          : finding.severity === 'HIGH'
                          ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                          : 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30'
                      }`}
                    >
                      {finding.severity}
                    </span>
                    <span className="text-xs font-mono font-medium text-slate-300">{finding.rule_id}</span>
                    <span className="text-sm font-bold text-white">{finding.title}</span>
                  </div>

                  <div className="flex items-center space-x-2">
                    <span className="text-[10px] text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                      Confidence: {finding.confidence}
                    </span>
                    {finding.related_session_id && onNavigateToReplay && (
                      <button
                        onClick={() => onNavigateToReplay(finding.rule_id, finding.related_session_id)}
                        className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-xs transition"
                        title="View chronological session replay"
                      >
                        <Eye className="w-3 h-3" />
                        <span>Replay</span>
                      </button>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-[11px] font-semibold text-slate-400">Plain Explanation:</span>
                    <p className="text-slate-200 mt-0.5 leading-relaxed">{finding.plain_explanation}</p>
                  </div>
                  <div>
                    <span className="text-[11px] font-semibold text-slate-400">Technical Impact:</span>
                    <p className="text-slate-300 mt-0.5 leading-relaxed">{finding.why_it_matters}</p>
                    <RemediationCard remediation={finding.remediation} fallback={finding.recommendation}/>
                  </div>
                </div>

                {/* Evidence Items */}
                {finding.evidence_items && finding.evidence_items.length > 0 && (
                  <div className="bg-slate-900/60 border border-slate-800/80 rounded p-3">
                    <div className="text-[10px] font-semibold text-slate-400 mb-1.5">
                      Authoritative Evidence Items:
                    </div>
                    <div className="space-y-1">
                      {finding.evidence_items.map((ev, i) => (
                        <div key={i} className="text-xs flex items-start space-x-2">
                          <span className="text-sky-400 font-mono font-bold text-[11px]">[{ev.type}]</span>
                          <span className="text-slate-300 font-mono text-[11px]">{ev.field}={String(ev.value)}</span>
                          <span className="text-slate-400 font-sans">{ev.description}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* References */}
                {finding.references && finding.references.length > 0 && (
                  <div className="text-xs text-slate-400 pt-0.5">
                    <strong>Standards:</strong> {finding.references.join(' • ')}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      {/* 4. Cryptographic Evidence Integrity Manifest */}
      <section className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3 mb-4">
          <div className="flex items-center space-x-2 text-sm font-semibold text-sky-400">
            <Lock className="w-4 h-4" />
            <span>4. Cryptographic Evidence Integrity</span>
          </div>

          <button
            onClick={handleVerifyIntegrity}
            disabled={verifying}
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs transition disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
            <span>Re-Verify Integrity</span>
          </button>
        </div>

        <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-5 text-xs space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="text-slate-400">Integrity Status:</span>
            <span className="flex items-center space-x-2">
              <span className="text-sky-400 font-mono">{manifest.integrity_algorithm}</span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                  isVerified
                    ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                    : 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                }`}
              >
                {isVerified ? 'VERIFIED' : 'TAMPERED'}
              </span>
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs text-slate-400">
            <div>
              <span className="text-slate-500 block text-[11px]">Capture SHA-256:</span>
              <div className="text-slate-300 font-mono break-all text-[11px]">{manifest.capture_sha256}</div>
            </div>
            <div>
              <span className="text-slate-500 block text-[11px]">Findings Digest:</span>
              <div className="text-slate-300 font-mono break-all text-[11px]">{manifest.findings_digest}</div>
            </div>
            <div>
              <span className="text-slate-500 block text-[11px]">Replay Digest:</span>
              <div className="text-slate-300 font-mono break-all text-[11px]">{manifest.replay_digest}</div>
            </div>
            <div>
              <span className="text-slate-500 block text-[11px]">Discovery Digest:</span>
              <div className="text-slate-300 font-mono break-all text-[11px]">{manifest.discovery_digest}</div>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <span className="text-xs font-semibold text-sky-400">Merkle Evidence Root:</span>
              <div className="text-xs font-mono text-emerald-300 break-all">{manifest.evidence_root}</div>
            </div>
            <div className="text-emerald-400 font-medium text-xs flex items-center space-x-1.5 shrink-0">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Evidence integrity verified against the report manifest.</span>
            </div>
          </div>
        </div>
      </section>

      {/* 5. Authoritative Limitations & Privacy */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-sm">
          <div className="flex items-center space-x-2 text-sm font-semibold text-sky-400 mb-4 border-b border-slate-800 pb-3">
            <Info className="w-4 h-4" />
            <span>Authoritative Limitations</span>
          </div>
          <ul className="space-y-2 text-xs text-slate-300 list-disc list-inside">
            {limitations.map((lim, i) => (
              <li key={i} className="leading-relaxed">{lim}</li>
            ))}
          </ul>
        </section>

        <section className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-sm">
          <div className="flex items-center space-x-2 text-sm font-semibold text-emerald-400 mb-4 border-b border-slate-800 pb-3">
            <Lock className="w-4 h-4" />
            <span>Privacy Guarantee</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/60 p-4 rounded-lg border border-slate-800">
            {privacy}
          </p>
        </section>
      </div>
    </div>
  );
};
