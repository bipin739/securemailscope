import React, { useState } from 'react';
import {
  Investigation,
  ClientDiscoveryResult,
  ClientAnomalyResult,
  AnomalyPriority,
  LegacyClassification,
} from '../types';
import {
  Users,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  Sparkles,
  Search,
  PlayCircle,
  Cpu,
  Layers,
  Info,
  CheckCircle2,
} from 'lucide-react';

interface ClientDiscoveryProps {
  investigation: Investigation;
  onNavigateToFindings: (clientFindingIds: string[]) => void;
  onNavigateToReplay: (sessionId: string) => void;
  onNavigateToSimulator: (clientId: string) => void;
  selectedClientId?: string;
  onSelectClient?: (clientId: string) => void;
}

export const ClientDiscovery: React.FC<ClientDiscoveryProps> = ({
  investigation,
  onNavigateToFindings,
  onNavigateToReplay,
  onNavigateToSimulator,
  selectedClientId: propSelectedClientId,
  onSelectClient,
}) => {
  const discovery: ClientDiscoveryResult | undefined = investigation.discovery;

  const [selectedClientId, setSelectedClientId] = useState<string>(
    propSelectedClientId || (discovery?.inventory && discovery.inventory.length > 0 ? discovery.inventory[0].client_id : '')
  );
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [classificationFilter, setClassificationFilter] = useState<string>('ALL');
  const [priorityFilter, setPriorityFilter] = useState<string>('ALL');

  React.useEffect(() => {
    if (discovery?.inventory && discovery.inventory.length > 0) {
      if (!discovery.inventory.some((p) => p.client_id === selectedClientId)) {
        setSelectedClientId(discovery.inventory[0].client_id);
      }
    }
  }, [investigation.id, discovery]);

  if (!discovery) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center space-y-4">
        <Users className="w-12 h-12 text-slate-500 mx-auto" />
        <h3 className="text-base font-semibold text-slate-200">No Client Discovery Data Available</h3>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          The current capture does not contain client discovery metadata.
        </p>
      </div>
    );
  }

  const { inventory, summary, anomaly_assessment } = discovery;

  // Build anomaly map
  const anomalyMap = new Map<string, ClientAnomalyResult>();
  if (anomaly_assessment && anomaly_assessment.results) {
    for (const res of anomaly_assessment.results) {
      anomalyMap.set(res.client_id, res);
    }
  }

  // Filter inventory
  const filteredInventory = inventory.filter((profile) => {
    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = profile.client_id.toLowerCase().includes(q);
      const matchIp = profile.observed_ip.toLowerCase().includes(q);
      const matchProto = profile.protocol.toLowerCase().includes(q);
      if (!matchId && !matchIp && !matchProto) return false;
    }

    // Classification filter
    if (classificationFilter !== 'ALL' && profile.legacy_classification !== classificationFilter) {
      return false;
    }

    // Priority filter
    if (priorityFilter !== 'ALL') {
      const aRes = anomalyMap.get(profile.client_id);
      const pri = aRes?.priority || 'NORMAL';
      if (priorityFilter !== pri) return false;
    }

    return true;
  });

  const selectedProfile = inventory.find((p) => p.client_id === selectedClientId) || (inventory.length > 0 ? inventory[0] : null);
  const selectedAnomaly = selectedProfile ? anomalyMap.get(selectedProfile.client_id) : null;

  const handleSelectClientRow = (clientId: string) => {
    setSelectedClientId(clientId);
    if (onSelectClient) {
      onSelectClient(clientId);
    }
  };

  // Terminology cleanup: Legacy cryptography vs Insecure transport behavior
  const getClassificationBadge = (classification: LegacyClassification) => {
    switch (classification) {
      case 'MODERN_OBSERVED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <ShieldCheck className="w-3 h-3" />
            <span>Modern TLS</span>
          </span>
        );
      case 'LEGACY_OBSERVED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-medium bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <ShieldAlert className="w-3 h-3" />
            <span>Legacy Crypto</span>
          </span>
        );
      case 'MIXED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-medium bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3" />
            <span>Mixed Transport</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-800 text-slate-400 border border-slate-700">
            <HelpCircle className="w-3 h-3" />
            <span>Unknown Baseline</span>
          </span>
        );
    }
  };

  const getPriorityBadge = (priority?: AnomalyPriority, status?: string) => {
    if (status === 'INSUFFICIENT_SAMPLE') {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-slate-800 text-slate-400 border border-slate-700" title="Statistical anomaly ranking abstained due to small capture sample">
          Insufficient baseline (&lt;5)
        </span>
      );
    }
    switch (priority) {
      case 'HIGH_REVIEW':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
            <Sparkles className="w-3 h-3 text-purple-400" />
            <span>High Attention</span>
          </span>
        );
      case 'REVIEW':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-medium bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
            <Sparkles className="w-3 h-3 text-indigo-400" />
            <span>Review Attention</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] bg-slate-800/80 text-slate-400 border border-slate-700/60">
            Normal
          </span>
        );
    }
  };

  const getIndicatorSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-500/15 text-rose-300 border-rose-500/40';
      case 'HIGH':
        return 'bg-amber-500/15 text-amber-300 border-amber-500/40';
      case 'MEDIUM':
        return 'bg-yellow-500/15 text-yellow-300 border-yellow-500/40';
      default:
        return 'bg-sky-500/15 text-sky-300 border-sky-500/30';
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Header & Context */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-2.5">
              <span className="p-1.5 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/30">
                <Users className="w-4 h-4" />
              </span>
              <h2 className="text-xl font-bold text-white tracking-tight">Observed Client Discovery</h2>
              <span className="text-xs font-semibold px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30">
                AI-Assisted Prioritization
              </span>
            </div>
            <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
              Discovers email client endpoints from passive transport metadata, evaluates deterministic cryptographic behavior, and applies offline statistical anomaly detection to prioritize unusual clients for review.
            </p>
          </div>

          {/* AI Status */}
          <div className="flex items-center space-x-2 bg-slate-950 border border-slate-800 px-3.5 py-2 rounded-lg text-xs">
            <Cpu className="w-4 h-4 text-purple-400" />
            <span className="text-slate-400">AI Prioritization:</span>
            {anomaly_assessment.status === 'ANALYZED' ? (
              <span className="text-emerald-400 font-semibold flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Active ({anomaly_assessment.population_size} compared)</span>
              </span>
            ) : anomaly_assessment.status === 'INSUFFICIENT_SAMPLE' ? (
              <span className="text-amber-400 font-medium flex items-center gap-1" title="Sample size below minimum threshold (5)">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Insufficient comparison population (&lt;5)</span>
              </span>
            ) : (
              <span className="text-slate-400">Unavailable</span>
            )}
          </div>
        </div>
      </div>

      {/* 2. Summary KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Total Observed */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
            <span>Observed Clients</span>
            <Users className="w-4 h-4 text-sky-400" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-extrabold font-sans text-white">{summary.observed_clients}</span>
            <p className="text-[11px] text-slate-500 mt-0.5">Observed in capture</p>
          </div>
        </div>

        {/* Modern */}
        <div className="bg-slate-900/90 border border-emerald-900/30 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-emerald-400 text-xs font-medium">
            <span>Modern Observed</span>
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-extrabold font-sans text-emerald-400">{summary.modern_clients}</span>
            <p className="text-[11px] text-slate-500 mt-0.5">Strict TLS 1.2 / 1.3</p>
          </div>
        </div>

        {/* Legacy */}
        <div className="bg-slate-900/90 border border-rose-900/30 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-rose-400 text-xs font-medium">
            <span>Legacy Crypto</span>
            <ShieldAlert className="w-4 h-4" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-extrabold font-sans text-rose-400">{summary.legacy_clients}</span>
            <p className="text-[11px] text-slate-500 mt-0.5">Deprecated TLS / Ciphers</p>
          </div>
        </div>

        {/* Mixed */}
        <div className="bg-slate-900/90 border border-amber-900/30 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-amber-400 text-xs font-medium">
            <span>Mixed Transport</span>
            <AlertTriangle className="w-4 h-4" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-extrabold font-sans text-amber-400">{summary.mixed_clients}</span>
            <p className="text-[11px] text-slate-500 mt-0.5">TLS + Insecure fallback</p>
          </div>
        </div>

        {/* Unknown */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
            <span>Unknown Baseline</span>
            <HelpCircle className="w-4 h-4" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-extrabold font-sans text-slate-300">{summary.unknown_clients}</span>
            <p className="text-[11px] text-slate-500 mt-0.5">Partial evidence trace</p>
          </div>
        </div>

        {/* Needs Review */}
        <div className="bg-slate-900/90 border border-purple-900/30 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-purple-300 text-xs font-medium">
            <span>AI Review Queue</span>
            <Sparkles className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-extrabold font-sans text-purple-300">{summary.needs_review_count}</span>
            <p className="text-[11px] text-purple-400/80 mt-0.5">Statistical Outliers</p>
          </div>
        </div>
      </div>

      {/* 3. Methodology & Honesty Note */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex items-start gap-3.5 text-xs">
        <Info className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
        <div className="text-slate-300 space-y-1 font-sans">
          <p className="font-semibold text-white">
            Evidentiary Separation: Deterministic Security vs. AI Prioritization
          </p>
          <p className="text-slate-400 leading-relaxed">
            <strong className="text-slate-200">1. Deterministic Security Rules:</strong> Hard cryptographic vulnerabilities (deprecated TLS, cleartext authentication, weak ciphers) are evaluated authoritatively.
            <br />
            <strong className="text-slate-200">2. AI-Assisted Prioritization:</strong> Statistical anomaly scoring highlights unusual endpoint behavior relative to other clients in this capture. AI never overrides deterministic findings or invents vulnerabilities.
          </p>
          {anomaly_assessment.status === 'INSUFFICIENT_SAMPLE' && (
            <div className="pt-1.5 flex items-center gap-2 text-amber-300 text-xs">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              <span>Insufficient comparison population: Statistical anomaly analysis requires at least 5 observed clients.</span>
            </div>
          )}
        </div>
      </div>

      {/* 4. Main Grid: Inventory Table (Left) & Inspector (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Client Inventory Table */}
        <div className="lg:col-span-7 bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden flex flex-col shadow-sm">
          {/* Controls */}
          <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <div className="relative flex-1 min-w-[180px]">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search by IP, ID, or protocol..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500/50"
              />
            </div>

            <select
              value={classificationFilter}
              onChange={(e) => setClassificationFilter(e.target.value)}
              className="text-xs bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-sky-500/50"
            >
              <option value="ALL">All Classifications</option>
              <option value="MODERN_OBSERVED">Modern</option>
              <option value="LEGACY_OBSERVED">Legacy Crypto</option>
              <option value="MIXED">Mixed</option>
              <option value="UNKNOWN">Unknown</option>
            </select>

            <select
              value={priorityFilter}
              onChange={(e) => setPriorityFilter(e.target.value)}
              className="text-xs bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-sky-500/50"
            >
              <option value="ALL">All AI Priorities</option>
              <option value="HIGH_REVIEW">High Attention</option>
              <option value="REVIEW">Review</option>
              <option value="NORMAL">Normal</option>
            </select>
          </div>

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase text-[10px] font-medium border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3.5">Client Endpoint</th>
                  <th className="py-2.5 px-3 text-center">Sessions</th>
                  <th className="py-2.5 px-3">Baseline</th>
                  <th className="py-2.5 px-3">Observed TLS</th>
                  <th className="py-2.5 px-3">AI Outlier Priority</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredInventory.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500">
                      No observed clients match the active filter criteria.
                    </td>
                  </tr>
                ) : (
                  filteredInventory.map((profile) => {
                    const isSelected = selectedClientId === profile.client_id;
                    const aRes = anomalyMap.get(profile.client_id);

                    return (
                      <tr
                        key={profile.client_id}
                        onClick={() => handleSelectClientRow(profile.client_id)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-sky-500/10 border-l-2 border-l-sky-400'
                            : 'hover:bg-slate-800/40'
                        }`}
                      >
                        {/* Endpoint */}
                        <td className="py-3 px-3.5">
                          <div className="font-bold text-slate-100 flex items-center gap-1.5">
                            <span className="text-sky-400 font-mono">{profile.protocol}</span>
                            <span className="text-slate-400">:</span>
                            <span className="font-mono">{profile.observed_ip}
                            <div className="text-[10px] font-normal text-slate-400 mt-1 break-all max-w-xs">[{profile.ja3_fingerprints?.length?'OBSERVED':'COVERAGE_GAP'}] JA3: {profile.ja3_fingerprints?.join(' / ')||profile.ja3_fingerprint||'UNKNOWN'}</div></span>
                          </div>
                          <div className="text-[11px] text-slate-400 mt-0.5">
                            {profile.transport_modes.length > 0 ? profile.transport_modes[0] : 'Standard Transport'}
                          </div>
                        </td>

                        {/* Sessions */}
                        <td className="py-3 px-3 text-center text-slate-300 font-semibold font-mono">
                          {profile.session_count}
                        </td>

                        {/* Baseline */}
                        <td className="py-3 px-3">
                          {getClassificationBadge(profile.legacy_classification)}
                        </td>

                        {/* Observed TLS */}
                        <td className="py-3 px-3">
                          {profile.observed_tls_versions.length > 0 ? (
                            <span className={`font-mono ${profile.weak_tls_count > 0 ? 'text-rose-400 font-bold' : 'text-slate-200'}`}>
                              {profile.observed_tls_versions.join(', ')}
                            </span>
                          ) : (
                            <span className="text-amber-400/90 font-medium">{profile.plaintext_session_count > 0 ? '[OBSERVED] Cleartext' : '[COVERAGE_GAP] UNKNOWN'}</span>
                          )}
                        </td>

                        {/* AI Priority */}
                        <td className="py-3 px-3">
                          {getPriorityBadge(aRes?.priority, anomaly_assessment.status)}
                        </td>

                        {/* Action */}
                        <td className="py-3 px-3 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleSelectClientRow(profile.client_id);
                            }}
                            className={`px-2.5 py-1 rounded text-xs font-medium transition ${
                              isSelected
                                ? 'bg-sky-500 text-slate-950 font-bold'
                                : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                            }`}
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Client Detailed Drawer */}
        <div className="lg:col-span-5 space-y-4">
          {selectedProfile ? (
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-5 shadow-sm">
              {/* Header */}
              <div className="flex items-start justify-between border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-medium border border-slate-700">
                      {selectedProfile.protocol} Endpoint
                    </span>
                    {getClassificationBadge(selectedProfile.legacy_classification)}
                  </div>
                  <h3 className="text-base font-bold text-white font-mono mt-1.5">
                    {selectedProfile.client_id}
                  </h3>
                  <p className="text-xs text-slate-400">
                    Observed across {selectedProfile.session_count} session(s) in this capture.
                  </p>
                </div>
              </div>

              {/* 1: DETERMINISTIC SECURITY POSTURE */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-1.5 text-xs font-bold uppercase text-slate-300">
                    <Shield className="w-4 h-4 text-sky-400" />
                    <span>Deterministic Security Posture</span>
                  </div>
                  <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    Authoritative
                  </span>
                </div>

                <div className="space-y-2">
                  {selectedProfile.indicators.length === 0 ? (
                    <div className="p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20 text-xs text-emerald-300 flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
                      <span>No deterministic security defects observed for this client endpoint.</span>
                    </div>
                  ) : (
                    selectedProfile.indicators.map((ind) => (
                      <div
                        key={ind.indicator_id}
                        className={`p-3 rounded-lg border text-xs space-y-1 ${getIndicatorSeverityBadge(ind.severity)}`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold">{ind.title}</span>
                          <span className="text-[10px] uppercase font-bold">{ind.severity}</span>
                        </div>
                        <p className="text-xs opacity-90 leading-relaxed font-sans">{ind.description}</p>
                        <div className="text-[11px] font-mono opacity-80 pt-0.5">
                          Evidence: {ind.evidence}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* 2: AI-ASSISTED PRIORITIZATION */}
              <div className="space-y-3 pt-3 border-t border-slate-800">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-1.5 text-xs font-bold uppercase text-purple-300">
                    <Sparkles className="w-4 h-4 text-purple-400" />
                    <span>AI-Assisted Prioritization</span>
                  </div>
                  <div>
                    {getPriorityBadge(selectedAnomaly?.priority, anomaly_assessment.status)}
                  </div>
                </div>

                {anomaly_assessment.status === 'INSUFFICIENT_SAMPLE' ? (
                  <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 space-y-1.5">
                    <div className="flex items-center gap-2 text-amber-400 font-semibold">
                      <AlertTriangle className="w-4 h-4" />
                      <span>Statistical Anomaly Analysis Abstained</span>
                    </div>
                    <p className="text-slate-400 text-xs leading-relaxed">
                      Statistical anomaly analysis requires at least 5 observed clients. Because only 1 client is present in this capture, relative outlier scoring is responsibly withheld to prevent false statistical conclusions.
                    </p>
                  </div>
                ) : selectedAnomaly ? (
                  <div className="p-3.5 rounded-lg bg-purple-950/20 border border-purple-800/40 text-xs space-y-3">
                    <div>
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-300">Anomaly Attention Score:</span>
                        <span className="text-purple-300 font-bold">{selectedAnomaly.anomaly_score} / 100</span>
                      </div>
                      <div className="w-full h-1.5 bg-slate-800 rounded-full mt-1.5 overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-indigo-500 to-purple-400 rounded-full transition-all duration-500"
                          style={{ width: `${Math.min(100, Math.max(5, selectedAnomaly.anomaly_score))}%` }}
                        />
                      </div>
                    </div>

                    <div className="space-y-1">
                      <span className="text-xs font-semibold text-slate-200">Why AI Surfaced This:</span>
                      <p className="text-xs text-slate-300 leading-relaxed font-sans bg-slate-950/60 p-2.5 rounded border border-slate-800">
                        {selectedAnomaly.explanation}
                      </p>
                    </div>

                    {selectedAnomaly.contributing_features.length > 0 && (
                      <div>
                        <span className="text-[11px] text-slate-400 uppercase font-semibold">Divergence Factors:</span>
                        <div className="flex flex-wrap gap-1.5 mt-1">
                          {selectedAnomaly.contributing_features.map((feat, i) => (
                            <span key={i} className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-900/40 text-purple-200 border border-purple-700/50">
                              {feat}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : null}
              </div>

              {/* 3: OBSERVED CRYPTOGRAPHIC PARAMETERS */}
              <div className="space-y-2 pt-3 border-t border-slate-800 text-xs">
                <div className="text-slate-400 uppercase text-[10px] font-semibold">Observed Cryptographic Baseline</div>
                <div className="grid grid-cols-2 gap-2">
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase">Negotiated TLS</span>
                    <span className="text-white font-mono font-semibold text-xs">
                      {selectedProfile.observed_tls_versions.join(', ') || 'UNKNOWN'}
                    </span>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase">Forward Secrecy</span>
                    <span className={`text-xs font-semibold ${selectedProfile.forward_secrecy_observed ? 'text-emerald-400' : 'text-slate-400'}`}>
                      {selectedProfile.forward_secrecy_observed ? 'Verified (PFS)' : 'Not Observed'}
                    </span>
                  </div>
                </div>

                {selectedProfile.observed_cipher_suites.length > 0 && (
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase">Negotiated Cipher Suites</span>
                    <span className="text-slate-200 font-mono text-[11px] break-all">
                      {selectedProfile.observed_cipher_suites.join(', ')}
                    </span>
                  </div>
                )}
              </div>

              {/* 4: CROSS-SUBSYSTEM NAVIGATION */}
              <div className="space-y-2 pt-3 border-t border-slate-800">
                <div className="text-slate-400 uppercase text-[10px] font-semibold">Cross-Subsystem Actions</div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <button
                    onClick={() => onNavigateToFindings(selectedProfile.deterministic_finding_ids)}
                    className="flex items-center justify-center space-x-1.5 px-3 py-2 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 text-sky-300 border border-sky-500/30 text-xs font-semibold transition"
                  >
                    <Shield className="w-3.5 h-3.5" />
                    <span>Findings ({selectedProfile.deterministic_finding_ids.length})</span>
                  </button>

                  <button
                    onClick={() => {
                      const sessId = selectedProfile.replay_session_ids[0] || '';
                      onNavigateToReplay(sessId);
                    }}
                    className="flex items-center justify-center space-x-1.5 px-3 py-2 rounded-lg bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-xs font-semibold transition"
                  >
                    <PlayCircle className="w-3.5 h-3.5" />
                    <span>Security Replay</span>
                  </button>

                  <button
                    onClick={() => onNavigateToSimulator(selectedProfile.client_id)}
                    className="flex items-center justify-center space-x-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition"
                  >
                    <Layers className="w-3.5 h-3.5" />
                    <span>Hardening Test</span>
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-500 text-xs">
              Select an observed client endpoint to inspect deterministic indicators and AI anomaly prioritization.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
