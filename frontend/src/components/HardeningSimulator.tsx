import React, { useState, useEffect, useMemo } from 'react';
import { 
  ShieldCheck, 
  HelpCircle, 
  Sliders, 
  Play, 
  RefreshCw, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  ChevronDown, 
  ChevronUp, 
  BookOpen, 
  Layers, 
  Info,
  Sparkles
} from 'lucide-react';
import { 
  Investigation, 
  HardeningPolicy, 
  SimulationResult, 
  ClientSimulationResult, 
  ClientSimulationOutcome 
} from '../types';
import { fetchHardeningPolicies, runPolicySimulation } from '../services/api';

interface HardeningSimulatorProps {
  investigation: Investigation;
  initialSelectedPolicies?: string[];
  onSelectPolicyFromBridge?: (policyId: string) => void;
}

export const HardeningSimulator: React.FC<HardeningSimulatorProps> = ({
  investigation,
  initialSelectedPolicies,
}) => {
  const [policies, setPolicies] = useState<HardeningPolicy[]>([]);
  const [selectedPolicies, setSelectedPolicies] = useState<string[]>(
    initialSelectedPolicies && initialSelectedPolicies.length > 0
      ? initialSelectedPolicies
      : ['SMS-POLICY-TLS12', 'SMS-POLICY-NO-WEAK-CIPHER']
  );
  const [simulationResult, setSimulationResult] = useState<SimulationResult | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedClients, setExpandedClients] = useState<Record<string, boolean>>({});
  const [filterOutcome, setFilterOutcome] = useState<string>('ALL');

  // Load policies on mount
  useEffect(() => {
    const loadPolicies = async () => {
      try {
        const availablePolicies = await fetchHardeningPolicies();
        setPolicies(availablePolicies);
      } catch (err: unknown) {
        console.error('Failed to load policies:', err);
      }
    };
    loadPolicies();
  }, []);

  // Sync initialSelectedPolicies if changed externally
  useEffect(() => {
    if (initialSelectedPolicies && initialSelectedPolicies.length > 0) {
      setSelectedPolicies(initialSelectedPolicies);
    }
  }, [initialSelectedPolicies]);

  // Execute simulation
  const handleRunSimulation = async (pIds: string[] = selectedPolicies) => {
    if (pIds.length === 0) {
      setError('Please select at least one security hardening policy to simulate.');
      setSimulationResult(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await runPolicySimulation(investigation, pIds);
      setSimulationResult(res);
    } catch (err: unknown) {
      console.error('Simulation error:', err);
      const msg = err instanceof Error ? err.message : 'Simulation failed';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  // Run simulation automatically when investigation or selected policies change on initial load
  useEffect(() => {
    if (policies.length > 0 && selectedPolicies.length > 0) {
      handleRunSimulation(selectedPolicies);
    }
  }, [investigation.id, policies.length]);

  const togglePolicy = (policyId: string) => {
    const next = selectedPolicies.includes(policyId)
      ? selectedPolicies.filter((id) => id !== policyId)
      : [...selectedPolicies, policyId];
    setSelectedPolicies(next);
  };

  const selectAllPolicies = () => {
    setSelectedPolicies(policies.map((p) => p.id));
  };

  const clearAllPolicies = () => {
    setSelectedPolicies([]);
  };

  const toggleClientExpand = (clientId: string) => {
    setExpandedClients((prev) => ({
      ...prev,
      [clientId]: !(prev[clientId] ?? simulationResult?.clients.find(c=>c.client_id===clientId)?.outcome === "WOULD_BREAK"),
    }));
  };

  const isReal = !investigation.is_simulated || investigation.data_source === 'REAL_CAPTURE';

  const filteredClients = useMemo(() => {
    if (!simulationResult) return [];
    if (filterOutcome === 'ALL') return simulationResult.clients;
    return simulationResult.clients.filter((c) => c.outcome === filterOutcome);
  }, [simulationResult, filterOutcome]);

  const getOutcomeBadge = (outcome: ClientSimulationOutcome) => {
    switch (outcome) {
      case 'COMPATIBLE':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-md text-xs font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/40">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>COMPATIBLE</span>
          </span>
        );
      case 'WOULD_BREAK':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-md text-xs font-bold bg-rose-500/15 text-rose-300 border border-rose-500/40">
            <XCircle className="w-3.5 h-3.5 text-rose-400" />
            <span>WOULD BREAK</span>
          </span>
        );
      case 'UNKNOWN':
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-md text-xs font-bold bg-amber-500/15 text-amber-300 border border-amber-500/40">
            <HelpCircle className="w-3.5 h-3.5 text-amber-400" />
            <span>UNKNOWN</span>
          </span>
        );
    }
  };

  const getConfidenceBadge = (confidence: string) => {
    switch (confidence) {
      case 'HIGH':
        return <span className="text-[11px] font-medium px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800">Confidence: HIGH</span>;
      case 'MEDIUM':
        return <span className="text-[11px] font-medium px-2 py-0.5 rounded bg-amber-950/80 text-amber-400 border border-amber-800">Confidence: MEDIUM</span>;
      case 'LOW':
      default:
        return <span className="text-[11px] font-medium px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">Confidence: LOW</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Purpose Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center space-x-2.5">
              <span className="p-1.5 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/30">
                <Sliders className="w-4 h-4" />
              </span>
              <h2 className="text-xl font-bold text-white tracking-tight">
                Hardening Impact Simulator
              </h2>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                isReal
                  ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                  : 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
              }`}>
                {isReal ? 'REAL CAPTURE EVIDENCE' : 'DEMO FLEET CLIENTS'}
              </span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed max-w-3xl">
              Estimate compatibility impact before enforcing stronger security policies. Evaluates hypothetical policies against observed client cryptographic capabilities without touching servers or injecting traffic.
            </p>
          </div>

          <button
            onClick={() => handleRunSimulation()}
            disabled={loading || selectedPolicies.length === 0}
            className={`inline-flex items-center space-x-2 px-5 py-2.5 rounded-xl text-xs font-bold transition shadow-sm shrink-0 ${
              loading || selectedPolicies.length === 0
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                : 'bg-sky-500 hover:bg-sky-400 text-slate-950 border border-sky-400'
            }`}
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Simulating Impact...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Run Simulation</span>
              </>
            )}
          </button>
        </div>

        {/* 3-Step Simulation Visual Flow */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-6 pt-5 border-t border-slate-800 text-xs">
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800 flex items-start space-x-2.5">
            <span className="w-5 h-5 rounded-full bg-slate-800 text-sky-400 font-bold flex items-center justify-center shrink-0 text-[11px]">1</span>
            <div>
              <span className="font-semibold text-slate-200 block">Current Behavior</span>
              <span className="text-slate-400 text-[11px] block mt-0.5">Observed protocol & cipher capabilities in capture</span>
            </div>
          </div>

          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800 flex items-start space-x-2.5">
            <span className="w-5 h-5 rounded-full bg-sky-500/20 text-sky-300 font-bold flex items-center justify-center shrink-0 text-[11px]">2</span>
            <div>
              <span className="font-semibold text-slate-200 block">Proposed Policy</span>
              <span className="text-slate-400 text-[11px] block mt-0.5">Selected cryptographic enforcement rules</span>
            </div>
          </div>

          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800 flex items-start space-x-2.5">
            <span className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-300 font-bold flex items-center justify-center shrink-0 text-[11px]">3</span>
            <div>
              <span className="font-semibold text-slate-200 block">Predicted Impact</span>
              <span className="text-slate-400 text-[11px] block mt-0.5">Compatibility breakdown (Compatible vs Would Break)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Policy Selection Cards */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
          <div className="flex items-center space-x-2">
            <Layers className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-bold text-white">
              Target Hardening Policies
            </h3>
            <span className="text-xs text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
              {selectedPolicies.length} of {policies.length} Selected
            </span>
          </div>

          <div className="flex items-center space-x-2 text-xs">
            <button
              onClick={selectAllPolicies}
              className="text-sky-400 hover:text-sky-300 transition hover:underline"
            >
              Select All
            </button>
            <span className="text-slate-600">•</span>
            <button
              onClick={clearAllPolicies}
              className="text-slate-400 hover:text-slate-200 transition hover:underline"
            >
              Clear
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          {policies.map((policy) => {
            const isSelected = selectedPolicies.includes(policy.id);
            return (
              <div
                key={policy.id}
                onClick={() => togglePolicy(policy.id)}
                className={`p-4 rounded-xl border transition cursor-pointer flex flex-col justify-between ${
                  isSelected
                    ? 'bg-sky-950/25 border-sky-500/40 shadow-sm'
                    : 'bg-slate-950/50 border-slate-800/80 hover:bg-slate-900/60 hover:border-slate-700'
                }`}
              >
                <div>
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center space-x-2">
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => {}}
                        className="rounded bg-slate-800 border-slate-700 text-sky-500 focus:ring-0 focus:ring-offset-0 cursor-pointer"
                      />
                      <span className="text-xs font-mono font-bold text-sky-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                        {policy.id}
                      </span>
                    </div>
                    {isSelected && (
                      <span className="text-[10px] font-semibold text-sky-300 bg-sky-900/40 px-1.5 py-0.5 rounded">
                        Active
                      </span>
                    )}
                  </div>

                  <h4 className="text-sm font-semibold text-white mt-2">
                    {policy.name}
                  </h4>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed font-sans">
                    {policy.description}
                  </p>
                </div>

                <div className="mt-3 pt-2.5 border-t border-slate-800/60 flex flex-wrap items-center justify-between gap-1 text-[11px] text-slate-500">
                  <div className="flex items-center space-x-1 font-mono text-[10px]">
                    <BookOpen className="w-3 h-3 text-slate-400" />
                    <span>{policy.references.join(', ')}</span>
                  </div>
                  <span className="text-slate-400">
                    {policy.requirements.length} requirement{policy.requirements.length !== 1 ? 's' : ''}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Evidentiary Discipline Note */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex items-start space-x-3 text-xs">
        <Info className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
        <div className="space-y-0.5">
          <div className="font-semibold text-slate-200">
            Evidentiary Capability Discipline
          </div>
          <p className="text-slate-400 leading-relaxed font-sans">
            Simulation is based strictly on capabilities observed in this capture. <strong className="text-amber-300 font-semibold">UNKNOWN</strong> indicates that the capture does not provide enough capability evidence to predict compatibility safely. A negotiated cipher or TLS version is not assumed to represent the client's maximum capability.
          </p>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="bg-rose-950/20 border border-rose-900/60 rounded-xl p-4 flex items-center space-x-3 text-rose-300 text-xs">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Simulation Results Section */}
      {simulationResult && (
        <div className="space-y-6">
          {/* Top Metric Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Total Observed Clients */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
              <div className="text-xs font-semibold text-slate-400">
                Observed clients
              </div>
              <div className="text-3xl font-extrabold text-white mt-1 font-sans">
                {simulationResult.total_observed_clients}
              </div>
              <div className="text-xs text-slate-500 mt-1">
                Distinct endpoints in capture
              </div>
            </div>

            {/* Compatible */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm hover:border-emerald-900/50 transition">
              <div className="text-xs font-semibold text-emerald-400 flex items-center justify-between">
                <span>Compatible</span>
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="text-3xl font-extrabold text-emerald-400 mt-1 font-sans">
                {simulationResult.compatible_count}
              </div>
              <div className="text-xs text-slate-500 mt-1">
                Capability meets all policies
              </div>
            </div>

            {/* Would Break */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm hover:border-rose-900/50 transition">
              <div className="text-xs font-semibold text-rose-400 flex items-center justify-between">
                <span>Would Break</span>
                <XCircle className="w-4 h-4 text-rose-400" />
              </div>
              <div className="text-3xl font-extrabold text-rose-400 mt-1 font-sans">
                {simulationResult.would_break_count}
              </div>
              <div className="text-xs text-slate-500 mt-1">
                Confirmed incompatibility
              </div>
            </div>

            {/* Unknown */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm hover:border-amber-900/50 transition">
              <div className="text-xs font-semibold text-amber-400 flex items-center justify-between">
                <span>Unknown</span>
                <HelpCircle className="w-4 h-4 text-amber-400" />
              </div>
              <div className="text-3xl font-extrabold text-amber-400 mt-1 font-sans">
                {simulationResult.unknown_count}
              </div>
              <div className="text-xs text-slate-500 mt-1">
                Insufficient trace evidence
              </div>
            </div>
          </div>

          {/* Potential Security Improvement Box */}
          <div className="bg-gradient-to-r from-sky-950/30 via-slate-900 to-indigo-950/20 border border-sky-800/40 rounded-xl p-5 shadow-sm">
            <div className="flex items-start space-x-3">
              <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/30 shrink-0 mt-0.5">
                <Sparkles className="w-4 h-4" />
              </div>
              <div className="space-y-1">
                <h4 className="text-xs font-bold text-sky-300 uppercase tracking-wider">
                  Potential Security Improvement
                </h4>
                <p className="text-xs text-slate-200 leading-relaxed font-sans">
                  {simulationResult.potential_security_improvement}
                </p>
                <div className="text-xs text-slate-400 pt-1 flex items-center space-x-2">
                  <span>Tested against:</span>
                  <div className="flex flex-wrap gap-1">
                    {simulationResult.policy_names.map((name, idx) => (
                      <span key={idx} className="bg-slate-950 px-2 py-0.5 rounded text-sky-300 border border-slate-800 text-[11px]">
                        {name}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Observed Clients Table */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800 gap-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                  <span>Observed Client Assessment</span>
                  <span className="text-xs font-normal text-slate-400">
                    ({filteredClients.length} of {simulationResult.clients.length})
                  </span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Breakdown of client compatibility based on captured cryptographic capabilities.
                </p>
              </div>

              {/* Outcome Filter */}
              <div className="flex items-center space-x-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
                {['ALL', 'COMPATIBLE', 'WOULD_BREAK', 'UNKNOWN'].map((out) => (
                  <button
                    key={out}
                    onClick={() => setFilterOutcome(out)}
                    className={`px-2.5 py-1 rounded transition text-xs font-medium ${
                      filterOutcome === out
                        ? 'bg-sky-500 text-slate-950 font-semibold shadow-sm'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                    }`}
                  >
                    {out === 'ALL' ? 'All' : out === 'WOULD_BREAK' ? 'Would Break' : out === 'COMPATIBLE' ? 'Compatible' : 'Unknown'}
                  </button>
                ))}
              </div>
            </div>

            {/* Client List */}
            <div className="space-y-3">
              {filteredClients.map((client: ClientSimulationResult) => {
                const isExpanded = expandedClients[client.client_id] ?? client.outcome === "WOULD_BREAK";
                const offers = investigation.observed_clients?.find(c=>c.client_id===client.client_id);
                return (
                  <div
                    key={client.client_id}
                    className={`border rounded-xl transition overflow-hidden ${
                      client.outcome === 'COMPATIBLE'
                        ? 'bg-slate-950/50 border-slate-800 hover:border-emerald-900/50'
                        : client.outcome === 'WOULD_BREAK'
                        ? 'bg-rose-950/40 border-rose-500 border-l-4'
                        : 'bg-slate-950/50 border-slate-800 hover:border-amber-900/50'
                    }`}
                  >
                    {/* Main Row */}
                    <div
                      onClick={() => toggleClientExpand(client.client_id)}
                      className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 cursor-pointer hover:bg-slate-900/50 transition"
                    >
                      <div className="flex items-start md:items-center space-x-3">
                        <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 font-mono text-xs shrink-0">
                          {client.protocol}
                        </div>
                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="text-sm font-bold text-white font-mono">
                              {client.endpoint}
                            </span>
                            <span className="text-xs text-slate-500 font-mono">
                              ({client.client_id})
                            </span>
                          </div>
                          <div className="text-xs text-slate-400 mt-0.5 line-clamp-1 font-sans">
                            {client.reason}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center space-x-3 self-end md:self-center">
                        {getConfidenceBadge(client.confidence)}
                        {getOutcomeBadge(client.outcome)}
                        <button className="p-1 rounded text-slate-400 hover:text-slate-200">
                          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>

                    <div className="px-4 pb-3 text-xs text-slate-300 break-words space-y-1">
                      <p>[{offers?.supported_tls_versions?.length?'OBSERVED':'COVERAGE_GAP'}] Offered versions: {offers?.supported_tls_versions?.join(', ')||'UNKNOWN — no ClientHello version evidence'}</p>
                      <p>[{offers?.offered_cipher_suites?.length?'OBSERVED':'COVERAGE_GAP'}] Offered ciphers: {offers?.offered_cipher_suites?.join(', ')||'UNKNOWN — no ClientHello cipher evidence'}</p>
                      <p className="text-slate-400">[RULE] Outcome applies to visible offers only.</p>
                    </div>
                    {/* Expanded Evidentiary Details */}
                    {isExpanded && (
                      <div className="p-4 bg-slate-950/90 border-t border-slate-800 space-y-3 text-xs">
                        <div className="space-y-1">
                          <span className="text-[11px] text-sky-400 font-bold uppercase tracking-wider block">
                            Full Evidentiary Assessment:
                          </span>
                          <p className="text-slate-200 leading-relaxed font-sans text-xs">
                            {client.reason}
                          </p>
                        </div>

                        <div className="space-y-1">
                          <span className="text-[11px] text-slate-400 font-semibold uppercase tracking-wider block">
                            Observed Capability Evidence:
                          </span>
                          <div className="space-y-1">
                            {client.evidence.map((ev, eIdx) => (
                              <div key={eIdx} className="flex items-start space-x-1.5 text-slate-300 text-xs">
                                <span className="text-sky-400 shrink-0">•</span>
                                <span><strong>[{ev.type}]</strong> {ev.field}: {JSON.stringify(ev.value)} — {ev.description}</span>
                              </div>
                            ))}
                          </div>
                        </div>

                        <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs text-slate-500">
                          <span>Evaluated against: {simulationResult.policy_names.join(', ')}</span>
                          <span className="text-slate-400">Deterministic passive evaluation</span>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}

              {filteredClients.length === 0 && (
                <div className="py-8 text-center text-slate-500 text-xs">
                  No observed clients match the selected outcome filter.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
