export type SecuritySeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type ConnectionStatus = 'SECURE' | 'WARNING' | 'CRITICAL';
export type NodeStatus = 'secure' | 'warning' | 'critical' | 'neutral';
export type RuleStatus = 'PASS' | 'WARN' | 'FAIL' | 'UNKNOWN';
export type EvidenceType = 'OBSERVED' | 'RULE' | 'ASSUMPTION' | 'COVERAGE_GAP';
export type SecurityPostureStatus = 'CRITICAL' | 'HIGH_RISK' | 'NEEDS_ATTENTION' | 'ACCEPTABLE' | 'UNKNOWN';

export interface EvidenceItem {
  type: EvidenceType;
  field: string;
  value: any;
  source: string;
  description: string;
}

export interface SecurityPosture {
  status: SecurityPostureStatus;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  passed_checks: number;
  coverage_gaps: number;
}

export interface SummaryStats {
  sessions_analyzed: number;
  secure_sessions: number;
  warning_sessions: number;
  critical_sessions: number;
}

export interface NetworkNode {
  id: string;
  label: string;
  role: string;
  ip_address: string;
  hostname: string;
  is_external: boolean;
  security_posture: NodeStatus;
}

export interface ConnectionEvidence {
  session_id: string;
  handshake_record: string;
  cipher_suite_hex?: string;
  protocol_version_hex?: string;
  ports: string;
  packet_count: number;
}

export interface PlainLanguageExploration {
  headline: string;
  summary: string;
  why_it_matters: string;
  evidence_summary: string;
  recommended_action: string;
}

export interface NetworkConnection {
  server_key_share_group?: string|null;
  quantum_readiness?: {type:EvidenceType;severity:"INFO";classification:string;group:string|null;group_name:string|null;label:string;detail:string;frame:string|null};
  id: string;
  source_node_id: string;
  target_node_id: string;
  source_label: string;
  target_label: string;
  protocol: string;
  transport_mode: string;
  tls_version: string;
  cipher_suite: string;
  security_status: ConnectionStatus;
  session_id: string;
  has_pfs: boolean;
  has_aead: boolean;
  starttls_advertised?: boolean;
  starttls_used?: boolean;
  auth_observed?: boolean;
  auth_before_tls?: boolean;
  starttls_requested?: boolean;
  starttls_accepted?: boolean;
  server_hello_frame?: string;
  capture_gaps?: boolean;
  certificates?: {subject:string;issuer:string;sha256:string;frame:string;not_before:string;not_after:string;public_key_algorithm:string;public_key_bits:number|null;signature_hash:string;chain_status:string;chain_detail:string;issues:string[]}[];
  explanation: PlainLanguageExploration;
  evidence: ConnectionEvidence;
}

export interface Remediation {
  type: 'RULE'; steps: string[];
  snippet?: { software: string; scope: string; warning: string; config: string } | null;
}
export interface SecurityFinding {
  remediation?: Remediation;
  id: string;
  title: string;
  severity: SecuritySeverity;
  category: string;
  status?: RuleStatus;
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  affected_connection_id?: string;
  location: string;
  plain_explanation: string;
  why_it_matters: string;
  evidence: string;
  evidence_items?: EvidenceItem[];
  recommendation: string;
  rule_id: string;
  references?: string[];
}

export interface Investigation {
  fix_first?: FixFirst;
  id: string;
  filename: string;
  capture_date: string;
  status: 'completed' | 'processing' | 'failed';
  is_simulated: boolean;
  data_source?: string;
  capture_origin?: string;
  sha256_hash?: string;
  sha256_short?: string;
  analysis_engine: string;
  summary: SummaryStats;
  security_posture?: SecurityPosture;
  nodes: NetworkNode[];
  connections: NetworkConnection[];
  findings: SecurityFinding[];
  observed_clients?: ObservedClientCapability[];
  replays?: SessionReplay[];
  discovery?: ClientDiscoveryResult;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  is_simulated_mode: boolean;
  tshark_available?: boolean;
  tshark_version?: string | null;
}

export type ActiveTab = 'overview' | 'journey' | 'findings' | 'discovery' | 'replay' | 'simulator' | 'report' | 'upload';
export type UploadProgressState = 'IDLE' | 'UPLOADING' | 'ANALYSING' | 'COMPLETE' | 'FAILED';

// ==========================================
// PHASE 3: SIMULATION & CLIENT CAPABILITY TYPES
// ==========================================

export type EvidenceQuality = 'STRONG' | 'PARTIAL' | 'INSUFFICIENT';
export type ClientSimulationOutcome = 'COMPATIBLE' | 'WOULD_BREAK' | 'UNKNOWN';
export type SimulationConfidence = 'HIGH' | 'MEDIUM' | 'LOW';

export interface ObservedClientCapability {
  client_id: string;
  protocol: string;
  observed_ip: string;
  observed_tls_versions: string[];
  supported_tls_versions: string[];
  observed_cipher_suites: string[];
  offered_cipher_suites: string[];
  starttls_advertised?: boolean;
  starttls_used?: boolean;
  plaintext_observed: boolean;
  forward_secrecy_observed: boolean;
  evidence_quality: EvidenceQuality;
  evidence: string[];
}

export interface HardeningPolicy {
  id: string;
  name: string;
  description: string;
  requirements: string[];
  references: string[];
}

export interface ClientSimulationResult {
  client_id: string;
  protocol: string;
  endpoint: string;
  outcome: ClientSimulationOutcome;
  confidence: SimulationConfidence;
  reason: string;
  evidence: EvidenceItem[];
  tested_policies?: string[];
}

export interface SimulationResult {
  policy_ids: string[];
  policy_names: string[];
  total_observed_clients: number;
  compatible_count: number;
  would_break_count: number;
  unknown_count: number;
  clients: ClientSimulationResult[];
  potential_security_improvement: string;
  disclaimer: string;
}

// ==========================================
// PHASE 4: VISUAL SECURITY SESSION REPLAY TYPES
// ==========================================

export type EventSecurityState = 'NEUTRAL' | 'SECURE' | 'WARNING' | 'CRITICAL' | 'UNKNOWN';
export type EventDirection = 'CLIENT_TO_SERVER' | 'SERVER_TO_CLIENT' | 'INTERNAL';

export interface SecurityEvent {
  event_id: string;
  session_id: string;
  timestamp?: string | null;
  relative_time_ms: number;
  direction: EventDirection;
  event_type: string;
  title: string;
  description: string;
  transport_state: string;
  security_state: EventSecurityState;
  evidence_source: string;
  related_rule_ids: string[];
  metadata: Record<string, any>;
}

export interface CriticalMoment {
  event_id: string;
  title: string;
  reason: string;
  rule_id: string;
  severity: string;
}

export interface ReplaySummary {
  session_id: string;
  protocol: string;
  client_endpoint: string;
  server_endpoint: string;
  started_at: string;
  duration_ms: number;
  initial_transport: string;
  final_transport: string;
  event_count: number;
  highest_security_state: EventSecurityState;
  critical_event_id?: string | null;
  critical_event_title?: string | null;
  related_findings: string[];
}

export interface SessionReplay {
  session_id: string;
  protocol: string;
  summary: ReplaySummary;
  critical_moment?: CriticalMoment | null;
  events: SecurityEvent[];
}

// ==========================================
// PHASE 5: OBSERVED CLIENT DISCOVERY & AI ANOMALY TYPES
// ==========================================

export type LegacyClassification = 'MODERN_OBSERVED' | 'LEGACY_OBSERVED' | 'MIXED' | 'UNKNOWN';
export type IndicatorSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AnomalyPriority = 'NORMAL' | 'REVIEW' | 'HIGH_REVIEW';
export type AnomalyStatus = 'ANALYZED' | 'INSUFFICIENT_SAMPLE' | 'INSUFFICIENT_EVIDENCE' | 'UNAVAILABLE';

export interface ClientIndicator {
  indicator_id: string;
  title: string;
  severity: IndicatorSeverity;
  description: string;
  evidence: string;
  related_rule_ids: string[];
}

export interface ObservedClientProfile {
  client_id: string;
  protocol: string;
  observed_ip: string;
  session_count: number;
  first_seen: string;
  last_seen: string;
  transport_modes: string[];
  observed_tls_versions: string[];
  supported_tls_versions: string[];
  observed_cipher_suites: string[];
  offered_cipher_suites: string[];
  starttls_advertised_count: number;
  starttls_used_count: number;
  plaintext_session_count: number;
  tls_session_count: number;
  auth_before_tls_count: number;
  weak_tls_count: number;
  weak_cipher_count: number;
  forward_secrecy_observed: boolean;
  evidence_quality: string;
  legacy_classification: LegacyClassification;
  deterministic_finding_ids: string[];
  replay_session_ids: string[];
  indicators: ClientIndicator[];
  ja3_fingerprint?: string | null;
  ja3_fingerprints?: string[];
  ja3_evidence?: EvidenceItem[];
}

export interface ClientAnomalyResult {
  client_id: string;
  anomaly_score: number;
  raw_decision_score?: number | null;
  priority: AnomalyPriority;
  explanation: string;
  contributing_features: string[];
  deterministic_findings: string[];
  disclaimer: string;
}

export interface AnomalyAssessment {
  status: AnomalyStatus;
  method: string;
  population_size: number;
  minimum_threshold: number;
  results: ClientAnomalyResult[];
  summary_explanation: string;
}

export interface DiscoverySummary {
  observed_clients: number;
  modern_clients: number;
  legacy_clients: number;
  mixed_clients: number;
  unknown_clients: number;
  clients_with_critical_findings: number;
  clients_with_high_findings: number;
  cleartext_clients: number;
  needs_review_count: number;
  anomaly_analysis_status: AnomalyStatus;
}

export interface ClientDiscoveryResult {
  inventory: ObservedClientProfile[];
  summary: DiscoverySummary;
  anomaly_assessment: AnomalyAssessment;
}

// ==========================================
// PHASE 6: EVIDENCE REPORTING & INTEGRITY TYPES
// ==========================================

export interface ReportMetadata {
  report_id: string;
  investigation_id: string;
  generated_at: string;
  engine_name: string;
  engine_version: string;
  schema_version: string;
  data_source: string;
  is_simulated: boolean;
}

export interface CaptureSummary {
  filename: string;
  capture_sha256: string;
  capture_sha256_short: string;
  capture_date: string;
  total_sessions: number;
  secure_sessions: number;
  warning_sessions: number;
  critical_sessions: number;
  observed_clients_count: number;
  protocols_observed: string[];
}

export interface ExecutiveSummary {
  headline: string;
  overall_posture: string;
  posture_summary: string;
  key_findings_summary: string;
  transport_security_summary: string;
  ai_anomaly_summary: string;
  full_text: string;
}

export interface ReportFinding {
  remediation?: Remediation;
  rule_id: string;
  title: string;
  severity: SecuritySeverity;
  status: RuleStatus;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  location: string;
  plain_explanation: string;
  why_it_matters: string;
  evidence: string;
  evidence_items?: EvidenceItem[];
  recommendation: string;
  references: string[];
  affected_connection_id?: string;
  related_session_id?: string;
  related_replay_event?: string;
}

export interface ReportRecommendation {
  priority_rank: number;
  rule_id: string;
  severity: SecuritySeverity;
  action: string;
  rationale: string;
  policy_bridge?: string;
}

export interface SecurityReplaySummaryItem {
  session_id: string;
  protocol: string;
  endpoints: string;
  event_count: number;
  highest_security_state: string;
  critical_moment?: string;
}

export interface HardeningImpactReportSummary {
  available_policies_count: number;
  tested_policies: string[];
  summary_notes: string;
  recommendation: string;
  client_compatibility_overview: {
    COMPATIBLE?: number;
    WOULD_BREAK?: number;
    UNKNOWN?: number;
  };
}

export interface ClientDiscoveryReportSummary {
  total_observed_clients: number;
  modern_count: number;
  legacy_count: number;
  mixed_count: number;
  unknown_count: number;
  cleartext_clients_count: number;
  clients_with_critical_findings: number;
}

export interface AIAssistedPrioritizationSummary {
  status: AnomalyStatus;
  method: string;
  population_size: number;
  minimum_threshold: number;
  summary_explanation: string;
  top_prioritized_clients: {
    client_id: string;
    anomaly_score: number;
    priority: AnomalyPriority;
    explanation: string;
    contributing_features: string[];
  }[];
  disclaimer: string;
}

export interface EvidenceManifest {
  schema_version: string;
  investigation_id: string;
  source_filename: string;
  capture_sha256: string;
  generated_at: string;
  data_source: string;
  engine_version: string;
  session_count: number;
  finding_count: number;
  replay_count: number;
  observed_client_count: number;
  findings_digest: string;
  replay_digest: string;
  discovery_digest: string;
  simulation_digest: string;
  evidence_root: string;
  report_digest: string;
  integrity_algorithm: string;
  integrity_status: 'VERIFIED' | 'TAMPERED' | 'UNVERIFIED';
  verification_statement: string;
}

export interface InvestigationReport {
  fix_first?: FixFirst;
  report_metadata: ReportMetadata;
  executive_summary: ExecutiveSummary;
  capture_summary: CaptureSummary;
  security_posture: SecurityPosture;
  deterministic_findings: ReportFinding[];
  security_replay_summary: SecurityReplaySummaryItem[];
  hardening_impact_summary: HardeningImpactReportSummary;
  client_discovery_summary: ClientDiscoveryReportSummary;
  ai_assisted_prioritization: AIAssistedPrioritizationSummary;
  evidence_manifest: EvidenceManifest;
  limitations: string[];
  privacy_statement: string;
  recommendations: ReportRecommendation[];
}

export interface IntegrityVerificationResult {
  is_valid: boolean;
  status: 'VERIFIED' | 'TAMPERED' | 'UNVERIFIED';
  verification_statement: string;
  algorithm: string;
  evidence_root: string;
  report_digest: string;
  mismatches: string[];
}



export interface FixFirst {
  type: 'RULE'; label: string; weights: {severity:number; affected_sessions:number; anomaly_tiebreak:number};
  severity_values: Record<string,number>; anomaly_population:number; anomaly_status:string; formula:string;
  rows: {rank:number;rule_id:string;title:string;severity:SecuritySeverity;finding_ids:string[];client_ids:string[];affected_sessions:number;anomaly_rank:number|null;ordering_points:number}[];
}
