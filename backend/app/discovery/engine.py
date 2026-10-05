from typing import List, Optional
from app.models import Investigation
from app.discovery.models import (
    ObservedClientProfile,
    DiscoverySummary,
    AnomalyAssessment,
    ClientDiscoveryResult,
)
from app.discovery.inventory import build_client_inventory
from app.discovery.anomaly import ClientAnomalyEngine

class ClientDiscoveryEngine:
    """
    Top-level orchestrator for Observed Client Discovery and AI-assisted Anomaly Prioritization.
    Maintains clean separation between deterministic findings, policy simulation, session replay,
    and client inventory discovery.
    """
    def __init__(self, anomaly_engine: Optional[ClientAnomalyEngine] = None):
        self.anomaly_engine = anomaly_engine or ClientAnomalyEngine()

    def discover(self, investigation: Investigation) -> ClientDiscoveryResult:
        """
        Executes full observed client discovery pipeline on the provided investigation.
        """
        # 1. Build deterministic client inventory
        inventory = build_client_inventory(investigation)

        # 2. Run AI anomaly assessment
        anomaly_assessment = self.anomaly_engine.analyze(inventory, investigation)

        # 3. Create mapping of client_id -> anomaly priority
        anomaly_priority_map = {r.client_id: r.priority for r in anomaly_assessment.results}

        # 4. Compute critical & high finding client sets
        critical_finding_ids = {f.id for f in investigation.findings if f.severity == "CRITICAL"}
        high_finding_ids = {f.id for f in investigation.findings if f.severity == "HIGH"}

        modern_count = sum(1 for p in inventory if p.legacy_classification == "MODERN_OBSERVED")
        legacy_count = sum(1 for p in inventory if p.legacy_classification == "LEGACY_OBSERVED")
        mixed_count = sum(1 for p in inventory if p.legacy_classification == "MIXED")
        unknown_count = sum(1 for p in inventory if p.legacy_classification == "UNKNOWN")

        critical_clients_count = sum(
            1 for p in inventory if any(fid in critical_finding_ids for fid in p.deterministic_finding_ids)
        )
        high_clients_count = sum(
            1 for p in inventory if any(fid in high_finding_ids for fid in p.deterministic_finding_ids)
        )
        cleartext_count = sum(
            1 for p in inventory if p.plaintext_session_count > 0 or any("CLEARTEXT" in m.upper() for m in p.transport_modes)
        )
        needs_review_count = sum(
            1 for p in inventory if anomaly_priority_map.get(p.client_id) in ("REVIEW", "HIGH_REVIEW")
        )

        summary = DiscoverySummary(
            observed_clients=len(inventory),
            modern_clients=modern_count,
            legacy_clients=legacy_count,
            mixed_clients=mixed_count,
            unknown_clients=unknown_count,
            clients_with_critical_findings=critical_clients_count,
            clients_with_high_findings=high_clients_count,
            cleartext_clients=cleartext_count,
            needs_review_count=needs_review_count,
            anomaly_analysis_status=anomaly_assessment.status,
        )

        return ClientDiscoveryResult(
            inventory=inventory,
            summary=summary,
            anomaly_assessment=anomaly_assessment,
        )
