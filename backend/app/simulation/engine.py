from typing import List, Dict, Optional, Set, Tuple
from app.simulation.models import (
    ObservedClientCapability,
    HardeningPolicy,
    ClientSimulationResult,
    SimulationResult,
    SimulationOutcome,
    SimulationConfidence,
    EvidenceQuality,
)
from app.simulation.policies import POLICY_REGISTRY, BasePolicyEvaluator
from app.models import Investigation, NetworkConnection
from app.analysis.evidence import Evidence

class HardeningSimulatorEngine:
    """
    Passive Hardening Impact Simulator Engine.
    Evaluates policy impact on observed clients without active network probing or server modifications.
    """
    def __init__(self, evaluators: Optional[Dict[str, BasePolicyEvaluator]] = None):
        self.evaluators = evaluators or POLICY_REGISTRY

    def extract_client_capabilities(self, investigation: Investigation) -> List[ObservedClientCapability]:
        """
        Aggregates session records from an investigation into unique observed client capability profiles.
        Groups by (protocol, client_ip) to maintain evidentiary integrity.
        """
        client_map: Dict[Tuple[str, str], Dict[str, Any]] = {}

        # Look up node mapping
        node_ip_map = {n.id: n.ip_address for n in investigation.nodes}

        for conn in investigation.connections:
            client_ip = node_ip_map.get(conn.source_node_id, conn.source_label.split('(')[-1].replace(')', '').strip())
            protocol = conn.protocol or "SMTP"
            key = (protocol, client_ip)

            if key not in client_map:
                client_map[key] = {
                    "client_id": f"{protocol}:{client_ip}",
                    "protocol": protocol,
                    "observed_ip": client_ip,
                    "observed_tls_versions": set(),
                    "supported_tls_versions": [],
                    "client_hello_offers": [],
                    "offered_groups": [],
                    "observed_cipher_suites": set(),
                    "offered_cipher_suites": [],
                    "starttls_observed": False,
                    "starttls_used": False,
                    "plaintext_observed": False,
                    "forward_secrecy_observed": False,
                    "evidence_quality": "INSUFFICIENT",
                    "evidence": [],
                    "session_count": 0,
                }

            entry = client_map[key]
            entry["session_count"] += 1

            for offer in conn.client_hello_offers:
                entry["client_hello_offers"].append(offer)
                for field in ("supported_tls_versions", "offered_cipher_suites", "offered_groups"):
                    entry[field] = sorted(set(entry[field]) | set(offer.get(field, [])))

            # TLS Version
            if conn.tls_version and conn.tls_version not in ("None", "NONE", "UNKNOWN"):
                entry["observed_tls_versions"].add(conn.tls_version)

            # Cipher Suite
            if conn.cipher_suite and conn.cipher_suite not in ("NONE (Unencrypted / Plaintext)", "UNKNOWN / Not Captured", "None"):
                entry["observed_cipher_suites"].add(conn.cipher_suite)

            # STARTTLS & Transport
            if conn.starttls_advertised:
                entry["starttls_observed"] = True
            if conn.starttls_used:
                entry["starttls_used"] = True
            if "CLEARTEXT" in conn.transport_mode.upper():
                entry["plaintext_observed"] = True
            if conn.has_pfs:
                entry["forward_secrecy_observed"] = True

            # Determine baseline evidence quality
            if entry["supported_tls_versions"] or entry["offered_cipher_suites"]:
                entry["evidence_quality"] = "STRONG"
            elif entry["observed_tls_versions"] or entry["observed_cipher_suites"]:
                entry["evidence_quality"] = "PARTIAL"
            else:
                entry["evidence_quality"] = "INSUFFICIENT"

        # Build ObservedClientCapability objects
        capabilities: List[ObservedClientCapability] = []
        for key, entry in client_map.items():
            ev_list: List[Evidence] = []
            for offer in entry["client_hello_offers"]:
                for field in ("supported_tls_versions", "offered_cipher_suites", "offered_groups"):
                    ev_list.append(Evidence(type="OBSERVED" if offer[field] else "COVERAGE_GAP", field=field,
                        value=offer[field] or "UNKNOWN", source=f"ClientHello frame {offer['frame']}",
                        description=f"{field}: {offer[field] or 'not visible'}"))
            if entry["observed_tls_versions"]:
                ev_list.append(
                    Evidence(
                        type="OBSERVED",
                        field="negotiated_tls",
                        value=list(entry["observed_tls_versions"]),
                        source="Transport Session",
                        description=f"Observed negotiated versions: {', '.join(entry['observed_tls_versions'])}",
                    )
                )
            if entry["plaintext_observed"]:
                ev_list.append(
                    Evidence(
                        type="OBSERVED",
                        field="transport_mode",
                        value="CLEARTEXT",
                        source="Transport Session",
                        description="Observed unencrypted cleartext communication.",
                    )
                )
            if entry["starttls_observed"]:
                ev_list.append(
                    Evidence(
                        type="OBSERVED",
                        field="starttls_advertised",
                        value=True,
                        source="SMTP Greeting",
                        description=f"STARTTLS advertised (Used: {'YES' if entry['starttls_used'] else 'NO'}).",
                    )
                )

            capabilities.append(
                ObservedClientCapability(
                    client_id=entry["client_id"],
                    protocol=entry["protocol"],
                    observed_ip=entry["observed_ip"],
                    observed_tls_versions=sorted(list(entry["observed_tls_versions"])),
                    supported_tls_versions=entry["supported_tls_versions"],
                    observed_cipher_suites=sorted(list(entry["observed_cipher_suites"])),
                    offered_cipher_suites=entry["offered_cipher_suites"],
                    offered_groups=entry["offered_groups"],
                    client_hello_offers=entry["client_hello_offers"],
                    starttls_observed=entry["starttls_observed"],
                    starttls_used=entry["starttls_used"],
                    plaintext_observed=entry["plaintext_observed"],
                    forward_secrecy_observed=entry["forward_secrecy_observed"],
                    evidence_quality=entry["evidence_quality"],
                    evidence=ev_list,
                    session_count=entry["session_count"],
                )
            )

        return capabilities

    def simulate(
        self,
        clients: List[ObservedClientCapability],
        policy_ids: List[str],
    ) -> SimulationResult:
        """
        Executes deterministic simulation of the selected policies against observed client capabilities.
        Applies multi-policy combination logic:
        - Any WOULD_BREAK -> client outcome is WOULD_BREAK
        - Else any UNKNOWN -> client outcome is UNKNOWN
        - Else -> client outcome is COMPATIBLE
        """
        active_policies: List[BasePolicyEvaluator] = []
        for pid in policy_ids:
            if pid in self.evaluators:
                active_policies.append(self.evaluators[pid])

        if not active_policies:
            # Fallback if no valid policies specified
            active_policies = list(self.evaluators.values())

        eval_policy_ids = [p.policy_id for p in active_policies]
        eval_policy_names = [p.name for p in active_policies]

        client_results: List[ClientSimulationResult] = []
        compatible_count = 0
        would_break_count = 0
        unknown_count = 0

        norm_clients = [
            c if isinstance(c, ObservedClientCapability) else ObservedClientCapability(**c)
            for c in clients
        ]

        for client in norm_clients:
            policy_outcomes: List[ClientSimulationResult] = [
                pol.evaluate_client(client) for pol in active_policies
            ]

            # Check if any policy results in WOULD_BREAK
            break_results = [r for r in policy_outcomes if r.outcome == "WOULD_BREAK"]
            unknown_results = [r for r in policy_outcomes if r.outcome == "UNKNOWN"]

            if break_results:
                final_outcome: SimulationOutcome = "WOULD_BREAK"
                final_confidence: SimulationConfidence = break_results[0].confidence
                reasons = [f"[{r.outcome}] {r.reason}" for r in break_results]
                final_reason = "; ".join(reasons)
                combined_evidence = [e for r in break_results for e in r.evidence]
                would_break_count += 1
            elif unknown_results:
                final_outcome = "UNKNOWN"
                final_confidence = unknown_results[0].confidence
                reasons = [f"{r.reason}" for r in unknown_results]
                final_reason = "; ".join(reasons)
                combined_evidence = [e for r in unknown_results for e in r.evidence]
                unknown_count += 1
            else:
                final_outcome = "COMPATIBLE"
                final_confidence = "HIGH"
                reasons = [r.reason for r in policy_outcomes]
                final_reason = "; ".join(reasons)
                combined_evidence = [e for r in policy_outcomes for e in r.evidence]
                compatible_count += 1

            combined_evidence.append(Evidence(type="RULE", field="policy_outcome", value=final_outcome, source="Offline policy comparison", description="Applies only to the offers visible in this capture; not a guarantee of future client behavior."))
            client_results.append(
                ClientSimulationResult(
                    client_id=client.client_id,
                    protocol=client.protocol,
                    endpoint=client.observed_ip,
                    outcome=final_outcome,
                    confidence=final_confidence,
                    reason=final_reason,
                    evidence=combined_evidence,
                )
            )

        # Formulate potential security improvement
        if len(clients) == 0:
            potential_improvement = "No observed email clients in the capture scope to evaluate."
        elif would_break_count > 0:
            potential_improvement = (
                f"Enforcing {', '.join(eval_policy_names)} would eliminate insecure legacy configurations, "
                f"but {would_break_count} client(s) require configuration upgrades before policy rollout."
            )
        elif unknown_count > 0 and compatible_count > 0:
            potential_improvement = (
                f"Enforcing {', '.join(eval_policy_names)} protects {compatible_count} verified client(s). "
                f"{unknown_count} client(s) require additional ClientHello capture evidence to confirm compatibility."
            )
        elif unknown_count > 0:
            potential_improvement = (
                f"All {unknown_count} observed client(s) require additional ClientHello handshake evidence "
                f"before predicting policy compatibility with certainty."
            )
        else:
            potential_improvement = (
                f"All {compatible_count} observed client(s) are fully compatible with {', '.join(eval_policy_names)}. "
                "Visible offers satisfy these selected checks; server configuration, authentication, and future sessions still require testing."
            )

        return SimulationResult(
            policy_ids=eval_policy_ids,
            policy_names=eval_policy_names,
            total_observed_clients=len(clients),
            compatible_count=compatible_count,
            would_break_count=would_break_count,
            unknown_count=unknown_count,
            potential_security_improvement=potential_improvement,
            clients=client_results,
        )
