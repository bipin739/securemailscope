from typing import List, Tuple, Optional, Set, TYPE_CHECKING
from app.analysis.rules import (
    BaseSecurityRule,
    EmailSessionContext,
    RuleEvaluationResult,
    CleartextTransportRule,
    StartTLSUnusedRule,
    AuthenticationBeforeTLSRule,
    DeprecatedTLSRule,
    ModernTLSRule,
    WeakCipherRule,
    ForwardSecrecyRule,
    CoverageGapRule,
)
from app.analysis.scoring import calculate_security_posture, SecurityPosture
from app.analysis.certificate_rules import CertificateRule

if TYPE_CHECKING:
    from app.models import SecurityFinding

class SecurityAnalysisEngine:
    """
    Deterministic, explainable security analysis engine for SecureMailScope.
    Evaluates rule-based security posture from extracted session metadata.
    """
    def __init__(self, rules: Optional[List[BaseSecurityRule]] = None):
        self.rules: List[BaseSecurityRule] = rules or [
            CleartextTransportRule(),
            StartTLSUnusedRule(),
            AuthenticationBeforeTLSRule(),
            DeprecatedTLSRule(),
            ModernTLSRule(),
            WeakCipherRule(),
            ForwardSecrecyRule(),
            CoverageGapRule(),
            CertificateRule(),
        ]

    def evaluate_session(self, session: EmailSessionContext) -> List[RuleEvaluationResult]:
        """Evaluates all registered rules against a single session context."""
        results: List[RuleEvaluationResult] = []
        for rule in self.rules:
            res = rule.evaluate(session)
            if res is not None:
                results.append(res)
        return results

    def analyze_sessions(
        self, sessions: List[EmailSessionContext]
    ) -> Tuple[List["SecurityFinding"], SecurityPosture]:
        """
        Runs deterministic rule evaluations across all reconstructed session contexts.
        Deduplicates findings per rule and stream ID.
        Computes overall security posture.
        """
        from app.models import SecurityFinding

        all_evaluations: List[RuleEvaluationResult] = []
        findings: List[SecurityFinding] = []
        seen_keys: Set[Tuple[str, str]] = set()

        for sess in sessions:
            eval_results = self.evaluate_session(sess)
            for res in eval_results:
                dedup_key = (res.rule_id, sess.stream_id)
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)
                all_evaluations.append(res)

                # Formulate evidence summary string for UI compatibility
                ev_summary = (
                    "; ".join(e.description for e in res.evidence)
                    if res.evidence
                    else f"Stream {sess.stream_id} (Port {sess.server_port})"
                )

                finding = SecurityFinding(
                    id=f"FIND-{res.rule_id}-{sess.stream_id}",
                    title=res.title,
                    severity=res.severity,
                    category=res.category,
                    status=res.status,
                    confidence=res.confidence,
                    affected_connection_id=res.affected_connection_id,
                    location=res.location or f"{sess.client_ip} → {sess.server_ip}",
                    plain_explanation=res.plain_explanation,
                    why_it_matters=res.why_it_matters,
                    evidence=ev_summary,
                    evidence_items=res.evidence,
                    recommendation=res.recommendation,
                    remediation=res.remediation,
                    rule_id=res.rule_id,
                    references=res.references,
                )
                findings.append(finding)

        posture = calculate_security_posture(all_evaluations)
        return findings, posture
