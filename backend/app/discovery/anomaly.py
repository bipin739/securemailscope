from typing import List, Dict, Any, Optional
import math
from app.discovery.models import (
    ObservedClientProfile,
    ClientAnomalyResult,
    AnomalyAssessment,
    AnomalyStatus,
    AnomalyPriority,
)
from app.discovery.features import build_feature_matrix
from app.discovery.explanations import generate_client_explanation, DISCLAIMER_TEXT
from app.models import Investigation

MIN_POPULATION_THRESHOLD = 5

class ClientAnomalyEngine:
    """
    Lightweight, privacy-safe offline anomaly prioritization engine.
    Uses Isolation Forest with feature scaling to rank behavioral outliers relative to the capture.
    Never declares maliciousness or replaces deterministic Phase 2 security rules.
    """
    def __init__(self, min_threshold: int = MIN_POPULATION_THRESHOLD, random_state: int = 42):
        self.min_threshold = min_threshold
        self.random_state = random_state

    def analyze(
        self,
        profiles: List[ObservedClientProfile],
        investigation: Optional[Investigation] = None,
    ) -> AnomalyAssessment:
        """
        Executes offline anomaly assessment on observed client profiles.
        Abstains gracefully if population is below the minimum threshold.
        """
        population_size = len(profiles)

        # 1. Zero client safety check
        if population_size == 0:
            return AnomalyAssessment(
                status="INSUFFICIENT_EVIDENCE",
                method="Isolation Forest (Offline Preprocessed)",
                population_size=0,
                minimum_threshold=self.min_threshold,
                results=[],
                summary_explanation="No observed email clients in this capture to analyze.",
            )

        # 2. Small sample abstention check (Critical safety requirement)
        if population_size < self.min_threshold:
            client_results: List[ClientAnomalyResult] = []
            for prof in profiles:
                client_results.append(
                    ClientAnomalyResult(
                        client_id=prof.client_id,
                        anomaly_score=0.0,
                        raw_decision_score=None,
                        priority="NORMAL",
                        explanation=(
                            f"Capture contains {population_size} observed client(s). Statistical outlier analysis "
                            f"requires a larger comparison population (minimum {self.min_threshold} observed clients)."
                        ),
                        contributing_features=[],
                        deterministic_findings=prof.deterministic_finding_ids,
                        disclaimer=DISCLAIMER_TEXT,
                    )
                )

            summary_msg = (
                f"Only {population_size} observed client{' is' if population_size == 1 else 's are'} present in this capture. "
                f"Statistical outlier analysis requires a larger comparison population (minimum {self.min_threshold} observed clients)."
            )

            return AnomalyAssessment(
                status="INSUFFICIENT_SAMPLE",
                method="Isolation Forest (Offline Preprocessed)",
                population_size=population_size,
                minimum_threshold=self.min_threshold,
                results=client_results,
                summary_explanation=summary_msg,
            )

        # 3. Check scikit-learn dependency availability
        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
        except ImportError:
            # Graceful degradation if ML dependencies are missing
            client_results = [
                ClientAnomalyResult(
                    client_id=prof.client_id,
                    anomaly_score=0.0,
                    raw_decision_score=None,
                    priority="NORMAL",
                    explanation="Scikit-learn offline anomaly module is unavailable in this environment.",
                    contributing_features=[],
                    deterministic_findings=prof.deterministic_finding_ids,
                    disclaimer=DISCLAIMER_TEXT,
                )
                for prof in profiles
            ]
            return AnomalyAssessment(
                status="UNAVAILABLE",
                method="Isolation Forest (Offline Preprocessed)",
                population_size=population_size,
                minimum_threshold=self.min_threshold,
                results=client_results,
                summary_explanation="Scikit-learn offline anomaly module is unavailable in the execution environment.",
            )

        # 4. Feature Extraction & Scaling
        client_ids, raw_matrix, dict_records = build_feature_matrix(profiles, investigation)
        X = np.array(raw_matrix, dtype=float)

        # Check if all rows are identical
        if np.all(X == X[0, :]):
            # All clients have identical feature vectors
            results = []
            for prof, d_rec in zip(profiles, dict_records):
                results.append(
                    ClientAnomalyResult(
                        client_id=prof.client_id,
                        anomaly_score=20.0,
                        raw_decision_score=0.0,
                        priority="NORMAL",
                        explanation="All observed clients in this capture exhibit identical cryptographic and transport parameters.",
                        contributing_features=[],
                        deterministic_findings=prof.deterministic_finding_ids,
                        disclaimer=DISCLAIMER_TEXT,
                    )
                )
            return AnomalyAssessment(
                status="ANALYZED",
                method="Isolation Forest (Offline Preprocessed)",
                population_size=population_size,
                minimum_threshold=self.min_threshold,
                results=results,
                summary_explanation="All observed clients exhibit uniform cryptographic and transport behavior in this capture.",
            )

        # Scale features using StandardScaler
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # 5. Fit Isolation Forest
        # Contamination set conservatively for relative prioritization
        contamination = min(0.25, max(0.1, 1.0 / population_size))
        iso_forest = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=self.random_state,
        )
        iso_forest.fit(X_scaled)
        decision_scores = iso_forest.decision_function(X_scaled)

        # 6. Normalize Scores to 0-100 Relative Attention Scores
        # Sklearn decision_function: lower score = more abnormal, higher = normal
        min_score = float(np.min(decision_scores))
        max_score = float(np.max(decision_scores))
        score_range = max_score - min_score if max_score > min_score else 1.0

        results: List[ClientAnomalyResult] = []
        review_count = 0
        high_review_count = 0

        for idx, (prof, d_rec) in enumerate(zip(profiles, dict_records)):
            raw_s = float(decision_scores[idx])
            
            # Linear inversion with fixed bounds
            rel_divergence = (max_score - raw_s) / score_range  # 0.0 (most normal) to 1.0 (most abnormal)
            
            # Map into 15.0 - 95.0 attention score range
            attention_score = round(15.0 + (rel_divergence * 75.0), 1)

            # Assign review priority
            if attention_score >= 70.0 or (prof.auth_before_tls_count > 0 and attention_score >= 55.0):
                priority: AnomalyPriority = "HIGH_REVIEW"
                high_review_count += 1
            elif attention_score >= 50.0:
                priority = "REVIEW"
                review_count += 1
            else:
                priority = "NORMAL"

            # Plain-language evidence explanation
            explanation, contributing = generate_client_explanation(
                profile=prof,
                client_features=d_rec,
                population_features=dict_records,
                priority=priority,
                anomaly_score=attention_score,
            )

            results.append(
                ClientAnomalyResult(
                    client_id=prof.client_id,
                    anomaly_score=attention_score,
                    raw_decision_score=round(raw_s, 4),
                    priority=priority,
                    explanation=explanation,
                    contributing_features=contributing,
                    deterministic_findings=prof.deterministic_finding_ids,
                    disclaimer=DISCLAIMER_TEXT,
                )
            )

        # Sort results: highest anomaly score first
        results.sort(key=lambda r: r.anomaly_score, reverse=True)

        summary_explanation = (
            f"Evaluated {population_size} observed client profile(s) across {len(X[0])} transport dimensions. "
            f"{high_review_count + review_count} client(s) surfaced for prioritized analyst review based on "
            f"statistical behavioral divergence."
        )

        return AnomalyAssessment(
            status="ANALYZED",
            method="Isolation Forest (Offline Preprocessed)",
            population_size=population_size,
            minimum_threshold=self.min_threshold,
            results=results,
            summary_explanation=summary_explanation,
        )
