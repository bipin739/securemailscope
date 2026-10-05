from typing import List, Dict, Any, Tuple
from app.discovery.models import ObservedClientProfile, AnomalyPriority

DISCLAIMER_TEXT = (
    "AI ranking is relative to clients in this capture and indicates statistical outlier behavior, "
    "not maliciousness or security certainty."
)

FEATURE_HUMAN_LABELS = {
    "plaintext_ratio": "Cleartext session ratio",
    "tls_ratio": "Encrypted session ratio",
    "auth_before_tls_ratio": "Cleartext authentication ratio",
    "deprecated_tls_ratio": "Deprecated TLS version ratio",
    "weak_cipher_ratio": "Weak cipher suite ratio",
    "starttls_use_ratio": "STARTTLS upgrade ratio",
    "session_count_scaled": "Session volume",
    "tls_version_diversity": "TLS version variations",
    "cipher_diversity": "Cipher suite variations",
    "forward_secrecy_flag": "Forward secrecy support",
    "security_finding_count": "Triggered security findings",
    "transport_mode_diversity": "Transport mode variety",
    "evidence_quality_numeric": "Handshake evidence depth",
}

def generate_client_explanation(
    profile: ObservedClientProfile,
    client_features: Dict[str, float],
    population_features: List[Dict[str, float]],
    priority: AnomalyPriority,
    anomaly_score: float,
) -> Tuple[str, List[str]]:
    """
    Generates an evidence-backed, human-readable explanation of why this client profile
    was prioritized or categorized by the statistical anomaly model.
    Never invents attacks, assumes maliciousness, or identifies humans.
    """
    if not population_features or len(population_features) < 2:
        return (
            "Baseline client profile recorded. Insufficient capture population for comparative outlier analysis.",
            [],
        )

    # Compute population averages
    keys = list(client_features.keys())
    pop_avg: Dict[str, float] = {}
    for k in keys:
        vals = [f[k] for f in population_features if k in f]
        pop_avg[k] = sum(vals) / len(vals) if vals else 0.0

    # Calculate absolute differences from capture mean
    diffs: List[Tuple[str, float, float]] = []
    for k in keys:
        val = client_features.get(k, 0.0)
        avg = pop_avg.get(k, 0.0)
        diff = abs(val - avg)
        diffs.append((k, diff, val - avg))

    # Sort top differing features
    diffs.sort(key=lambda x: x[1], reverse=True)
    top_diff_keys = [d[0] for d in diffs if d[1] > 0.05][:3]
    contributing_labels = [FEATURE_HUMAN_LABELS.get(k, k) for k in top_diff_keys]

    # Formulate contextual plain-language justification
    reasons: List[str] = []

    if profile.auth_before_tls_count > 0:
        reasons.append(
            "this client is one of the few observed endpoints transmitting authentication before TLS encryption"
        )
    elif profile.weak_tls_count > 0:
        reasons.append(
            f"this client negotiated deprecated {', '.join(profile.observed_tls_versions)} while the majority used modern TLS 1.2+"
        )
    elif profile.weak_cipher_count > 0:
        reasons.append(
            "this client negotiated obsolete cipher suites (e.g. 3DES / RC4) differing from the standard capture baseline"
        )
    elif profile.plaintext_session_count > 0 and profile.starttls_advertised_count > 0 and profile.starttls_used_count == 0:
        reasons.append(
            "this client continued in cleartext despite the mail server offering STARTTLS capability"
        )
    elif profile.plaintext_session_count > 0 and profile.tls_session_count > 0:
        reasons.append(
            "this client exhibited mixed transport behavior, alternating between TLS encryption and cleartext"
        )
    elif priority in ("REVIEW", "HIGH_REVIEW"):
        if "forward_secrecy_flag" in top_diff_keys and not profile.forward_secrecy_observed:
            reasons.append("this client negotiated non-forward-secret cipher suites unlike most captured peers")
        elif "cipher_diversity" in top_diff_keys or "tls_version_diversity" in top_diff_keys:
            reasons.append("this client utilizes an uncommon TLS or cipher suite configuration within this capture")
        else:
            reasons.append("observed transport parameters statistically diverge from the predominant capture profile")

    if reasons:
        explanation = f"Prioritized for analyst review because {'; '.join(reasons)}."
    elif priority == "NORMAL":
        explanation = "Observed transport and cryptographic parameters align with the predominant baseline profile in this capture."
    else:
        explanation = "Observed transport configuration shows minor statistical variance from the capture average."

    return explanation, contributing_labels
