from typing import List, Dict, Any, Tuple
import math
from app.discovery.models import ObservedClientProfile
from app.models import Investigation

FEATURE_NAMES = [
    "session_count_scaled",
    "plaintext_ratio",
    "tls_ratio",
    "starttls_offer_count_scaled",
    "starttls_use_ratio",
    "auth_before_tls_ratio",
    "deprecated_tls_ratio",
    "weak_cipher_ratio",
    "tls_version_diversity",
    "cipher_diversity",
    "forward_secrecy_flag",
    "security_finding_count",
    "transport_mode_diversity",
    "evidence_quality_numeric",
]

def extract_client_features(
    profile: ObservedClientProfile,
    investigation: Investigation = None,
) -> Dict[str, float]:
    """
    Extracts a privacy-safe, normalized numerical feature vector for an observed client.
    Contains zero sensitive information (no credentials, usernames, email addresses, or payloads).
    """
    total_sessions = max(1, profile.session_count)
    
    # 1. Transport Ratios
    plaintext_ratio = profile.plaintext_session_count / total_sessions
    tls_ratio = profile.tls_session_count / total_sessions
    
    # 2. STARTTLS Ratios
    adv_count = profile.starttls_advertised_count
    starttls_use_ratio = (profile.starttls_used_count / adv_count) if adv_count > 0 else 0.0
    
    # 3. Security Risk Ratios
    auth_before_tls_ratio = profile.auth_before_tls_count / total_sessions
    deprecated_tls_ratio = profile.weak_tls_count / total_sessions
    weak_cipher_ratio = profile.weak_cipher_count / total_sessions
    
    # 4. Diversity metrics
    tls_version_diversity = float(len(profile.observed_tls_versions))
    cipher_diversity = float(len(profile.observed_cipher_suites))
    transport_mode_diversity = float(len(profile.transport_modes))
    
    # 5. Forward secrecy and evidence quality
    forward_secrecy_flag = 1.0 if profile.forward_secrecy_observed else 0.0
    
    ev_score = 0.0
    if profile.evidence_quality == "STRONG":
        ev_score = 1.0
    elif profile.evidence_quality == "PARTIAL":
        ev_score = 0.5
    else:
        ev_score = 0.0

    # 6. Scaled counts to prevent large session_count from dominating all dimensions
    # Using log1p scaling for counts
    session_count_scaled = math.log1p(profile.session_count)
    starttls_offer_count_scaled = math.log1p(profile.starttls_advertised_count)
    security_finding_count = float(len(profile.deterministic_finding_ids))

    return {
        "session_count_scaled": session_count_scaled,
        "plaintext_ratio": plaintext_ratio,
        "tls_ratio": tls_ratio,
        "starttls_offer_count_scaled": starttls_offer_count_scaled,
        "starttls_use_ratio": starttls_use_ratio,
        "auth_before_tls_ratio": auth_before_tls_ratio,
        "deprecated_tls_ratio": deprecated_tls_ratio,
        "weak_cipher_ratio": weak_cipher_ratio,
        "tls_version_diversity": tls_version_diversity,
        "cipher_diversity": cipher_diversity,
        "forward_secrecy_flag": forward_secrecy_flag,
        "security_finding_count": security_finding_count,
        "transport_mode_diversity": transport_mode_diversity,
        "evidence_quality_numeric": ev_score,
    }

def build_feature_matrix(
    profiles: List[ObservedClientProfile],
    investigation: Investigation = None,
) -> Tuple[List[str], List[List[float]], List[Dict[str, float]]]:
    """
    Constructs a deterministic feature matrix from client profiles.
    Returns:
    - client_ids: List of client IDs in order
    - matrix: 2D list of float values
    - dict_records: List of feature dictionary records
    """
    client_ids: List[str] = []
    matrix: List[List[float]] = []
    dict_records: List[Dict[str, float]] = []

    for prof in profiles:
        feat_dict = extract_client_features(prof, investigation)
        client_ids.append(prof.client_id)
        dict_records.append(feat_dict)
        matrix.append([feat_dict[k] for k in FEATURE_NAMES])

    return client_ids, matrix, dict_records
