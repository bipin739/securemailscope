from app.mock_data import DEMO_INVESTIGATION
from app.discovery.engine import ClientDiscoveryEngine
from app.discovery.features import build_feature_matrix, FEATURE_NAMES

def verify_live():
    engine = ClientDiscoveryEngine()
    res = engine.discover(DEMO_INVESTIGATION)

    client_ids, matrix, dict_records = build_feature_matrix(res.inventory, DEMO_INVESTIGATION)

    print("========================================")
    print("SECUREMAILSCOPE PHASE 5 LIVE VERIFICATION")
    print("========================================")
    print(f"Population Size: {len(client_ids)} observed clients")
    print(f"Feature Dimensions: {len(FEATURE_NAMES)}")
    print(f"AI Assessment Status: {res.anomaly_assessment.status}")
    print(f"Summary: {res.summary.model_dump_json(indent=2)}")
    print("----------------------------------------")
    print("FEATURE MATRIX:")
    for c_id, feats in zip(client_ids, dict_records):
        print(f"  {c_id:20} | sessions_scaled={feats['session_count_scaled']:.2f} | plaintext_ratio={feats['plaintext_ratio']:.2f} | auth_before_tls_ratio={feats['auth_before_tls_ratio']:.2f} | deprecated_tls_ratio={feats['deprecated_tls_ratio']:.2f} | weak_cipher_ratio={feats['weak_cipher_ratio']:.2f}")

    print("----------------------------------------")
    print("ANOMALY PRIORITIZATION RANKINGS:")
    for idx, r in enumerate(res.anomaly_assessment.results):
        prof = next(p for p in res.inventory if p.client_id == r.client_id)
        print(f"  {idx+1}. [{r.priority:11}] Score: {r.anomaly_score:4.1f} | Raw: {r.raw_decision_score:7.4f} | ID: {r.client_id:20} | Sessions: {prof.session_count:2} | Class: {prof.legacy_classification}")
        print(f"     Why: {r.explanation}")
        print(f"     Factors: {r.contributing_features}")
        print(f"     Findings: {r.deterministic_findings}")

    print("----------------------------------------")
    # Verify highest session count is NOT simply ranking #1
    max_session_client = max(res.inventory, key=lambda p: p.session_count)
    top_ranked_anomaly = res.anomaly_assessment.results[0]
    print(f"Client with highest session_count ({max_session_client.session_count}): {max_session_client.client_id}")
    print(f"Top ranked anomaly: {top_ranked_anomaly.client_id} (Score: {top_ranked_anomaly.anomaly_score})")

    if max_session_client.client_id != top_ranked_anomaly.client_id:
        print("Scaling Sanity Check: PASS (Session count is NOT dominating feature ranking)")
    else:
        print("Scaling Note: Top ranked client also has high volume")

if __name__ == "__main__":
    verify_live()
