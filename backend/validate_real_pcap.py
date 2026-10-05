import json
from app.ingest.validator import validate_pcap_file
from app.ingest.tshark import extract_packet_records
from app.parse.sessions import reconstruct_investigation_from_packets

pcap_path = r"C:\Users\LOQ\Downloads\smtp.pcap"
with open(pcap_path, "rb") as f:
    file_bytes = f.read()

validation = validate_pcap_file("smtp.pcap", file_bytes)
assert validation.is_valid

pkts = extract_packet_records(pcap_path)
inv = reconstruct_investigation_from_packets("smtp.pcap", validation.sha256_full, validation.sha256_short, pkts)

print("========================================")
print("SECUREMAILSCOPE REAL PCAP VALIDATION")
print("========================================")
print(f"Filename: {inv.filename}")
print(f"Data Source: {inv.data_source}")
print(f"SHA256 Short: {inv.sha256_short}")
print(f"Sessions Analyzed: {inv.summary.sessions_analyzed}")
print(f"Overall Security Posture: {inv.security_posture.status if inv.security_posture else 'N/A'}")
print("----------------------------------------")

for conn in inv.connections:
    print(f"Protocol: {conn.protocol}")
    print(f"Endpoints: {conn.source_label} -> {conn.target_label}")
    print(f"Transport: {conn.transport_mode}")
    print(f"TLS Version: {conn.tls_version}")
    print(f"STARTTLS Advertised: {conn.starttls_advertised}")
    print(f"STARTTLS Used: {conn.starttls_used}")
    print(f"Authentication Observed: {conn.auth_observed}")
    print(f"Authentication Before TLS: {conn.auth_before_tls}")

print("----------------------------------------")
print("DETERMINISTIC SECURITY FINDINGS:")
for f in inv.findings:
    print(f"[{f.severity}] {f.rule_id}: {f.title}")
    print(f"  Status: {f.status} | Confidence: {f.confidence}")
    print(f"  Plain Explanation: {f.plain_explanation}")
    print(f"  Remediation: {f.recommendation}")
    print(f"  References: {f.references}")
    print("  Evidence items:")
    for ev in f.evidence_items:
        print(f"    - [{ev.type}] {ev.field}={ev.value} ({ev.source}): {ev.description}")

inv_json = inv.model_dump_json()
sensitive_hits = [w for w in ["password", "secret", "base64", "dXNlcg=="] if w in inv_json.lower()]
print("----------------------------------------")
print(f"Sensitive Leakage Check: {'PASS (No sensitive leaks)' if not sensitive_hits else 'FAIL'}")
