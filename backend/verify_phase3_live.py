import urllib.request
import json
import os

def test_live_pipeline():
    # 1. Test policies endpoint
    req = urllib.request.Request('http://127.0.0.1:8000/api/investigations/policies')
    with urllib.request.urlopen(req) as resp:
        policies = json.loads(resp.read().decode('utf-8'))
        print("Policies returned:", len(policies), [p['id'] for p in policies])

    # 2. Analyze smtp.pcap
    boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
    pcap_path = r'C:\Users\LOQ\Downloads\smtp.pcap'
    with open(pcap_path, 'rb') as f:
        file_bytes = f.read()

    header_part = (
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="file"; filename="smtp.pcap"\r\n'
        f'Content-Type: application/vnd.tcpdump.pcap\r\n\r\n'
    ).encode('utf-8')
    footer_part = f'\r\n--{boundary}--\r\n'.encode('utf-8')
    body = header_part + file_bytes + footer_part

    req = urllib.request.Request('http://127.0.0.1:8000/api/investigations/analyze', data=body)
    req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
    with urllib.request.urlopen(req) as resp:
        inv = json.loads(resp.read().decode('utf-8'))
        print("Analyzed real pcap:", inv['filename'], "SHA256:", inv['sha256_short'])
        print("Observed clients in pcap:", len(inv.get('observed_clients', [])))
        print("Observed client summary:", inv.get('observed_clients', [])[0])

    # 3. Simulate Require TLS policy
    sim_payload = json.dumps({
        'investigation': inv,
        'policy_ids': ['SMS-POLICY-REQUIRE-TLS']
    }).encode('utf-8')
    req = urllib.request.Request('http://127.0.0.1:8000/api/investigations/simulate', data=sim_payload)
    req.add_header('Content-Type', 'application/json')
    with urllib.request.urlopen(req) as resp:
        sim_res = json.loads(resp.read().decode('utf-8'))
        print("\n--- REQUIRE TLS SIMULATION RESULT ---")
        print("Total clients:", sim_res['total_observed_clients'])
        print("Compatible:", sim_res['compatible_count'])
        print("Would Break:", sim_res['would_break_count'])
        print("Unknown:", sim_res['unknown_count'])
        print("Disclaimer:", sim_res['disclaimer'])
        print("Improvement:", sim_res['potential_security_improvement'])
        for c in sim_res['clients']:
            print(f"Client: {c['client_id']} | Outcome: {c['outcome']} | Conf: {c['confidence']}")
            print("Reason:", c['reason'])
            print("Evidence:", c['evidence'])

    # 4. Simulate Combined policies (TLS1.2 + Weak ciphers + PFS)
    sim_payload2 = json.dumps({
        'investigation': inv,
        'policy_ids': ['SMS-POLICY-TLS12', 'SMS-POLICY-NO-WEAK-CIPHER', 'SMS-POLICY-PFS']
    }).encode('utf-8')
    req2 = urllib.request.Request('http://127.0.0.1:8000/api/investigations/simulate', data=sim_payload2)
    req2.add_header('Content-Type', 'application/json')
    with urllib.request.urlopen(req2) as resp:
        sim_res2 = json.loads(resp.read().decode('utf-8'))
        print("\n--- COMBINED POLICIES SIMULATION RESULT ---")
        print("Total clients:", sim_res2['total_observed_clients'])
        print("Compatible:", sim_res2['compatible_count'])
        print("Would Break:", sim_res2['would_break_count'])
        print("Unknown:", sim_res2['unknown_count'])
        for c in sim_res2['clients']:
            print(f"Client: {c['client_id']} | Outcome: {c['outcome']} | Conf: {c['confidence']}")
            print("Reason:", c['reason'])

    # 5. Check sensitive data leakage
    full_str = json.dumps(sim_res)
    sensitive_words = ['password', 'auth plain', 'base64', 'dGVzdHVzZXI=', 'secret', 'user@domain.com']
    found_leaks = [w for w in sensitive_words if w.lower() in full_str.lower()]
    print("\nSensitive leak check in simulation response:", "CLEAN (no sensitive data)" if not found_leaks else f"LEAK: {found_leaks}")

if __name__ == '__main__':
    test_live_pipeline()
