"""Re-run every supplied PCAP through the real parser; save measured results."""
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.ingest.tshark import extract_packet_records, get_tshark_version
from app.parse.sessions import reconstruct_investigation_from_packets
from app.reporting.report_builder import build_investigation_report
from app.reporting.integrity import verify_report_manifest
from app.reporting.exporters import export_report_to_html,export_report_to_json
from app.reporting.pdf_export import export_pdf
from app.simulation.engine import HardeningSimulatorEngine

root=Path(__file__).resolve().parents[2]
out=root/'validation';out.mkdir(exist_ok=True)
manifest=json.loads((root/'sample-captures'/'manifest.json').read_text())
results=[]
for case in manifest:
    file=root/'sample-captures'/case['filename'];sha=hashlib.sha256(file.read_bytes()).hexdigest()
    records=extract_packet_records(str(file));inv=reconstruct_investigation_from_packets(file.name,sha,sha[:12],records)
    inv.capture_origin='SYNTHETIC_LAB'
    expected=case['expected'];rules={f.rule_id for f in inv.findings}
    checks=[sha==case['sha256'],len(inv.connections)==expected.get('sessions',1),set(expected.get('rules',[]))<=rules,not set(expected.get('forbidden_rules',[]))&rules]
    if inv.connections:
        c=inv.connections[0]
        for key,actual in [('protocol',c.protocol),('tls',c.tls_version),('cipher',c.cipher_suite),('starttls',c.starttls_used),('certificates',len(c.certificates))]:
            if key in expected:checks.append(actual==expected[key])
        if 'certificate_issue' in expected:checks.append(expected['certificate_issue'] in c.certificates[0]['issues'])
    simulation=HardeningSimulatorEngine().simulate(inv.observed_clients,['SMS-POLICY-TLS12','SMS-POLICY-NO-WEAK-CIPHER'])
    counts=dict(COMPATIBLE=simulation.compatible_count,WOULD_BREAK=simulation.would_break_count,UNKNOWN=simulation.unknown_count)
    if 'simulation_counts' in expected:checks.append(counts==expected['simulation_counts'])
    result=dict(simulation_counts=counts,filename=file.name,sha256=sha,passed=all(checks),expected=expected,
                sessions=len(inv.connections),posture=inv.security_posture.status,
                negotiated_tls=sorted({c.tls_version for c in inv.connections}),
                protocols=sorted({c.protocol for c in inv.connections}),
                findings=[dict(rule_id=f.rule_id,status=f.status,severity=f.severity) for f in inv.findings],
                ai_status=inv.discovery.anomaly_assessment.status if inv.discovery else 'NO_CLIENTS')
    results.append(result)
    if file.name in ('lab-mixed-fleet.pcap','lab-expired-certificate.pcap','lab-legacy-clients-offer.pcap'):
        report=build_investigation_report(inv)
        assert verify_report_manifest(report)['is_valid']
        stem=file.stem
        (out/(stem+'-investigation.json')).write_text(inv.model_dump_json(indent=2),encoding='utf-8')
        (out/(stem+'-report.json')).write_text(export_report_to_json(report),encoding='utf-8')
        (out/(stem+'-report.html')).write_text(export_report_to_html(report),encoding='utf-8')
        if file.name=='lab-expired-certificate.pcap':(out/'example-forensic-report.pdf').write_bytes(export_pdf(inv,report))
summary=dict(generated_at=dt.datetime.now(dt.timezone.utc).isoformat(),tshark_version=get_tshark_version(),
             origin='Synthetic lab fixtures, not production or public benchmark traffic',passed=sum(r['passed'] for r in results),total=len(results),results=results)
(out/'capture-results.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
lines=['# Measured capture validation','',f"{summary['passed']}/{summary['total']} byte-level scenarios passed.",'',summary['origin'],f"TShark: {summary['tshark_version']}",'', '| Capture | Sessions | TLS observed | Posture | Result |','|---|---:|---|---|---|']
for r in results:lines.append(f"| {r['filename']} | {r['sessions']} | {', '.join(r['negotiated_tls']) or 'none'} | {r['posture']} | {'PASS' if r['passed'] else 'FAIL'} |")
lines+=['','The JSON companion records expected values, actual findings and each input SHA-256. Trust tests are in pytest; default capture validation does not implicitly trust the lab CA.','', 'Regenerate captures with `python tools/generate_captures.py`. OpenSSL generates fresh random handshakes and keys, so hashes change; the manifest is regenerated alongside them. Scenario assertions remain stable.']
(out/'CAPTURE_RESULTS.md').write_text('\n'.join(lines),encoding='utf-8')
print(f"{summary['passed']}/{summary['total']} capture scenarios passed; reports saved to {out}")
if not all(r['passed'] for r in results):sys.exit(1)
