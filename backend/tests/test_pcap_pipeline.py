"""Independent byte-level regression: PCAP -> TShark -> assessment -> API."""
import hashlib
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.ingest.tshark import extract_packet_records, is_tshark_available
from app.parse.sessions import reconstruct_investigation_from_packets

SAMPLES=Path(__file__).resolve().parents[2]/'sample-captures'
CASES=json.loads((SAMPLES/'manifest.json').read_text())


@pytest.mark.skipif(not is_tshark_available(),reason='TShark required for byte-level packet tests')
@pytest.mark.parametrize('case',CASES,ids=[c['filename'] for c in CASES])
def test_actual_packet_capture(case):
    path=SAMPLES/case['filename'];sha=hashlib.sha256(path.read_bytes()).hexdigest()
    assert sha==case['sha256'],'Fixture manifest does not match capture bytes'
    records=extract_packet_records(str(path))
    inv=reconstruct_investigation_from_packets(path.name,sha,sha[:12],records)
    exp=case['expected'];rules={f.rule_id for f in inv.findings}
    assert not inv.is_simulated and inv.sha256_hash==sha
    assert len(inv.connections)==exp.get('sessions',1)
    assert set(exp.get('rules',[])) <= rules
    assert not set(exp.get('forbidden_rules',[])) & rules
    if inv.connections:
        c=inv.connections[0]
        if 'protocol' in exp:assert c.protocol==exp['protocol']
        if 'tls' in exp:assert c.tls_version==exp['tls']
        if exp.get('tls')=='UNKNOWN':assert inv.replays[0].summary.final_transport=='UNKNOWN'
        if 'cipher' in exp:assert c.cipher_suite==exp['cipher']
        if 'starttls' in exp:assert c.starttls_used==exp['starttls']
        if 'certificates' in exp:assert len(c.certificates)==exp['certificates']
        if 'certificate_issue' in exp:assert exp['certificate_issue'] in c.certificates[0]['issues']
        assert inv.capture_date.startswith('2026-10-04')
    if 'protocols' in exp:assert set(exp['protocols'])=={c.protocol for c in inv.connections}
    # Synthetic credentials must not appear anywhere in exported investigation.
    serialized=inv.model_dump_json()
    assert 'AHN5bnRoZXRpYwBkdW1teQ==' not in serialized
    assert 'PASS dummy' not in serialized
    assert 'LOGIN synthetic dummy' not in serialized


def test_upload_rejects_bad_extension_and_malformed_capture():
    client=TestClient(app)
    assert client.post('/api/investigations/analyze',files={'file':('bad.exe',b'bad')}).status_code==400
    assert client.post('/api/investigations/analyze',files={'file':('bad.pcap',b'x'*30)}).status_code==400


@pytest.mark.skipif(not is_tshark_available(),reason='TShark required')
def test_upload_report_and_tamper_detection():
    client=TestClient(app)
    path=SAMPLES/'lab-mixed-fleet.pcap'
    response=client.post('/api/investigations/analyze',files={'file':(path.name,path.read_bytes(),'application/octet-stream')})
    assert response.status_code==200,response.text
    inv=response.json()
    assert inv['summary']['sessions_analyzed']==8
    report=client.post('/api/investigations/report',json=inv)
    assert report.status_code==200,report.text
    assert client.post('/api/investigations/report/verify',json=report.json()).status_code==200
    verification=client.post('/api/investigations/report/verify',json=report.json()).json()
    assert verification['is_valid'] is True
    def browser_numbers(value):
        if isinstance(value,dict):return {k:browser_numbers(v) for k,v in value.items()}
        if isinstance(value,list):return [browser_numbers(v) for v in value]
        if isinstance(value,float) and value.is_integer():return int(value)
        return value
    browser_report=browser_numbers(report.json())
    assert client.post('/api/investigations/report/verify',json=browser_report).json()['is_valid'] is True
    tampered=report.json();tampered['deterministic_findings'][0]['title']='Modified evidence'
    assert client.post('/api/investigations/report/verify',json=tampered).json()['is_valid'] is False
    for fmt in ('json','html','pdf'):
        result=client.post('/api/investigations/report/export/'+fmt,json=inv)
        assert result.status_code==200 and len(result.content)>1000
        if fmt=='pdf':assert result.content.startswith(b'%PDF-')


def test_explicit_lab_trust_store(monkeypatch):
    monkeypatch.setenv('SMS_TRUST_STORE',str(SAMPLES/'lab-root-ca.pem'))
    path=SAMPLES/'lab-ca-signed-tls12.pcap'
    records=extract_packet_records(str(path))
    inv=reconstruct_investigation_from_packets(path.name,'a'*64,'a'*12,records)
    assert inv.connections[0].certificates[0]['chain_status']=='PASS'
    assert inv.summary.secure_sessions==1
    assert inv.security_posture.status=='ACCEPTABLE'


def test_missing_trust_store_stays_unknown(monkeypatch):
    monkeypatch.setenv('SMS_TRUST_STORE',str(SAMPLES/'missing-root.pem'))
    path=SAMPLES/'lab-ca-signed-tls12.pcap'
    inv=reconstruct_investigation_from_packets(path.name,'b'*64,'b'*12,extract_packet_records(str(path)))
    assert inv.connections[0].certificates[0]['chain_status']=='UNKNOWN'
    assert inv.summary.secure_sessions==0


def test_hostname_mismatch_fails_trusted_path(monkeypatch):
    monkeypatch.setenv('SMS_TRUST_STORE',str(SAMPLES/'lab-root-ca.pem'))
    path=SAMPLES/'lab-ca-signed-tls12.pcap'
    records=extract_packet_records(str(path))
    for record in records:
        if record.get('tls.handshake.extensions_server_name'):
            record['tls.handshake.extensions_server_name']='wrong.sih.test'
    inv=reconstruct_investigation_from_packets(path.name,'c'*64,'c'*12,records)
    assert inv.connections[0].certificates[0]['chain_status']=='FAIL'
    assert inv.summary.secure_sessions==0


def test_greeting_only_is_incomplete_not_plaintext_failure():
    records=[{'frame.number':'1','tcp.stream':'0','ip.src':'192.0.2.1','ip.dst':'198.51.100.25',
              'tcp.srcport':'49100','tcp.dstport':'587','smtp.req.command':'EHLO'}]
    inv=reconstruct_investigation_from_packets('partial.pcap','d'*64,'d'*12,records)
    assert inv.connections[0].tls_version=='UNKNOWN'
    assert not any(f.rule_id=='SMS-TLS-001' for f in inv.findings)
