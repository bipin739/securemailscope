import hashlib
from pathlib import Path
import pytest
from app.ingest.tshark import extract_packet_records
from app.parse.sessions import reconstruct_investigation_from_packets
from app.parse.client_hello import extract_client_hellos
from app.simulation.engine import HardeningSimulatorEngine
from app.simulation.models import ObservedClientCapability

SAMPLES = Path(__file__).resolve().parents[2] / 'sample-captures'
POLICIES = ['SMS-POLICY-TLS12', 'SMS-POLICY-NO-WEAK-CIPHER']


@pytest.fixture(scope='module')
def legacy_investigation():
    path = SAMPLES / 'lab-legacy-clients-offer.pcap'
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    inv = reconstruct_investigation_from_packets(path.name, sha, sha[:12], extract_packet_records(str(path)))
    inv.capture_origin = 'SYNTHETIC_LAB'
    return inv


def test_offer_capture_simulation_counts(legacy_investigation):
    inv = legacy_investigation
    result = HardeningSimulatorEngine().simulate(inv.observed_clients, POLICIES)
    assert (result.compatible_count, result.would_break_count, result.unknown_count) == (2, 2, 1)
    broken = [c for c in result.clients if c.outcome == 'WOULD_BREAK']
    assert {c.endpoint for c in broken} == {'192.0.2.23', '192.0.2.24'}
    assert all(any(e.type == 'OBSERVED' and isinstance(e.value, list) for e in c.evidence) for c in broken)
    assert all(any(e.type == 'RULE' for e in c.evidence) for c in result.clients)
    assert any(c.offered_groups for c in inv.discovery.inventory)
    assert inv.discovery.inventory[-1].client_hello_offers == []


def test_missing_hello_stays_unknown_despite_server_selection():
    c = ObservedClientCapability(client_id='SMTP:test', observed_ip='test',
        observed_tls_versions=['TLS 1.3'], observed_cipher_suites=['TLS_AES_128_GCM_SHA256'])
    result = HardeningSimulatorEngine().simulate([c], POLICIES)
    assert result.unknown_count == 1
    assert any(e.type == 'COVERAGE_GAP' for e in result.clients[0].evidence)


def test_client_hello_legacy_compatibility_grease_and_signalling():
    p = {'ip.src':'192.0.2.1','tcp.srcport':'50000','tls.handshake.type':'1',
         'tls.handshake.version':'0x0303','tls.handshake.extensions.supported_version':'0x0304,0x0a0a',
         'tls.handshake.ciphersuite':'0x1301,0x00ff,0x5600,0x0a0a'}
    offer = extract_client_hellos([p], '192.0.2.1', 50000)[0]
    assert offer['supported_tls_versions'] == ['TLS 1.3']
    assert offer['legacy_version'] == 'TLS 1.2'
    assert offer['offered_cipher_suites'] == ['TLS_AES_128_GCM_SHA256']
    assert extract_client_hellos([dict(p, **{'tls.handshake.type':'2'})], '192.0.2.1', 50000) == []


def test_unknown_offers_do_not_prove_compatibility_or_failure():
    c = ObservedClientCapability(client_id='SMTP:test', observed_ip='test',
        supported_tls_versions=['0x9999'], offered_cipher_suites=['UNKNOWN (0xbeef)'])
    assert HardeningSimulatorEngine().simulate([c], POLICIES).unknown_count == 1


def test_every_registered_rule_has_remediation(legacy_investigation):
    from app.analysis.engine import SecurityAnalysisEngine
    from app.analysis.rules import EmailSessionContext
    engine=SecurityAnalysisEngine()
    cases=[dict(tls_version='None',transport_mode='CLEARTEXT',auth_before_tls=True,auth_observed=True,starttls_advertised=True),
           dict(tls_version='TLS 1.0',cipher_suite='TLS_RSA_WITH_3DES_EDE_CBC_SHA'),
           dict(tls_version='TLS 1.3',cipher_suite='TLS_AES_128_GCM_SHA256',has_pfs=True),dict(tls_version='UNKNOWN')]
    seen=set()
    for case in cases:
        context=dict(stream_id='t',client_ip='c',server_ip='s',client_port=50000,server_port=587,transport_mode='TLS')
        context.update(case)
        for result in engine.evaluate_session(EmailSessionContext(**context)):
            seen.add(result.rule_id)
            assert result.remediation.type=='RULE' and result.remediation.steps
            if result.status in ('UNKNOWN','PASS'):assert result.remediation.snippet is None
    assert {r.rule_id for r in engine.rules}<=seen


def test_remediation_reports_and_tamper_detection(legacy_investigation):
    import json
    from app.reporting.report_builder import build_investigation_report
    from app.reporting.integrity import verify_report_manifest
    from app.reporting.exporters import export_report_to_html,export_report_to_json
    from app.reporting.pdf_export import export_pdf
    report=build_investigation_report(legacy_investigation)
    assert all(f.remediation and f.remediation.steps for f in report.deterministic_findings)
    finding=next(f for f in report.deterministic_findings if f.rule_id=='SMS-TLSVER-001')
    assert finding.remediation.snippet.software.startswith('Postfix 3.6+')
    assert 'authenticated submission only' in finding.remediation.snippet.scope
    assert 'smtpd_tls_mandatory_protocols = >=TLSv1.2' in finding.remediation.snippet.config
    html=export_report_to_html(report)
    assert 'Review and test before applying' in html and '&gt;=TLSv1.2' in html
    assert json.loads(export_report_to_json(report))['deterministic_findings'][0]['remediation']['type']=='RULE'
    assert export_pdf(legacy_investigation,report).startswith(b'%PDF-')
    assert verify_report_manifest(report)['is_valid']
    finding.remediation.steps[0]='tampered recommendation'
    assert not verify_report_manifest(report)['is_valid']


def test_ja3_is_observed_client_hello_only(legacy_investigation):
    import re
    profiles=legacy_investigation.discovery.inventory
    assert len([p for p in profiles if p.ja3_fingerprint])==4
    assert all(re.fullmatch('[0-9a-f]{32}',p.ja3_fingerprint) for p in profiles if p.ja3_fingerprint)
    unknown=next(p for p in profiles if p.observed_ip=='192.0.2.25')
    assert unknown.ja3_fingerprint is None
    assert unknown.ja3_evidence[0].type=='COVERAGE_GAP'
    known=profiles[0]
    assert known.ja3_evidence[0].type=='OBSERVED'
    assert known.ja3_fingerprint in {o.get('ja3_fingerprint') for o in known.client_hello_offers}


def test_ja3_not_synthesized_or_taken_from_serverhello():
    packet={'ip.src':'192.0.2.1','tcp.srcport':'50000','tls.handshake.type':'1'}
    assert extract_client_hellos([packet],'192.0.2.1',50000)[0]['ja3_fingerprint'] is None
    packet.update({'tls.handshake.type':'2','tls.handshake.ja3':'a'*32})
    assert not extract_client_hellos([packet],'192.0.2.1',50000)


def test_fix_first_precedence_and_grouping(legacy_investigation):
    from app.analysis.prioritization import build_fix_first
    from app.discovery.models import AnomalyAssessment,ClientAnomalyResult
    from types import SimpleNamespace
    inv=legacy_investigation.model_copy(deep=True)
    base=next(f for f in inv.findings if f.status=='FAIL')
    a,b,c=inv.connections[:3]
    inv.findings=[base.model_copy(update=dict(id='A',rule_id='A',severity='CRITICAL',affected_connection_id=a.id)),
                  base.model_copy(update=dict(id='B1',rule_id='B',severity='HIGH',affected_connection_id=b.id)),
                  base.model_copy(update=dict(id='B2',rule_id='B',severity='HIGH',affected_connection_id=c.id)),
                  base.model_copy(update=dict(id='C',rule_id='C',severity='HIGH',affected_connection_id=a.id)),
                  base.model_copy(update=dict(id='D',rule_id='D',severity='HIGH',affected_connection_id=c.id))]
    clients=inv.discovery.inventory
    inv.discovery=SimpleNamespace(anomaly_assessment=AnomalyAssessment(status='ANALYZED',population_size=5,results=[
        ClientAnomalyResult(client_id=p.client_id,anomaly_score=100 if p.observed_ip=='192.0.2.23' else 0,explanation='test') for p in clients]))
    ranking=build_fix_first(inv)
    assert [r['rule_id'] for r in ranking['rows']]==['A','B','D','C']
    assert ranking['rows'][1]['affected_sessions']==2
    assert ranking['label']=='Heuristic prioritisation, not a calibrated risk score'
    inv.discovery.anomaly_assessment.status='INSUFFICIENT_SAMPLE'
    abstained=build_fix_first(inv)
    assert all(r['anomaly_rank'] is None for r in abstained['rows'])
    assert [r['rule_id'] for r in abstained['rows']]==['A','B','C','D']


def test_fix_first_serialization_and_integrity(legacy_investigation):
    from app.models import Investigation
    from app.analysis.prioritization import build_fix_first
    from app.reporting.report_builder import build_investigation_report
    from app.reporting.integrity import verify_report_manifest
    inv=Investigation.model_validate_json(legacy_investigation.model_dump_json())
    assert build_fix_first(inv)==build_fix_first(legacy_investigation)
    report=build_investigation_report(inv)
    assert verify_report_manifest(report)['is_valid']
    report.fix_first['weights']['severity']=0
    assert not verify_report_manifest(report)['is_valid']


@pytest.mark.parametrize('version,group,classification',[
 ('TLS 1.3','0x11ec','PQ_HYBRID_OBSERVED'),('TLS 1.3','0x11eb','PQ_HYBRID_OBSERVED'),
 ('TLS 1.3','0x6399','PQ_HYBRID_OBSERVED'),('TLS 1.3','29','CLASSICAL_OBSERVED'),
 ('TLS 1.3','0x0017','CLASSICAL_OBSERVED'),('TLS 1.3',None,'UNKNOWN'),
 ('TLS 1.3','0xbeef','UNKNOWN'),('TLS 1.2','0x11ec','UNKNOWN')])
def test_quantum_indicator_info_only(version,group,classification):
    from app.analysis.quantum import quantum_indicator
    q=quantum_indicator(version,group,'12')
    assert q['classification']==classification and q['severity']=='INFO'
    assert q['type']==('COVERAGE_GAP' if classification=='UNKNOWN' else 'OBSERVED')
    assert 'status' not in q
    if classification=='CLASSICAL_OBSERVED':assert 'not a vulnerability' in q['detail']


def test_quantum_selection_capture_and_digest(legacy_investigation):
    from app.reporting.report_builder import build_investigation_report
    from app.reporting.integrity import verify_report_manifest
    inv=legacy_investigation
    tls13=next(c for c in inv.connections if c.tls_version=='TLS 1.3')
    assert tls13.server_key_share_group
    assert tls13.quantum_readiness['classification'] in ('CLASSICAL_OBSERVED','PQ_HYBRID_OBSERVED')
    assert not any(f.rule_id.startswith('SMS-PQ') for f in inv.findings)
    report=build_investigation_report(inv)
    assert verify_report_manifest(report)['is_valid']
    report.session_evidence[0]['quantum_readiness']['classification']='tampered'
    assert not verify_report_manifest(report)['is_valid']


def test_quantum_ignores_client_offer_and_hello_retry():
    base={'tcp.stream':'0','ip.src':'192.0.2.1','ip.dst':'198.51.100.25','tcp.srcport':'50000','tcp.dstport':'465','frame.number':'1',
          'tls.handshake.type':'1','tls.handshake.version':'0x0303','tls.handshake.extensions_key_share_group':'0x11ec'}
    inv=reconstruct_investigation_from_packets('partial.pcap','a'*64,'a'*12,[base])
    assert inv.connections[0].server_key_share_group is None
    retry=dict(base,**{'ip.src':'198.51.100.25','ip.dst':'192.0.2.1','tcp.srcport':'465','tcp.dstport':'50000','frame.number':'2',
        'tls.handshake.type':'2','tls.handshake.extensions.supported_version':'0x0304',
        'tls.handshake.random':'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c'})
    inv=reconstruct_investigation_from_packets('retry.pcap','a'*64,'a'*12,[base,retry])
    assert inv.connections[0].quantum_readiness['type']=='COVERAGE_GAP'
