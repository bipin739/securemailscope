from app.analysis.rules import BaseSecurityRule, RuleEvaluationResult
from app.analysis.evidence import Evidence


class CertificateRule(BaseSecurityRule):
    rule_id = 'SMS-CERT-001'

    def evaluate(self, session):
        if session.tls_version == 'None':
            return None
        certs = session.certificates
        issues = [issue for c in certs for issue in c['issues']]
        failed = bool(issues) or any(c['chain_status'] == 'FAIL' for c in certs)
        trusted = bool(certs) and certs[0]['chain_status'] == 'PASS'
        detail = '; '.join(issues) if issues else (certs[0]['chain_detail'] if certs else
            'No server certificate is visible. TLS 1.3 encrypts certificates; a partial or resumed handshake may also omit them.')
        return RuleEvaluationResult(
            rule_id=self.rule_id, title='Certificate assessment: ' + ('issues detected' if failed else 'verified path' if trusted else 'limited visibility'),
            severity='HIGH' if failed else 'INFO', category='X.509 Certificates',
            status='FAIL' if failed else 'PASS' if trusted else 'UNKNOWN', confidence='HIGH' if certs else 'LOW',
            plain_explanation=detail, why_it_matters='Encryption parameters alone do not establish the identity or trustworthiness of a mail server.',
            recommendation='Renew invalid certificates, use modern keys, and supply an approved PEM trust store via SMS_TRUST_STORE for offline path validation. Check revocation separately.',
            references=['RFC 5280', 'RFC 8446'], affected_connection_id=f'conn-real-{session.stream_id}',
            evidence=[Evidence(type='OBSERVED' if certs else 'COVERAGE_GAP', field='certificates', value=certs or 'Not visible',
                               source='TLS Certificate handshake', description=detail)])
