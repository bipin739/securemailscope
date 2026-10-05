"""Offline administrator guidance. Snippets are examples, never applied automatically."""
from typing import Literal
from pydantic import BaseModel, Field


class ConfigSnippet(BaseModel):
    software: str
    scope: str
    warning: str = 'Review and test before applying'
    config: str


class Remediation(BaseModel):
    type: Literal['RULE'] = 'RULE'
    steps: list[str] = Field(default_factory=list)
    snippet: ConfigSnippet | None = None


GUIDANCE = {
    'SMS-TLS-001': ['Identify whether the endpoint is client submission, mailbox access, or Internet SMTP relay.',
                    'Require TLS on authenticated submission and mailbox access; test all clients before rollout. Do not blindly require TLS on public port 25, which can reject legitimate mail.',
                    'Capture a fresh session and verify the upgrade before authentication.'],
    'SMS-STARTTLS-001': ['Configure the affected client to require STARTTLS or the correct implicit-TLS port.',
                         'For authenticated submission, reject plaintext fallback after testing clients. Treat public relay policy separately.',
                         'Capture again and check the server selection and authentication order.'],
    'SMS-AUTH-001': ['Require TLS before advertising or accepting authentication on the submission service.',
                     'Update affected clients and rotate potentially exposed credentials through your approved process.',
                     'Confirm in a fresh capture that authentication cannot occur in plaintext.'],
    'SMS-TLSVER-001': ['Inventory ClientHello offers and upgrade clients that cannot offer TLS 1.2 or newer.',
                       'Set a TLS 1.2 minimum on the affected service after staging tests and a rollback plan.',
                       'Check both mandatory and opportunistic TLS settings for the intended service.'],
    'SMS-CIPHER-001': ['Upgrade the affected mail server and client TLS libraries.',
                       'Remove the identified weak suites from that service using its version-specific cipher configuration; prefer supported AEAD suites.',
                       'Test client compatibility and verify the newly selected cipher in a fresh capture.'],
    'SMS-PFS-001': ['Prefer ephemeral ECDHE/DHE key exchange where supported; remove static RSA exchange after compatibility testing.',
                    'For TLS 1.3 inspect the selected key-share group; the cipher name alone does not prove forward secrecy.'],
    'SMS-CERT-001': ['Check the reported certificate issue against the intended hostname and capture time.',
                     'Renew expired certificates, correct names and intermediates, and use approved keys and signature algorithms as applicable.',
                     'Supply an approved PEM trust bundle for offline path validation. Assess revocation using separately obtained evidence; this tool makes no revocation requests.'],
}


def remediation_for(rule_id, status, fallback):
    if status == 'UNKNOWN':
        return Remediation(steps=['Collect the missing handshake or certificate evidence before deciding on a configuration change.',
                                  'For encrypted TLS 1.3 certificates, obtain approved endpoint certificate evidence separately. Do not interpret missing evidence as a failure.'])
    if status == 'PASS':
        return Remediation(steps=['No change is required by this observed check. Maintain the baseline and re-check a fresh capture after configuration changes.'])
    result = Remediation(steps=GUIDANCE.get(rule_id, [fallback]))
    # Postfix >=3.6 supports the >=TLSv1.2 syntax. Scope the example to submission.
    snippet = {
        'SMS-TLS-001': 'smtpd_tls_security_level = encrypt\nsmtpd_tls_auth_only = yes',
        'SMS-STARTTLS-001': 'smtpd_tls_security_level = encrypt\nsmtpd_tls_auth_only = yes',
        'SMS-AUTH-001': 'smtpd_tls_auth_only = yes\nsmtpd_tls_security_level = encrypt',
        'SMS-TLSVER-001': 'smtpd_tls_security_level = encrypt\nsmtpd_tls_mandatory_protocols = >=TLSv1.2',
    }.get(rule_id)
    if snippet:
        result.snippet = ConfigSnippet(software='Postfix 3.6+ (smtpd)',
            scope='Example parameter values for authenticated submission only. Translate to per-service master.cf overrides where appropriate. Requires a working TLS certificate/key. Do not apply globally to a public port-25 relay.', config=snippet)
    return result
