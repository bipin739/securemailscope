"""Offline X.509 assessment. Trust is explicit; network revocation is not performed."""
import datetime as dt
import hashlib
import os
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.x509.verification import PolicyBuilder, Store, DNSName


def extract_certificates(records, hostname, server_port):
    decoded = []
    seen = set()
    capture_time = next((dt.datetime.fromtimestamp(float(p['frame.time_epoch']), dt.timezone.utc)
                         for p in records if p.get('frame.time_epoch')), None)
    for p in records:
        if str(p.get('tcp.srcport')) != str(server_port):
            continue
        for raw in str(p.get('tls.handshake.certificate') or '').split(','):
            if not raw:
                continue
            try:
                der = bytes.fromhex(raw.replace(':', ''))
                digest = hashlib.sha256(der).hexdigest()
                if digest in seen:
                    continue
                seen.add(digest)
                cert = x509.load_der_x509_certificate(der)
                decoded.append((cert, digest, p.get('frame.number')))
            except (ValueError, TypeError):
                continue
    result = []
    chain_status = 'UNKNOWN'
    chain_detail = 'No explicit trust store supplied. Chain trust and revocation are not verified.'
    trust_file = os.environ.get('SMS_TRUST_STORE')
    if decoded and trust_file and hostname and capture_time:
        try:
            roots = x509.load_pem_x509_certificates(Path(trust_file).read_bytes())
            verifier = PolicyBuilder().store(Store(roots)).time(capture_time).build_server_verifier(DNSName(hostname))
            verifier.verify(decoded[0][0], [x[0] for x in decoded[1:]])
            chain_status = 'PASS'
            chain_detail = 'Certificate path and DNS identity verified against the configured trust store at capture time. Revocation not checked.'
        except OSError as exc:
            chain_detail = f'Trust-store configuration is unavailable: {str(exc)[:200]}. Certificate path not verified.'
        except Exception as exc:
            chain_status = 'FAIL'
            chain_detail = f'Configured trust validation failed: {str(exc)[:240]}'
    for i, (cert, digest, frame) in enumerate(decoded):
        key = cert.public_key()
        algo = 'RSA' if isinstance(key, rsa.RSAPublicKey) else 'EC' if isinstance(key, ec.EllipticCurvePublicKey) else 'Ed25519' if isinstance(key, ed25519.Ed25519PublicKey) else 'Ed448' if isinstance(key, ed448.Ed448PublicKey) else type(key).__name__
        try:
            names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            names = []
        issues = []
        if capture_time:
            if capture_time > cert.not_valid_after_utc:
                issues.append('Expired at capture time')
            if capture_time < cert.not_valid_before_utc:
                issues.append('Not yet valid at capture time')
        if algo == 'RSA' and key.key_size < 2048:
            issues.append('RSA public key below 2048 bits')
        if algo == 'EC' and key.key_size < 224:
            issues.append('EC public key below 224 bits')
        try:
            sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else 'intrinsic'
        except Exception:
            sig_hash = 'unknown'
        if sig_hash in ('md5', 'sha1'):
            issues.append('Deprecated signature hash: ' + sig_hash)
        if i == 0 and cert.issuer == cert.subject:
            issues.append('Self-issued leaf certificate; explicit trust required')
        if i == 0 and hostname and names:
            def matches(pattern):
                pattern, name = pattern.lower(), hostname.lower()
                return pattern == name or (pattern.startswith('*.') and name.count('.') == pattern.count('.') and name.endswith(pattern[1:]))
            if not any(matches(n) for n in names):
                issues.append('DNS subject alternative names do not match observed SNI')
        result.append(dict(subject=cert.subject.rfc4514_string(), issuer=cert.issuer.rfc4514_string(),
                           serial_number=hex(cert.serial_number), sha256=digest, frame=frame,
                           not_before=cert.not_valid_before_utc.isoformat(), not_after=cert.not_valid_after_utc.isoformat(),
                           assessed_at=capture_time.isoformat() if capture_time else None,
                           public_key_algorithm=algo, public_key_bits=getattr(key, 'key_size', None),
                           signature_algorithm=cert.signature_algorithm_oid.dotted_string, signature_hash=sig_hash,
                           dns_names=names, issues=issues, chain_status=chain_status if i == 0 else 'INTERMEDIATE',
                           chain_detail=chain_detail if i == 0 else 'Captured chain member; see leaf path validation.'))
    return result
