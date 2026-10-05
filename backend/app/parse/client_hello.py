"""Offline ClientHello metadata. Never infer offers from a ServerHello."""
import re
from app.analysis.normalization import normalize_tls_version, CIPHER_HEX_MAP


def values(value):
    return [s.strip() for s in str(value or '').split(',') if s.strip()]


def code(value):
    try:
        return int(value, 16 if str(value).startswith('0x') else 10)
    except ValueError:
        return None


def is_grease(value):
    n = code(value)
    return n is not None and n & 0x0f0f == 0x0a0a and n >> 8 == n & 255


def extract_client_hellos(packets, client_ip, client_port):
    offers = []
    for p in packets:
        if '1' not in values(p.get('tls.handshake.type')):
            continue
        if str(p.get('tcp.srcport')) != str(client_port) or (p.get('ip.src') or p.get('ipv6.src')) != client_ip:
            continue
        legacy = values(p.get('tls.handshake.version'))
        explicit = values(p.get('tls.handshake.extensions.supported_version'))
        # With supported_versions, legacy_version is compatibility metadata, not an offer.
        versions = [normalize_tls_version(v) for v in (explicit or legacy) if not is_grease(v)]
        ciphers = []
        for v in values(p.get('tls.handshake.ciphersuite')):
            n = code(v)
            if is_grease(v) or n in (0x00ff, 0x5600):
                continue  # Signalling suites are not cryptographic choices.
            ciphers.append(CIPHER_HEX_MAP.get(f'0x{n:04x}', f'UNKNOWN (0x{n:04x})') if n is not None else f'UNKNOWN ({v})')
        ja3 = str(p.get('tls.handshake.ja3') or '').lower()
        offers.append(dict(ja3_fingerprint=ja3 if re.fullmatch(r'[0-9a-f]{32}', ja3) else None, type='OBSERVED', frame=str(p.get('frame.number') or ''),
                           supported_tls_versions=sorted(set(versions)),
                           legacy_version=normalize_tls_version(legacy[0]) if legacy else None,
                           versions_source='supported_versions' if explicit else 'legacy maximum version',
                           offered_cipher_suites=sorted(set(ciphers)),
                           offered_groups=sorted(set(v for v in values(p.get('tls.handshake.extensions_supported_group')) if not is_grease(v)))))
    return offers
