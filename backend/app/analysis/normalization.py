from typing import Optional, Dict

CIPHER_HEX_MAP: Dict[str, str] = {
    '0x009e': 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
    '0x009f': 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
    '0xcca8': 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    '0xcca9': 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    '0xccaa': 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    '0xc013': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    '0xc014': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    '0xc009': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
    '0xc00a': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
    '0x0033': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
    '0x0039': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
    '0x003c': 'TLS_RSA_WITH_AES_128_CBC_SHA256',
    '0x003d': 'TLS_RSA_WITH_AES_256_CBC_SHA256',
    "0x1301": "TLS_AES_128_GCM_SHA256",
    "0x1302": "TLS_AES_256_GCM_SHA384",
    "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
    "0xc02f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "0xc030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "0xc02b": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "0xc02c": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "0x009c": "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "0x009d": "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "0x000a": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "0x002f": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "0x0035": "TLS_RSA_WITH_AES_256_CBC_SHA",
    "0x0005": "TLS_RSA_WITH_RC4_128_SHA",
    "0x0004": "TLS_RSA_WITH_RC4_128_MD5",
    "0x0002": "TLS_RSA_WITH_NULL_SHA",
    "0x0001": "TLS_RSA_WITH_NULL_MD5",
    "0x0003": "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    "0x0006": "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    "0x0008": "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "0x0009": "TLS_RSA_WITH_DES_CBC_SHA",
}

def normalize_tls_version(raw_version: Optional[str]) -> str:
    """
    Normalizes raw version strings, hex codes, and TShark protocol names to canonical TLS versions:
    'TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0', 'SSL 3.0', 'SSL 2.0', or 'None'.
    """
    if not raw_version:
        return "None"
    
    val = raw_version.strip()
    if val in ("None", "NONE", "null", ""):
        return "None"

    # Hex representations
    if val in ("0x0304", "0x7f1c") or "1.3" in val or "TLSv1.3" in val:
        return "TLS 1.3"
    elif val == "0x0303" or "1.2" in val or "TLSv1.2" in val:
        return "TLS 1.2"
    elif val == "0x0302" or "1.1" in val or "TLSv1.1" in val:
        return "TLS 1.1"
    elif val == "0x0301" or "1.0" in val or "TLSv1" in val or "TLS 1.0" in val:
        return "TLS 1.0"
    elif val == "0x0300" or "3.0" in val or "SSLv3" in val:
        return "SSL 3.0"
    elif val == "0x0200" or "2.0" in val or "SSLv2" in val:
        return "SSL 2.0"
    
    return val

def normalize_cipher_suite(raw_cipher: Optional[str], tls_version: str) -> str:
    """
    Maps hex cipher codes or raw names to standard RFC cipher suite names.
    Distinguishes plaintext / unencrypted, uncaptured, and identified suites.
    """
    if not raw_cipher or raw_cipher in ("None", "NONE", "0x0000", "null", ""):
        if tls_version == "None":
            return "NONE (Unencrypted / Plaintext)"
        return "UNKNOWN / Not Captured"

    raw_lower = raw_cipher.lower().strip()
    if raw_lower in CIPHER_HEX_MAP:
        return CIPHER_HEX_MAP[raw_lower]

    return raw_cipher.strip()
