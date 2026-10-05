# Measured capture validation

20/20 byte-level scenarios passed.

Synthetic lab fixtures, not production or public benchmark traffic
TShark: TShark (Wireshark) 4.6.9 (v4.6.9-0-g2d548b197c75).

| Capture | Sessions | TLS observed | Posture | Result |
|---|---:|---|---|---|
| lab-smtp-cleartext-auth.pcap | 1 | None | CRITICAL | PASS |
| lab-imap-cleartext.pcap | 1 | None | CRITICAL | PASS |
| lab-pop3-cleartext.pcap | 1 | None | CRITICAL | PASS |
| lab-smtp-starttls-tls12.pcap | 1 | TLS 1.2 | HIGH_RISK | PASS |
| lab-imap-starttls.pcap | 1 | TLS 1.2 | HIGH_RISK | PASS |
| lab-pop3-stls.pcap | 1 | TLS 1.2 | HIGH_RISK | PASS |
| lab-ca-signed-tls12.pcap | 1 | TLS 1.2 | UNKNOWN | PASS |
| lab-smtp-tls13.pcap | 1 | TLS 1.3 | UNKNOWN | PASS |
| lab-imap-tls13.pcap | 1 | TLS 1.3 | UNKNOWN | PASS |
| lab-pop3-tls13.pcap | 1 | TLS 1.3 | UNKNOWN | PASS |
| lab-fragmented-out-of-order.pcap | 1 | TLS 1.2 | HIGH_RISK | PASS |
| lab-expired-certificate.pcap | 1 | TLS 1.2 | HIGH_RISK | PASS |
| lab-clienthello-only.pcap | 1 | UNKNOWN | UNKNOWN | PASS |
| lab-midstream-encrypted.pcap | 1 | UNKNOWN | UNKNOWN | PASS |
| lab-starttls-rejected.pcap | 1 | UNKNOWN | UNKNOWN | PASS |
| lab-legacy-tls10-3des.pcap | 1 | TLS 1.0 | HIGH_RISK | PASS |
| lab-mixed-fleet.pcap | 8 | None, TLS 1.0, TLS 1.3 | CRITICAL | PASS |
| lab-mixed-fleet.pcapng | 8 | None, TLS 1.0, TLS 1.3 | CRITICAL | PASS |
| lab-legacy-clients-offer.pcap | 5 | TLS 1.0, TLS 1.2, TLS 1.3, UNKNOWN | HIGH_RISK | PASS |
| lab-no-mail.pcap | 0 | none | UNKNOWN | PASS |

The JSON companion records expected values, actual findings and each input SHA-256. Trust tests are in pytest; default capture validation does not implicitly trust the lab CA.

Regenerate captures with `python tools/generate_captures.py`. OpenSSL generates fresh random handshakes and keys, so hashes change; the manifest is regenerated alongside them. Scenario assertions remain stable.