# SIH 26159: implementation and assessment limits

This is a tested SIH demonstration/research prototype. It is not a production certification or a claim that every problem-statement objective is complete.

| Requirement | Current implementation | Boundary |
|---|---|---|
| SMTP, IMAP, POP3 identification | TShark protocol fields plus standard mail ports | Implicit TLS application identity inferred from port; arbitrary-port TLS cannot prove the application |
| PCAP / PCAPNG | Validated uploads and real TShark parsing | 50 MiB input limit; 30-second extraction timeout; large-capture load testing pending |
| TCP stream reconstruction | TShark two-pass stream/record reassembly with out-of-order support | Missing packets cannot be reconstructed; overlapping/conflicting segments need further adversarial testing |
| TLS negotiation | ServerHello-selected version/cipher; TLS 1.3 supported_versions | Selection is not proof of a completed, authenticated handshake |
| STARTTLS | Request, positive response, and later ServerHello tracked | Absence in a truncated capture does not establish an attack; no claim of proven STARTTLS stripping |
| X.509 | Visible certificates, fingerprints, validity at capture time, key size/type, signature OID/hash, DNS checks | TLS 1.3 encrypts Certificate messages; resumed/partial sessions can omit them |
| Chain validation | cryptography path verifier with explicit PEM trust anchors and observed SNI | No automatic trust of presented roots, no AIA retrieval, CRL or OCSP checks; non-DNS identities not validated |
| Weak crypto / PFS | Explainable TLS/cipher/authentication rules; TLS 1.3 PFS uses ServerHello key-share evidence | Cipher registry is a curated subset; unidentified suites remain unevaluated; a TLS 1.3 cipher name alone does not prove PFS |
| AI/ML | Offline Isolation Forest over observed client features, explanations and prioritization | Relative anomaly detection; minimum population is a demo heuristic, not statistical validation; no supervised risk classifier or measured generalization accuracy |
| Security posture | Transparent severity-based classification and coverage gaps | No calibrated AI security score. Visibility percentages are not security percentages |
| Reports | JSON, HTML, paginated PDF, SHA-256 input identity, report/component digests | Integrity checks require an independently retained reference for adversarial provenance; no digital signatures or immutable custody store |
| Dashboard | Current-capture summary, filters, evidence drawer, replay, client discovery, hardening simulation | Local single-analyst workspace; no authentication, RBAC, multi-tenant isolation or durable case database |

## Test evidence

The package includes 20 synthetic byte-level scenarios: SMTP plaintext AUTH; IMAP plaintext LOGIN; POP3 plaintext authentication; SMTP STARTTLS/TLS 1.2; IMAP STARTTLS; POP3 STLS; CA-signed TLS 1.2; implicit SMTPS/IMAPS/POP3S TLS 1.3; fragmented/out-of-order TLS; expired certificate; ClientHello only; encrypted midstream; rejected STARTTLS; legacy TLS 1.0/3DES; mixed-client PCAP and PCAPNG; non-mail traffic; and the five-client legacy-offer regression fixture.

Additional tests cover trust-store acceptance, missing trust configuration, hostname mismatch, greeting-only capture, invalid uploads, report exports, integrity tampering, and browser int/float round trips. See the machine-readable JUnit and capture validation results for exact outcomes and timing.

These tests establish correctness for supplied scenarios. They do not establish performance, detection accuracy on independent traffic, resistance to every malformed capture, or completeness across every cipher and extension. Before submission, add independent authorized captures from a real mail server/client, label their provenance, and compare selected fields with Wireshark. Before production, isolate TShark, bound parser output/resource use, add authentication/case retention controls, and obtain security review.

## Sources for implemented protocol distinctions

- TLS 1.3 ServerHello, supported_versions, encrypted certificates and key exchange: https://www.rfc-editor.org/rfc/rfc8446.html
- TShark TLS display fields: https://www.wireshark.org/docs/dfref/t/tls.html
- Certificate path validation: https://www.rfc-editor.org/rfc/rfc5280.html
- SMTP STARTTLS: https://www.rfc-editor.org/rfc/rfc3207.html

The protocol references support parsing decisions, not a claim of complete standards compliance. The interface and reports state the visibility limits explicitly.


## ClientHello offers and hardening impact

Client-side ClientHello frames supply supported versions, legacy version, cipher offers and supported groups. The legacy version is retained separately: if supported_versions exists it is authoritative, since the TLS 1.3 legacy value is not an offer of TLS 1.2. GREASE and signalling suites are not cryptographic choices. Unknown identifiers are retained as unknown and do not prove compatibility or breakage.

TLS-minimum and weak-cipher policies return WOULD_BREAK only from the relevant captured offer lists. A missing ClientHello remains UNKNOWN, even with a visible modern ServerHello. Explicitly captured offers apply to these observed configurations, not every version or setting a device may support. Per-client aggregation spans observed sessions; COMPATIBLE does not certify every possible version/cipher combination or full authenticated connection. Require-PFS/require-encryption policies are separate legacy policies and may use observed session evidence.

`lab-legacy-clients-offer.pcap` yields 2 COMPATIBLE / 2 WOULD_BREAK / 1 UNKNOWN under TLS 1.2 minimum + weak-cipher prohibition. Two clients use OpenSSL handshakes. The legacy offer/selection pairs are hand-built regression fixtures, not completed TLS sessions. Generation creates new certificates/randoms and refreshes all manifest hashes.

## Recommended fixes

Every deterministic finding includes a RULE-labelled remediation object with steps and an optional software/version/scoped snippet. Postfix examples apply to authenticated submission, require working TLS certificates, and are labelled “Review and test before applying.” They must not be blindly applied to a public port-25 relay. Unknown and passing checks receive evidence-collection or maintenance guidance. There is no automatic configuration change. Remediation is included in finding and report digests and in JSON, HTML and PDF.

## JA3

TShark's `tls.handshake.ja3` is retained only from visible client-direction ClientHello frames. Multiple observed fingerprints are preserved; the singular field is only populated for a single distinct value. Missing fields/handshakes produce COVERAGE_GAP. JA3 is not a unique software, device or user identifier; collisions and deliberate mimicry are possible. There is no online lookup. Fingerprints remain inside retained ClientHello session metadata and report integrity coverage.

## Fix first

Actionable FAIL/WARN findings are grouped by rule and severity. Ordering uses severity values 5/4/3/2/1 for CRITICAL/HIGH/MEDIUM/LOW/INFO. With N captured sessions and P clients with available ML results, session weight is P+1 and severity weight is (N+1)(P+1). The final tie term is P−anomaly_rank+1 (zero when unavailable); equal anomaly scores share a rank. These bounds guarantee severity precedes session count and ML only breaks remaining ties. Grouped rows show affected client IDs, distinct sessions and evidence labels. Ordering points are not risk probabilities or calibrated AI scores. ML still abstains for insufficient evidence/population; no fake score replaces abstention.

## Quantum-readiness observation

For TLS 1.3 only, the selected ServerHello key-share group is compared against a bounded allowlist checked against the installed Wireshark 4.6.9 value table. Recognized ML-KEM hybrids and explicitly named obsolete Kyber hybrid drafts produce “PQ hybrid observed.” Recognized classical groups produce “classical key exchange observed” with the harvest-now-decrypt-later caveat. ClientHello group offers and HelloRetryRequest group requests do not establish a selected share. Unknown/private/non-visible groups remain COVERAGE_GAP. This is an INFO-only session annotation, excluded from pass/fail security scoring. It cannot establish handshake completion, post-quantum authentication, implementation correctness, or overall quantum security.

## Verification boundary

Regression tests exercise the new offer counts, missing/unknown offers, JA3 provenance, fixes/export integrity, priority precedence and ML abstention, and classical/hybrid/unknown key-share classification. The local application makes no new external network calls; TShark name resolution is disabled. Configuration examples were not applied to a live Postfix/Dovecot server. No independent classifier accuracy or production mail-server interoperability result is claimed.
