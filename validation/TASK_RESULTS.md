# Ordered task completion

| Task | Changes and added coverage | Full pytest result |
|---|---|---:|
| 1 | ClientHello offers, conservative policies, legacy-client PCAP, highlighted WOULD_BREAK rows. Tests: offer extraction, missing/unknown evidence, exact capture counts. | 114 passed |
| 2 | Typed remediation for every finding, scoped snippets, drawer and JSON/HTML/PDF, digest inclusion. Tests: rule coverage, export content, tampering. | 116 passed |
| 3 | Offline JA3 extraction/UI and missing-fingerprint coverage. Tests: observed fingerprints and absent/server-only hellos. | 118 passed |
| 4 | Explainable severity/session/anomaly ordering and UI weights; ML abstention retained. Tests: precedence, grouping, abstention, serialization, digest. | 120 passed |
| 5 | INFO-only TLS 1.3 selected-group quantum observation. Tests: classical/hybrid/unknown, capture parsing, digest, ignoring ClientHello/HelloRetryRequest. | 130 passed |
| 6 | Bundled-capture demo, readiness, README and startup guidance with limits. Documentation only; no tests added. | 130 passed |

New upgrade tests: `backend/tests/test_sih_upgrades.py`. New capture also joins the parameterized suite. Local baseline was 109 passing tests. Existing tests retained. Final checks and browser limitations: `UI_CHECKS.md`.
