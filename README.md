# SecureMailScope — SIH 26159

Offline, passive email cryptography assessment from PCAP/PCAPNG. FastAPI/TShark backend and React/TypeScript frontend. This is a tested research/demo prototype, not a production certification.

- [Run and test](START_HERE.md)
- [3–5 minute demo](DEMO_GUIDE.md)
- [Coverage and limitations](SIH_READINESS.md)
- [Measured capture results](validation/CAPTURE_RESULTS.md)

Run `Start-SecureMailScope.ps1` on Windows and open http://127.0.0.1:8000. Python 3.14 and TShark are required. The first setup installs the pinned dependencies; analysis afterward stays local/offline. The built frontend is included.

The current demo uses `sample-captures/lab-legacy-clients-offer.pcap`: five clients and expected simulator counts of 2 COMPATIBLE, 2 WOULD_BREAK, and 1 UNKNOWN under TLS 1.2 minimum plus weak-cipher removal. The 20 bundled captures are synthetic, not production benchmarks.

Findings include structured fix guidance, JA3 is derived from observed ClientHellos, and Fix first uses an explained heuristic with ML only as a tie-breaker. Quantum-readiness is an INFO-only ServerHello key-share observation, never a failing check.

Every assessment distinguishes OBSERVED, RULE, ASSUMPTION and COVERAGE_GAP. Missing data remains UNKNOWN. No external lookup, active probing, credential retention or message-body retention is added. This README supersedes the input project's obsolete “production-ready” and sample-path claims; `ARCHITECTURE.md` is retained as legacy background.
