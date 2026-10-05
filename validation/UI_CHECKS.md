# Final validation record — 2026-10-05

## Automated checks

- 130 tests passed, zero skipped, with an upstream Starlette/httpx deprecation warning and a harmless pytest cache-write warning. See `test-results.xml`.
- 20/20 bundled synthetic PCAP/PCAPNG scenarios passed TShark 4.6.9. See `CAPTURE_RESULTS.md` and `capture-results.json`.
- `npm run build` passed TypeScript and Vite. Node 24 tested; native config loading avoids restricted Windows ancestor-directory access.
- Legacy-client capture: **2 COMPATIBLE / 2 WOULD_BREAK / 1 UNKNOWN** with TLS 1.2 minimum and weak-cipher prohibition.
- JSON, HTML and PDF exports tested. New result fields participate in the digest; mutation tests detect tampering.
- Saved legacy-client JSON report loaded independently: manifest **VERIFIED**, no mismatches.
- Eight-page legacy-client PDF rendered and visually inspected, including scoped Postfix guidance and quantum observation.

## Browser checks completed

- Uploaded `sample-captures/lab-legacy-clients-offer.pcap` through the file chooser; analyzed as SYNTHETIC_LAB.
- Simulator displayed 2 COMPATIBLE, 2 WOULD_BREAK and 1 UNKNOWN, offered lists and red breakage rows.
- Client Discovery displayed four JA3 fingerprints and one COVERAGE_GAP / UNKNOWN.
- Findings displayed recommended fixes and the Postfix snippet disclosure labelled “Review and test before applying”.
- `simulator-verified.png` records the simulator UI. `dashboard-preview.png` is an earlier mixed-fleet screenshot, not evidence of the final capture.

## Not verified in the final browser pass

After the execution/app session restarted, browser connections timed out despite Uvicorn reporting startup. Fresh tabs on loopback ports 8001 and 8002 also timed out. The final report-page VERIFIED badge and completed browser downloads are therefore **not claimed as verified**. Report integrity and exports passed automated/in-process checks. Final Fix first weights and quantum drawer visuals were not rechecked in the browser; logic is tested and the frontend compiles.

These are synthetic regression checks, not production benchmarks or independent ML accuracy evaluation. No live server configuration was changed. Read `../SIH_READINESS.md` before making judging claims.

