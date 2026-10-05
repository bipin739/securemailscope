# SecureMailScope - SIH 26159

A local, passive email cryptography investigation workspace. This package improves the supplied React/FastAPI project and contains its complete source, production frontend build, reproducible PCAPs, and measured validation results.

## Run the demo

Requirements: Python 3.14 (the tested version) and Wireshark/TShark. TShark is detected on PATH or in the standard Windows Wireshark install directory. You can also set `TSHARK_PATH` to the executable. For other Python versions, use the runtime ranges in `backend/requirements.txt` and install pytest/httpx separately; the exact pinned validation environment may require a newer Python.

In PowerShell, from this folder:

```powershell
.\Start-SecureMailScope.ps1
```

The first run creates `.venv` and installs the tested Python dependencies (Internet needed once). Open **http://127.0.0.1:8000**. The frontend build is included; Node is not needed to run it. The server binds only to your computer. If port 8000 is occupied, use `-Port 8001`.

If PowerShell blocks local scripts, run the equivalent commands manually rather than changing your system policy:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements-tested.txt
cd backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Suggested four-minute presentation

Follow [DEMO_GUIDE.md](DEMO_GUIDE.md). Start with `sample-captures/lab-legacy-clients-offer.pcap`: five clients, four observed JA3 fingerprints, and **2 COMPATIBLE / 2 WOULD_BREAK / 1 UNKNOWN** for TLS 1.2 minimum + weak-cipher prohibition. Show a finding's recommended fix, Fix first weights, an INFO-only quantum observation, and verified exports.

For X.509 evidence use `lab-expired-certificate.pcap`. To demonstrate a valid path, restart with `-LabTrust` and analyze `lab-ca-signed-tls12.pcap`. The lab CA is scoped to that launched server and is never installed into the OS trust store.

## Test and reproduce

```powershell
cd backend
..\.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider
..\.venv\Scripts\python.exe tools\validate_captures.py
```

`validation/CAPTURE_RESULTS.md` and `capture-results.json` contain observed results. `validation/test-results.xml` records the complete automated test run. Input hashes and expected results live in `sample-captures/manifest.json`.

To regenerate the synthetic traffic:

```powershell
..\.venv\Scripts\python.exe tools\generate_captures.py
```

The generator uses real OpenSSL `ssl.MemoryBIO` handshakes for TLS 1.2/1.3, then serializes Ethernet/IP/TCP packets. It contacts no server and requires no capture privileges. Legacy TLS is a manually specified ServerHello regression fixture. Random TLS values and fresh lab certificates change the hashes on regeneration; the manifest is regenerated with them. No private lab keys are retained. These are synthetic regression inputs, not captures of production email or a benchmark dataset.

## Develop the frontend

```powershell
cd frontend
npm ci
npm run dev
npm run build
```

Use Node 22.18+ (Node 24 was tested). The Vite dev server proxies `/api` to port 8000. The build/dev scripts use Vite native config loading to avoid esbuild traversing inaccessible parent directories in restricted Windows workspaces. Restart the backend after producing a new frontend build if it was started before `dist` existed.

## What is improved

- Responsive sidebar workspace, clear current-capture metrics, protocol bars, prioritized findings, searchable/filterable sessions, keyboard-accessible detail drawer, and a downloadable capture lab.
- Negotiated TLS parameters taken from server ServerHello, including the TLS 1.3 supported-version extension. Offered client ciphers and record-layer compatibility versions are not treated as negotiated choices.
- TShark reassembly enabled for segmented and out-of-order traffic. Partial handshakes and greeting-only sessions remain unverified rather than being labeled plaintext failures.
- SMTP STARTTLS, IMAP STARTTLS, POP3 STLS, implicit TLS, plaintext authentication, deprecated versions, weak ciphers, and forward secrecy evidence.
- Visible X.509 extraction, capture-time validity, key algorithm/size, signature identification, DNS checks, and offline path validation against an explicit `SMS_TRUST_STORE` PEM bundle.
- Paginated PDF export, capture provenance, report hashing that survives browser numeric serialization, bounded upload reads, local-only server binding, and removal of credential parameters from retained extraction records.

See **SIH_READINESS.md** for requirement coverage, known limitations, and defensible judging claims. Earlier README/architecture/demo documents describe the input prototype and are superseded by this guide.
