> Legacy input-project documentation. For the updated SIH package, use [START_HERE.md](START_HERE.md) and [SIH_READINESS.md](SIH_READINESS.md).

# SecureMailScope — Architecture Document

**Project:** SecureMailScope  
**Problem Statement:** SIH26159 — NTRO (Smart India Hackathon 2026)  
**System Type:** Offline-First Email Transport Security Analysis System  
**Repository:** [https://github.com/bipin739/securemailscope.git](https://github.com/bipin739/securemailscope.git)  
**Current State:** Phase 1 Complete (Real PCAP Ingestion & Session Extraction)

---

## 1. System Philosophy & Purpose

SecureMailScope is engineered to analyze authorized email network captures (PCAP/PCAPNG) offline and reconstruct the transport-security posture of SMTP, IMAP, and POP3 communications.

Instead of forcing cybersecurity analysts to manually inspect raw packet streams with generic packet analyzers, SecureMailScope maps cryptographic parameters into a visual **Mail Security Journey**, highlighting where transport trust degraded, why it matters, and providing actionable remediation guidance.

### Core Philosophy
> *"Show where trust weakened, explain why, and tell the administrator what to fix."*

### Privacy Principle
> **Metadata-Only Analysis:** SecureMailScope extracts only transport and session handshake parameters (TLS ClientHello/ServerHello, STARTTLS command negotiation, cipher suites, SNI, ALPN). It never reads, captures, or stores email message bodies, attachments, or authentication credentials.

---

## 2. End-to-End System Pipeline

```text
┌─────────────────────────────────────────────────────────────┐
│                    Authorized PCAP / PCAPNG                 │
│              (Offline Network Traffic Capture)              │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                      PCAP Ingestion                         │
│     (Magic byte validation, SHA-256 capture fingerprint)    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                   TShark Field Extraction                   │
│        (Safe subprocess argument array, no shell=True)      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                   Session Reconstruction                    │
│      (TCP stream reassembly, 5-tuple, directionality)       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│               SMTP / IMAP / POP3 Detection                  │
│       (Protocol classification & STARTTLS observation)      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                  TLS Metadata Extraction                    │
│      (TLS version normalization, Cipher suite RFC names)    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                Basic Observations & Topology                │
│       (Observed host graph & transport security status)     │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 SecureMailScope Dashboard                   │
│         (Interactive Mail Journey & Investigation UI)        │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Implementation Phasing Breakdown

### Implemented in Phase 0
- **FastAPI Backend Skeleton**:
  - `GET /api/health` — Health check confirming service readiness.
  - `GET /api/investigations/demo` — High-fidelity 4-hop mock investigation.
  - Pydantic models for `Investigation`, `NetworkNode`, `NetworkConnection`, `ConnectionEvidence`, `PlainLanguageExploration`, and `SecurityFinding`.
- **React + Vite + TypeScript Frontend**:
  - Dark-mode, high-clarity cybersecurity operations interface.
  - **Mail Security Journey** hero component displaying multi-hop routing.
  - Interactive **Connection Detail Drawer** translating technical cryptographic parameters into plain-language summaries.
  - **Transport Security Findings** table with severity filtering.
  - **Upload Capture Interface** with privacy guarantees and honest provenance indicators.

### Implemented in Phase 1 (Current State)
- **Capture Validation & Fingerprinting** (`app/ingest/validator.py`):
  - File extension verification (`.pcap`, `.pcapng`, `.cap`).
  - Strict header magic byte inspection (Microsecond/Nanosecond PCAP, PCAPNG Section Header Blocks).
  - Deterministic SHA-256 fingerprint generation (`sha256_full`, `sha256_short`).
  - Size limitation checks (50 MB limit).
- **TShark Execution Engine** (`app/ingest/tshark.py`):
  - Safe subprocess invocation with explicit argument arrays (never `shell=True`).
  - Automated binary discovery in system `PATH` and standard Windows installation paths.
  - Extraction of frames, timestamps, IP endpoints, TCP ports, TCP stream IDs, TLS handshakes, cipher suites, SNI, and mail protocol commands.
- **Session Reconstruction & Normalization** (`app/parse/sessions.py`):
  - TCP stream grouping and client/server direction determination.
  - SMTP, IMAP, and POP3 protocol classification.
  - STARTTLS / STLS command observation.
  - TLS version normalization (`TLS 1.3`, `TLS 1.2`, `TLS 1.1`, `TLS 1.0`, `SSL 3.0`).
  - Cipher suite hex mapping to RFC naming and PFS/AEAD property detection.
  - Dynamic topology generation showing only what the capture supports.
- **Real Analysis API Endpoint** (`app/routes/investigations.py`):
  - `POST /api/investigations/analyze` (multipart/form-data).
  - Returns `Investigation` with `data_source="REAL_CAPTURE"` and `is_simulated=False`.
  - Immediate secure cleanup of temporary files.
- **Frontend Integration**:
  - Dynamic state management supporting real capture ingestion and demo mode coexistence.
  - Provenance badges (`REAL CAPTURE ANALYSIS` vs `PROTOTYPE • SIMULATED DATA`).

### Next — Phase 2 (Deterministic Security Rule Engine)
- Formal deterministic rule evaluation:
  - Protocol obsolescence rules (RFC 8996 compliance).
  - Cipher suite vulnerability scoring (3DES Sweet32, RC4, CBC mode, non-AEAD).
  - Inconsistent STARTTLS enforcement policy rules.
- Evidence-backed security finding generation with rule IDs.
- Standards compliance mapping (NIST SP 800-52r2, BSI TR-03116-4, IETF RFC 8996).

### Later Phases (Advanced Security Intelligence)
- Active STRIPTLS downgrade and MITM attack detection.
- Historical baseline comparison and configuration drift analysis across captures.
- "Before and after" patch remediation verification.
- Advanced forensic evidence integrity hashing.
- Exportable executive compliance and technical audit reports (PDF/JSON).
