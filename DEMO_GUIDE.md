# SecureMailScope — SIH 26159 demo (3–5 minutes)

Run `Start-SecureMailScope.ps1`, then open http://127.0.0.1:8000. Requires Python 3.14 and local TShark. Use the included frontend build; no cloud or active probing is involved. Dependency installation is a separate first-time setup step.

## 0:00–0:40 — Analyze actual packet bytes

Open **Analyze a capture**. Upload `sample-captures/lab-legacy-clients-offer.pcap`, or select **legacy clients offer** in the capture lab and click **Analyze lab capture**. Say: “This is a reproducible synthetic capture processed by the real TShark pipeline. Two clients use real OpenSSL modern handshakes; the two legacy negotiation fixtures are hand-built and do not represent completed connections; one stream lacks ClientHello.” Show the filename and synthetic provenance. Five sessions should appear.

## 0:40–1:30 — Findings and a concrete fix

Open **Security findings**, then the deprecated TLS 1.0 finding. Read the packet evidence separately from **[RULE] Recommended fix**. Expand the Postfix 3.6+ example: `smtpd_tls_mandatory_protocols = >=TLSv1.2` alongside required TLS. Point out **Review and test before applying**, the authenticated-submission scope, and the warning against blindly applying mandatory TLS to public port 25. This is advice, never an automatic server edit.

## 1:30–2:30 — Show WOULD_BREAK

Open **Hardening lab** with **Require TLS 1.2 or Newer** and **Disable Weak Cipher Suites** selected. Run the simulation. Expected result: **2 COMPATIBLE, 2 WOULD_BREAK, 1 UNKNOWN**.

- `192.0.2.23` offers only TLS 1.0: WOULD_BREAK under the minimum-version policy.
- `192.0.2.24` offers only 3DES: WOULD_BREAK under the weak-cipher policy.
- `192.0.2.25` has no visible ClientHello: UNKNOWN.

Show the actual offered lists and their OBSERVED labels. The verdict is a RULE comparison for the visible offers, not proof of all future client behavior. Missing evidence is not a failure. COMPATIBLE is limited to the selected policy checks, not certificate trust or successful delivery.

## 2:30–3:15 — JA3 and honest prioritisation

Open **Client intelligence**. Four clients have visible JA3 fingerprints; the missing-hello stream shows COVERAGE_GAP. JA3 is a handshake fingerprint, not a unique device/user/software identity. No online fingerprint lookup occurs.

Return to **Overview → Fix first → Explain ordering and weights**. Severity comes first, number of affected sessions second, Isolation Forest anomaly rank only breaks remaining ties. Show the actual weights and the label **Heuristic prioritisation, not a calibrated risk score**. When ML abstains, the list remains deterministic and has no anomaly tie-break.

## 3:15–3:45 — Optional quantum observation

Open the TLS 1.3 session for `192.0.2.21`. The INFO card shows its selected key-share group. Depending on the installed OpenSSL used to regenerate fixtures, it may be classical or a recognized hybrid group. Do not promise a PQ result: the capture determines it. Classical wording states “may be exposed to harvest-now-decrypt-later; this is an observation, not a vulnerability.” No failing check is generated.

## 3:45–4:30 — Export and verify

Open **Evidence report**. Show **VERIFIED** integrity, fixes and limitations, then export JSON, HTML and PDF. Explain that the report digest covers remediation, session metadata and fix-first ordering. A digest is not a digital signature; keep an independent trusted reference for later comparison.

## Optional backup captures

- `sample-captures/lab-mixed-fleet.pcap`: eight endpoints with cleartext AUTH and legacy selection, for a broader dashboard/ML example. Use the dedicated offer capture above for the WOULD_BREAK demonstration.
- `sample-captures/lab-expired-certificate.pcap`: expiration at capture time.
- `sample-captures/lab-ca-signed-tls12.pcap`: explicit offline trust demonstration after restarting with `-LabTrust`.
- `sample-captures/lab-clienthello-only.pcap`: unknown server selection.
- `sample-captures/lab-midstream-encrypted.pcap`: missing handshake and ML abstention.

PCAP processing temporarily reads full local capture files; results retain transport/certificate metadata, not credential parameters or mail bodies. Uploaded temporary files are removed after processing. Reports still contain endpoint and certificate identifiers. Never claim production certification, calibrated ML accuracy, decryption of email contents, or complete visibility into absent/encrypted packets.
