# SecureMailScope — Demo Video Package
**SIH 2026 | Problem Statement 26159**

This folder contains all artifacts, automation scripts, audio assets, and recordings used to generate the continuous 90-second screen-capture demo video for **SecureMailScope**.

---

## 📁 Directory Structure & File Manifest

| File / Folder | Purpose |
| :--- | :--- |
| [`SecureMailScope_Demo_Video.mp4`](./SecureMailScope_Demo_Video.mp4) | **Final Mastered Demo Video** (1920x1080 @ 30fps, 90.0s, H.264 / AAC, 18.92 MB). |
| [`record_demo_video.py`](./record_demo_video.py) | **Automated Single-Pass Recorder**: Pre-warms app, controls Chromium via Playwright, renders 60fps easing cursor and burned-in captions, and post-processes with FFmpeg. |
| [`generate_voiceover.py`](./generate_voiceover.py) | **Voiceover Generator**: Uses Microsoft Edge Neural TTS (`en-US-ChristopherNeural`) to synthesize narrative segments and assemble a timed 90-second audio track. |
| [`assemble_audio.py`](./assemble_audio.py) | Standalone helper script for audio delays and mixing via FFmpeg filtergraph. |
| [`test_demo_flow.py`](./test_demo_flow.py) | Playwright test script verifying all UI selectors, tabs, and API endpoints before recording. |
| [`voiceover/`](./voiceover/) | Individual speech audio segments and the assembled `full_voiceover_90s.mp3`. |
| [`recordings/`](./recordings/) | Raw WebM screen captures produced during the Playwright recording session. |

---

## 🎬 Video Specifications

* **Resolution**: `1920x1080` (1080p, 16:9 widescreen, SAR 1:1)
* **Duration**: `90.00 seconds` (strictly within the 85–95s window)
* **Framerate**: `30.00 fps` (Progressive)
* **Video Encoding**: `H.264 / AVC1 High Profile` (`crf=18`, `preset=medium`)
* **Audio Encoding**: `AAC Stereo 44.1 kHz, 120 kb/s`
* **Captions**: Burned-in bottom-left, dark glassmorphic rounded container, 28px Inter typography.
* **Integrity & Flow**: Zero blank or idle frames; 60fps RequestAnimationFrame micro-motion loop; verified with FFmpeg `freezedetect` and `blackdetect`.

---

## ⏱️ Video Timeline Walkthrough

1. **0:00 – 0:10 \| Capture Lab Analysis**
   * Selects `legacy clients offer` (`sample-captures/lab-legacy-clients-offer.pcap`) and triggers **Analyze lab capture**.
   * Rebuilds 5 distinct mail sessions from authentic offline packet bytes.
   * *Caption*: `"Real packet bytes in, TShark pipeline, fully offline."`
2. **0:10 – 0:30 \| Security Findings & Concrete Fix Guidance**
   * Opens **Security findings**, inspects the **Deprecated TLS 1.0 Negotiated** finding.
   * Reviews packet evidence items and expands the **Postfix 3.6+ configuration snippet** (`smtpd_tls_mandatory_protocols = >=TLSv1.2`).
   * *Caption*: `"Evidence + RULE-based fix guidance. Never auto-applied."`
3. **0:30 – 0:55 \| Hardening Lab Simulation**
   * Selects **Require TLS 1.2 or Newer** and **Disable Weak Cipher Suites**, clicks **Run Simulation**.
   * Demonstrates compatibility breakdown: **2 COMPATIBLE \| 2 WOULD_BREAK \| 1 UNKNOWN**.
   * Expands client `192.0.2.23` (TLS 1.0 only, confirmed `WOULD_BREAK`).
   * *Caption*: `"Know what breaks BEFORE you harden."`
4. **0:55 – 1:10 \| Client Intelligence & Honest Prioritisation**
   * Inspects client inventory with **offline JA3 fingerprints** and `[COVERAGE_GAP]` for missing ClientHello.
   * Navigates to Overview, opens **Fix first**, and expands **"Explain ordering and weights"**.
   * *Caption*: `"Offline JA3. Honest, explainable prioritisation."`
5. **1:10 – 1:25 \| Evidence Report & Integrity Verification**
   * Shows the **VERIFIED** integrity status and Merkle digest.
   * Triggers exports for **JSON**, **HTML**, and **PDF**.
   * *Caption*: `"Tamper-evident reports with SHA-256 digests."`
6. **1:25 – 1:30 \| End Card**
   * Clean dark finish:
     `SecureMailScope | SIH 2026 | PS 26159 | Offline. Passive. Evidence-labelled.`
     `github.com/bipin739/securemailscope`

---

## 🚀 How to Re-generate the Video

1. **Ensure Backend is Running**:
   ```powershell
   # From workspace root
   .\Start-SecureMailScope.ps1
   ```
2. **Re-synthesize Voiceover (Optional)**:
   ```powershell
   python .\video_demo\generate_voiceover.py
   ```
3. **Execute Full Automated Recording & Post-Processing**:
   ```powershell
   python .\video_demo\record_demo_video.py
   ```
   *The script automatically pre-warms the app, launches Chromium with the custom cursor and caption overlay, performs the timeline actions in a single continuous pass, and encodes `SecureMailScope_Demo_Video.mp4` with FFmpeg 7.1.*
