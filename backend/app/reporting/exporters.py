import json
import html
from typing import Any, List
from app.reporting.models import InvestigationReport

def export_report_to_json(report: InvestigationReport) -> str:
    """Exports the complete InvestigationReport to machine-readable formatted JSON."""
    return json.dumps(report.model_dump(), indent=2, ensure_ascii=False)

def _esc(val: Any) -> str:
    """Safely escapes dynamic content for static HTML injection."""
    if val is None:
        return ""
    return html.escape(str(val))

def export_report_to_html(report: InvestigationReport) -> str:
    """
    Generates a standalone, beautiful, print-ready HTML report with embedded CSS.
    Zero external CDN requests or JavaScript required.
    """
    r_meta = report.report_metadata
    c_sum = report.capture_summary
    exec_sum = report.executive_summary
    posture = report.security_posture
    manifest = report.evidence_manifest
    is_real = not r_meta.is_simulated and r_meta.data_source == "REAL_CAPTURE"

    # Posture colors
    posture_color = {
        "CRITICAL": "#ef4444",
        "HIGH_RISK": "#f97316",
        "NEEDS_ATTENTION": "#eab308",
        "ACCEPTABLE": "#10b981",
        "UNKNOWN": "#64748b",
    }.get(posture.status, "#64748b")

    # Severity color helper
    def sev_badge(sev: str) -> str:
        colors = {
            "CRITICAL": ("#fee2e2", "#991b1b", "#ef4444"),
            "HIGH": ("#ffedd5", "#9a3412", "#f97316"),
            "MEDIUM": ("#fef9c3", "#854d0e", "#eab308"),
            "LOW": ("#e0f2fe", "#075985", "#0284c7"),
            "INFO": ("#f1f5f9", "#334155", "#64748b"),
        }
        bg, text, border = colors.get(sev, ("#f1f5f9", "#334155", "#64748b"))
        return f'<span style="background-color: {bg}; color: {text}; border: 1px solid {border}; font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; font-family: monospace; text-transform: uppercase;">{_esc(sev)}</span>'

    # Findings HTML
    findings_html = ""
    for idx, f in enumerate(report.deterministic_findings):
        ev_items_html = ""
        if f.evidence_items:
            ev_rows = "".join(
                f'<tr><td style="padding: 4px 8px; border-bottom: 1px solid #e2e8f0; font-family: monospace; font-size: 11px;">[{_esc(e.type)}] {_esc(e.field)}={_esc(e.value)}</td><td style="padding: 4px 8px; border-bottom: 1px solid #e2e8f0; font-size: 12px; color: #475569;">{_esc(e.description)}</td></tr>'
                for e in f.evidence_items
            )
            ev_items_html = f"""
            <div style="margin-top: 10px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 12px;">
                <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-bottom: 4px;">Structured Evidence Items:</div>
                <table style="width: 100%; border-collapse: collapse;">{ev_rows}</table>
            </div>
            """

        refs_html = ""
        if f.references:
            refs_str = " • ".join(_esc(ref) for ref in f.references)
            refs_html = f'<div style="margin-top: 6px; font-size: 11px; color: #64748b; font-family: monospace;"><strong>Standards References:</strong> {refs_str}</div>'

        session_tag = f'<span style="font-size: 11px; color: #64748b; font-family: monospace; margin-left: 8px;">Session: {_esc(f.related_session_id)}</span>' if f.related_session_id else ""

        remediation_html = ''
        if f.remediation:
            remediation_html = '<div><strong>[RULE] Recommended fix</strong><ol>' + ''.join('<li>'+_esc(step)+'</li>' for step in f.remediation.steps) + '</ol>'
            if f.remediation.snippet:
                snippet = f.remediation.snippet
                remediation_html += '<p>'+_esc(snippet.software)+' — '+_esc(snippet.warning)+'</p><p>'+_esc(snippet.scope)+'</p><pre style="white-space:pre-wrap">'+_esc(snippet.config)+'</pre>'
            remediation_html += '</div>'
        findings_html += f"""
        <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 16px; background-color: #ffffff; page-break-inside: avoid;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <div>
                    {sev_badge(f.severity)}
                    <span style="font-family: monospace; font-weight: 700; font-size: 13px; margin-left: 8px; color: #0f172a;">{_esc(f.rule_id)}</span>
                    <strong style="font-size: 14px; margin-left: 8px; color: #0f172a;">{_esc(f.title)}</strong>
                    {session_tag}
                </div>
                <span style="font-size: 11px; font-weight: 600; color: #475569; font-family: monospace; background: #f1f5f9; padding: 2px 6px; border-radius: 4px;">Confidence: {_esc(f.confidence)}</span>
            </div>
            <p style="margin: 8px 0 4px 0; font-size: 13px; color: #1e293b; line-height: 1.5;"><strong>Plain Explanation:</strong> {_esc(f.plain_explanation)}</p>
            <p style="margin: 4px 0; font-size: 12px; color: #475569; line-height: 1.4;"><strong>Technical Impact:</strong> {_esc(f.why_it_matters)}</p>
            <p style="margin: 4px 0; font-size: 12px; color: #0369a1; line-height: 1.4;"><strong>Remediation:</strong> {_esc(f.recommendation)}</p>
            {remediation_html}
            {ev_items_html}
            {refs_html}
        </div>
        """

    for c in report.session_evidence:
        q=c.get('quantum_readiness',{})
        if q:
            findings_html += '<div style="padding:12px;border:1px solid #ddd;margin-bottom:12px"><strong>INFO / ['+_esc(q['type'])+'] '+_esc(q['label'])+'</strong><p>'+_esc(c['session_id'])+' / '+_esc(q.get('group_name') or q.get('group') or 'UNKNOWN')+'</p><p>'+_esc(q['detail'])+'</p></div>'

    # Recommendations HTML
    rec_html = ""
    for r in report.recommendations:
        bridge_html = f'<span style="font-family: monospace; font-size: 10px; background: #e0f2fe; color: #0369a1; padding: 2px 6px; border-radius: 4px; margin-left: 8px;">Simulator Bridge: {_esc(r.policy_bridge)}</span>' if r.policy_bridge else ""
        rec_html += f"""
        <div style="display: flex; gap: 12px; align-items: flex-start; padding: 10px 14px; border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 8px; background: #ffffff; page-break-inside: avoid;">
            <div style="background: #0f172a; color: #ffffff; font-weight: 700; font-size: 12px; width: 24px; height: 24px; border-radius: 12px; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">{r.priority_rank}</div>
            <div style="flex: 1;">
                <div style="display: flex; align-items: center; margin-bottom: 4px;">
                    {sev_badge(r.severity)}
                    <span style="font-family: monospace; font-size: 11px; font-weight: 700; margin-left: 8px; color: #334155;">{_esc(r.rule_id)}</span>
                    {bridge_html}
                </div>
                <div style="font-weight: 600; font-size: 13px; color: #0f172a; margin-bottom: 2px;">{_esc(r.action)}</div>
                <div style="font-size: 12px; color: #64748b;">{_esc(r.rationale)}</div>
            </div>
        </div>
        """

    # Replays HTML
    replays_html = ""
    if report.security_replay_summary:
        replay_rows = "".join(
            f'<tr><td style="padding: 6px 10px; border-bottom: 1px solid #e2e8f0; font-family: monospace; font-size: 12px; font-weight: 600;">{_esc(rep.session_id)}</td><td style="padding: 6px 10px; border-bottom: 1px solid #e2e8f0; font-size: 12px;">{_esc(rep.protocol)}</td><td style="padding: 6px 10px; border-bottom: 1px solid #e2e8f0; font-size: 12px; font-family: monospace;">{_esc(rep.endpoints)}</td><td style="padding: 6px 10px; border-bottom: 1px solid #e2e8f0; font-size: 12px; text-align: center;">{rep.event_count}</td><td style="padding: 6px 10px; border-bottom: 1px solid #e2e8f0; font-size: 12px; color: #b91c1c; font-weight: 600;">{_esc(rep.critical_moment or "None")}</td></tr>'
            for rep in report.security_replay_summary
        )
        replays_html = f"""
        <table style="width: 100%; border-collapse: collapse; margin-top: 8px; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; overflow: hidden;">
            <thead>
                <tr style="background: #f8fafc; border-bottom: 2px solid #e2e8f0; text-align: left; font-size: 11px; text-transform: uppercase; color: #64748b;">
                    <th style="padding: 8px 10px;">Session ID</th>
                    <th style="padding: 8px 10px;">Protocol</th>
                    <th style="padding: 8px 10px;">Endpoints</th>
                    <th style="padding: 8px 10px; text-align: center;">Events</th>
                    <th style="padding: 8px 10px;">Critical Moment</th>
                </tr>
            </thead>
            <tbody>{replay_rows}</tbody>
        </table>
        """
    else:
        replays_html = '<div style="font-size: 12px; color: #64748b;">No visual session timelines reconstructed.</div>'

    # Limitations HTML
    limitations_html = "".join(
        f'<li style="margin-bottom: 4px; font-size: 12px; color: #475569; line-height: 1.4;">{_esc(lim)}</li>'
        for lim in report.limitations
    )

    # Provenance Badge Text
    prov_badge_html = f"""
    <span style="background: {'#ecfdf5' if is_real else '#fffbeb'}; color: {'#065f46' if is_real else '#92400e'}; border: 1px solid {'#a7f3d0' if is_real else '#fde68a'}; font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 6px; font-family: monospace; text-transform: uppercase;">
        {'SYNTHETIC LAB PCAP' if report.capture_origin == 'SYNTHETIC_LAB' else 'UPLOADED PCAP EVIDENCE' if is_real else 'SIMULATED DEMONSTRATION'}
    </span>
    """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureMailScope Report — {_esc(r_meta.report_id)}</title>
    <style>
        @page {{
            margin: 15mm;
            size: A4 portrait;
        }}
        body {{
            overflow-wrap: anywhere;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #0f172a;
            background-color: #f8fafc;
            margin: 0;
            padding: 24px;
            font-size: 13px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 960px;
            margin: 0 auto;
            background-color: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 32px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
        }}
        .header-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 24px;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 16px;
        }}
        .section-title {{
            font-size: 14px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #0f172a;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 6px;
            margin-top: 28px;
            margin-bottom: 14px;
        }}
        .grid-2 {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }}
        .grid-3 {{
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 12px;
        }}
        .stat-card {{
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 12px 16px;
        }}
        .stat-value {{
            font-size: 20px;
            font-weight: 800;
            color: #0f172a;
            font-family: monospace;
        }}
        .stat-label {{
            font-size: 11px;
            color: #64748b;
            text-transform: uppercase;
            font-weight: 600;
        }}
        .integrity-box {{
            background-color: #f8fafc;
            border: 1px solid #cbd5e1;
            border-left: 4px solid #0284c7;
            border-radius: 6px;
            padding: 12px 16px;
            font-family: monospace;
            font-size: 11px;
            line-height: 1.6;
        }}
        @media print {{
            body {{
                background-color: #ffffff;
                padding: 0;
            }}
            .container {{
                border: none;
                box-shadow: none;
                padding: 0;
                max-width: 100%;
            }}
            .no-print {{
                display: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Report Header -->
        <table class="header-table">
            <tr>
                <td style="vertical-align: top;">
                    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                        <span style="font-size: 20px; font-weight: 900; letter-spacing: -0.02em; color: #0f172a;">SECUREMAILSCOPE</span>
                        <span style="font-size: 10px; font-family: monospace; font-weight: 700; background: #0f172a; color: #ffffff; padding: 2px 6px; border-radius: 4px;">v{_esc(r_meta.engine_version)}</span>
                    </div>
                    <div style="font-size: 12px; color: #475569; font-weight: 600;">Cryptographic Security Posture Assessment for Secure Email Communications</div>
                    <div style="font-size: 11px; color: #64748b; margin-top: 2px;">SIH26159 — Offline-First Mail Transport Analysis</div>
                </td>
                <td style="text-align: right; vertical-align: top;">
                    <div style="margin-bottom: 6px;">{prov_badge_html}</div>
                    <div style="font-size: 11px; font-family: monospace; color: #334155;"><strong>Report ID:</strong> {_esc(r_meta.report_id)}</div>
                    <div style="font-size: 11px; font-family: monospace; color: #64748b;"><strong>Generated:</strong> {_esc(r_meta.generated_at)}</div>
                </td>
            </tr>
        </table>

        <!-- Capture & System Metadata Summary -->
        <div class="grid-3" style="margin-bottom: 16px;">
            <div class="stat-card">
                <div class="stat-label">Source Capture</div>
                <div style="font-weight: 700; font-size: 13px; color: #0f172a; font-family: monospace; word-break: break-all;">{_esc(c_sum.filename)}</div>
                <div style="font-size: 10px; color: #64748b; font-family: monospace;">SHA: {_esc(c_sum.capture_sha256_short)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Overall Security Posture</div>
                <div class="stat-value" style="color: {posture_color};">{_esc(posture.status)}</div>
                <div style="font-size: 10px; color: #64748b;">{posture.critical_count} Critical • {posture.high_count} High • {posture.medium_count} Med</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Observed Scope</div>
                <div class="stat-value">{c_sum.total_sessions} <span style="font-size: 12px; font-weight: 600; color: #64748b;">Session(s)</span></div>
                <div style="font-size: 10px; color: #64748b;">{c_sum.observed_clients_count} Client Endpoint(s) Discovered</div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="section-title">1. Executive Summary</div>
        <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 16px;">
            <h3 style="margin-top: 0; margin-bottom: 8px; font-size: 14px; font-weight: 700; color: #0f172a;">{_esc(exec_sum.headline)}</h3>
            <p style="margin: 6px 0; font-size: 13px; color: #1e293b; line-height: 1.5;">{_esc(exec_sum.transport_security_summary)}</p>
            <p style="margin: 6px 0; font-size: 13px; color: #1e293b; line-height: 1.5;">{_esc(exec_sum.posture_summary)} {_esc(exec_sum.key_findings_summary)}</p>
            <p style="margin: 6px 0; font-size: 12px; color: #475569; font-style: italic;">{_esc(exec_sum.ai_anomaly_summary)}</p>
        </div>

        <!-- Prioritized Recommendations -->
        <div class="section-title">2. Prioritized Administrator Recommendations</div>
        {rec_html}

        <!-- Deterministic Security Findings -->
        <div class="section-title">3. Deterministic Security Findings & Technical Evidence</div>
        {findings_html}

        <!-- Security Replay Journey -->
        <div class="section-title">4. Security Session Replay Summary</div>
        {replays_html}

        <!-- Hardening Impact & Client Discovery -->
        <div class="section-title">5. Hardening Impact & Observed Client Inventory</div>
        <div class="grid-2">
            <div class="stat-card">
                <div style="font-weight: 700; font-size: 12px; text-transform: uppercase; color: #0f172a; margin-bottom: 6px;">Passive Hardening Simulation</div>
                <p style="font-size: 12px; color: #475569; margin: 4px 0;">{_esc(report.hardening_impact_summary.summary_notes)}</p>
                <div style="margin-top: 8px; font-family: monospace; font-size: 11px;">
                    <strong>Simulated Compatibility:</strong>
                    <span style="color: #10b981; font-weight: 700; margin-left: 6px;">{report.hardening_impact_summary.client_compatibility_overview.get('COMPATIBLE', 0)} Compatible</span> •
                    <span style="color: #ef4444; font-weight: 700;">{report.hardening_impact_summary.client_compatibility_overview.get('WOULD_BREAK', 0)} Would Break</span> •
                    <span style="color: #64748b; font-weight: 700;">{report.hardening_impact_summary.client_compatibility_overview.get('UNKNOWN', 0)} Unknown</span>
                </div>
            </div>
            <div class="stat-card">
                <div style="font-weight: 700; font-size: 12px; text-transform: uppercase; color: #0f172a; margin-bottom: 6px;">Client Discovery & AI Outlier Status</div>
                <div style="font-size: 12px; color: #334155; margin-bottom: 4px;">
                    <strong>Inventory:</strong> {report.client_discovery_summary.total_observed_clients} total ({report.client_discovery_summary.modern_count} Modern, {report.client_discovery_summary.legacy_count} Legacy, {report.client_discovery_summary.cleartext_clients_count} Cleartext)
                </div>
                <div style="font-size: 12px; color: #475569;">
                    <strong>AI Engine:</strong> <span style="font-family: monospace; font-weight: 600;">{_esc(report.ai_assisted_prioritization.status)}</span> ({_esc(report.ai_assisted_prioritization.summary_explanation)})
                </div>
            </div>
        </div>

        <!-- Evidence Integrity & Merkle Evidence Root -->
        <div class="section-title">6. Cryptographic Evidence Integrity & Tamper Manifest</div>
        <div class="integrity-box">
            <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                <span style="font-weight: 700; color: #0f172a; font-size: 12px;">INTEGRITY MANIFEST: {_esc(manifest.integrity_status)}</span>
                <span style="color: #0284c7; font-weight: 700;">{_esc(manifest.integrity_algorithm)}</span>
            </div>
            <div><strong>Capture SHA-256:</strong> {_esc(manifest.capture_sha256)}</div>
            <div><strong>Findings Digest:</strong> {_esc(manifest.findings_digest)}</div>
            <div><strong>Replay Digest:</strong> {_esc(manifest.replay_digest)}</div>
            <div><strong>Discovery Digest:</strong> {_esc(manifest.discovery_digest)}</div>
            <div><strong>Simulation Digest:</strong> {_esc(manifest.simulation_digest)}</div>
            <div style="margin-top: 4px; padding-top: 4px; border-top: 1px dashed #cbd5e1;">
                <strong>Merkle Evidence Root:</strong> {_esc(manifest.evidence_root)}
            </div>
            <div><strong>Report Canonical Digest:</strong> {_esc(manifest.report_digest)}</div>
            <div style="margin-top: 6px; color: #059669; font-weight: 700; font-size: 11px;">
                ✓ {_esc(manifest.verification_statement)}
            </div>
        </div>

        <!-- Limitations & Privacy Statement -->
        <div class="section-title">7. Authoritative Limitations & Scope</div>
        <ul style="padding-left: 20px; margin: 8px 0;">{limitations_html}</ul>

        <div class="section-title">8. Privacy & Data Handling</div>
        <div style="background-color: #f1f5f9; border-radius: 6px; padding: 12px 16px; font-size: 12px; color: #334155; line-height: 1.5;">
            {_esc(report.privacy_statement)}
        </div>

        <!-- Report Footer -->
        <div style="margin-top: 32px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 11px; font-family: monospace; color: #94a3b8; display: flex; justify-content: space-between; align-items: center;">
            <span>SecureMailScope v{_esc(r_meta.engine_version)} • SIH26159</span>
            <span>Offline-First Evidence-Backed Transport Security</span>
        </div>
    </div>
</body>
</html>
"""
