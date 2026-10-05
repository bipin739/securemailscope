from typing import List, Dict, Any, Optional, Tuple
from app.replay.models import (
    SecurityEvent,
    CriticalMoment,
    ReplaySummary,
    SessionReplay,
    SecurityState,
    TransportState,
    EventDirection,
)
from app.replay.sanitization import (
    sanitize_smtp_command,
    sanitize_smtp_response,
    sanitize_imap_pop_activity,
)
from app.models import SecurityFinding
from app.analysis.rules import EmailSessionContext

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "WARNING": 3,
    "UNKNOWN": 2,
    "SECURE": 1,
    "NEUTRAL": 0,
}

class ReplayBuilder:
    """
    Constructs deterministic, privacy-safe visual security replays for reconstructed email sessions.
    Strictly derives events from captured packet metadata and connects to Phase 2 security findings.
    """

    def build_replay(
        self,
        stream_id: str,
        pkts: List[Dict[str, Any]],
        context: Optional[EmailSessionContext] = None,
        findings: Optional[List[SecurityFinding]] = None,
    ) -> SessionReplay:
        findings = findings or []
        stream_findings = [f for f in findings if f.affected_connection_id in (f"conn-real-{stream_id}", f"conn-sim-{stream_id}") or not f.affected_connection_id]
        rule_ids = [f.rule_id for f in stream_findings]

        protocol = context.protocol if context else "SMTP"
        client_ip = context.client_ip if context else "10.0.0.1"
        client_port = context.client_port if context else 1024
        server_ip = context.server_ip if context else "10.0.0.2"
        server_port = context.server_port if context else 25

        session_id = f"{protocol}-STREAM-{stream_id}"
        client_endpoint = f"{client_ip}:{client_port}"
        server_endpoint = f"{server_ip}:{server_port}"

        events: List[SecurityEvent] = []
        event_counter = 1

        # Sort packets by relative time / frame number
        sorted_pkts = sorted(
            pkts,
            key=lambda p: (
                float(p.get("frame.time_relative") or 0.0),
                int(p.get("frame.number") or 0),
            ),
        )

        if not sorted_pkts:
            # Synthetic / empty fallback
            summary = ReplaySummary(
                session_id=session_id,
                protocol=protocol,
                client_endpoint=client_endpoint,
                server_endpoint=server_endpoint,
                started_at="0.000s",
                duration_ms=0.0,
                initial_transport="CLEARTEXT",
                final_transport="CLEARTEXT",
                event_count=0,
                highest_security_state="NEUTRAL",
            )
            return SessionReplay(session_id=session_id, protocol=protocol, summary=summary, events=[])

        # Track base time
        first_time_rel = float(sorted_pkts[0].get("frame.time_relative") or 0.0)
        last_time_rel = float(sorted_pkts[-1].get("frame.time_relative") or 0.0)
        started_at = sorted_pkts[0].get("frame.time_epoch") or f"{first_time_rel:.3f}s"
        duration_ms = max(0.0, (last_time_rel - first_time_rel) * 1000.0)

        # State tracking
        current_transport_state: TransportState = "CONNECTED_CLEAR"
        starttls_offered_in_session = context.starttls_advertised if context else False
        tls_established_in_session = (context.tls_version not in ("None", "NONE", "UNKNOWN", None)) if context else False
        
        # Flags to prevent redundant duplicate events
        saw_syn = False
        saw_server_greeting = False
        saw_client_greeting = False
        saw_starttls_ad = False
        saw_starttls_req = False
        saw_tls_client_hello = False
        saw_tls_established = False
        saw_auth = False
        saw_mail_tx = False
        saw_quit = False

        # Check if capture starts mid-session without initial handshake
        has_syn_or_greeting = any(
            str(p.get("tcp.flags.syn") or "").lower() in ("true", "1")
            or str(p.get("smtp.response.code") or "") == "220"
            for p in sorted_pkts[:3]
        )
        if not has_syn_or_greeting and len(sorted_pkts) > 0 and not str(sorted_pkts[0].get("frame.number")) in ("1", "2"):
            # Coverage gap: capture begins mid-session
            rel_ms = 0.0
            events.append(
                SecurityEvent(
                    event_id=f"evt-{stream_id}-{event_counter}",
                    session_id=session_id,
                    timestamp=started_at,
                    relative_time_ms=rel_ms,
                    direction="INTERNAL",
                    event_type="COVERAGE_GAP",
                    title="Capture Begins Mid-Session",
                    description="Capture started after initial TCP/protocol handshake; reconstructing observed subsequent packets.",
                    transport_state="CONNECTED_CLEAR",
                    security_state="UNKNOWN",
                    evidence_source=f"Frame {sorted_pkts[0].get('frame.number') or '1'}",
                    related_rule_ids=[r for r in ["SMS-COVERAGE-001"] if r in rule_ids],
                    metadata={"reason": "Missing initial connection handshake"},
                )
            )
            event_counter += 1

        for p in sorted_pkts:
            frame_num = str(p.get("frame.number") or "0")
            p_time_rel = float(p.get("frame.time_relative") or 0.0)
            rel_ms = max(0.0, (p_time_rel - first_time_rel) * 1000.0)

            syn = str(p.get("tcp.flags.syn") or "").lower() in ("true", "1")
            cmd = (p.get("smtp.req.command") or "").strip().upper()
            code = str(p.get("smtp.response.code") or "").strip()
            rsp_param = str(p.get("smtp.rsp.parameter") or "").upper()
            rsp_text = str(p.get("smtp.response") or "").upper()
            
            imap_cmd = str(p.get("imap.request.command") or p.get("imap.request") or "").strip().upper()
            imap_rsp = str(p.get("imap.response") or "").strip().upper()
            pop_cmd = str(p.get("pop.request.command") or p.get("pop.request") or "").strip().upper()
            pop_rsp = str(p.get("pop.response") or "").strip().upper()

            # 1. TCP Connection Established
            if syn and not saw_syn:
                saw_syn = True
                events.append(
                    SecurityEvent(
                        event_id=f"evt-{stream_id}-{event_counter}",
                        session_id=session_id,
                        timestamp=p.get("frame.time_epoch"),
                        relative_time_ms=rel_ms,
                        direction="CLIENT_TO_SERVER",
                        event_type="TCP_CONNECTION_ESTABLISHED",
                        title="TCP Connection Established",
                        description=f"Client initiated TCP connection to mail server at {server_endpoint}.",
                        transport_state=current_transport_state,
                        security_state="NEUTRAL",
                        evidence_source=f"Frame {frame_num} (SYN)",
                        metadata={"client": client_endpoint, "server": server_endpoint},
                    )
                )
                event_counter += 1

            # 2. Server 220 Greeting
            if (code == "220" or "220" in rsp_text or "* OK" in imap_rsp or "+OK" in pop_rsp) and not saw_server_greeting:
                saw_server_greeting = True
                title, desc, meta = sanitize_smtp_response("220", rsp_param, rsp_text)
                events.append(
                    SecurityEvent(
                        event_id=f"evt-{stream_id}-{event_counter}",
                        session_id=session_id,
                        timestamp=p.get("frame.time_epoch"),
                        relative_time_ms=rel_ms,
                        direction="SERVER_TO_CLIENT",
                        event_type="SERVER_GREETING",
                        title=title,
                        description=desc,
                        transport_state=current_transport_state,
                        security_state="NEUTRAL",
                        evidence_source=f"Frame {frame_num} ({protocol} 220 Ready)",
                        metadata=meta,
                    )
                )
                event_counter += 1

            # 3. Client Greeting (EHLO / HELO / CAPABILITY)
            if (cmd.startswith("EHLO") or cmd.startswith("HELO") or "CAPABILITY" in imap_cmd or "CAPA" in pop_cmd) and not saw_client_greeting:
                saw_client_greeting = True
                title, desc, meta = sanitize_smtp_command(cmd or imap_cmd or pop_cmd, None)
                events.append(
                    SecurityEvent(
                        event_id=f"evt-{stream_id}-{event_counter}",
                        session_id=session_id,
                        timestamp=p.get("frame.time_epoch"),
                        relative_time_ms=rel_ms,
                        direction="CLIENT_TO_SERVER",
                        event_type="CLIENT_GREETING",
                        title=title,
                        description=desc,
                        transport_state=current_transport_state,
                        security_state="NEUTRAL",
                        evidence_source=f"Frame {frame_num} ({cmd or 'EHLO'})",
                        metadata=meta,
                    )
                )
                event_counter += 1

            # 4. STARTTLS Advertised
            if ("STARTTLS" in rsp_param or "STARTTLS" in rsp_text or "STARTTLS" in imap_rsp or "STLS" in pop_rsp) and not saw_starttls_ad:
                saw_starttls_ad = True
                current_transport_state = "TLS_AVAILABLE"
                related_rules = ["SMS-STARTTLS-001"] if (context and not context.starttls_used) else []
                sec_state: SecurityState = "WARNING" if (context and not context.starttls_used) else "SECURE"
                events.append(
                    SecurityEvent(
                        event_id=f"evt-{stream_id}-{event_counter}",
                        session_id=session_id,
                        timestamp=p.get("frame.time_epoch"),
                        relative_time_ms=rel_ms,
                        direction="SERVER_TO_CLIENT",
                        event_type="STARTTLS_ADVERTISED",
                        title="STARTTLS Capability Advertised",
                        description="Mail server advertised STARTTLS transport encryption capability.",
                        transport_state=current_transport_state,
                        security_state=sec_state,
                        evidence_source=f"Frame {frame_num} (250-STARTTLS)",
                        related_rule_ids=[r for r in related_rules if r in rule_ids],
                        metadata={"capability": "STARTTLS", "status": "AVAILABLE"},
                    )
                )
                event_counter += 1

            # 5. STARTTLS Requested
            if (cmd == "STARTTLS" or "STARTTLS" in imap_cmd or "STLS" in pop_cmd) and not saw_starttls_req:
                saw_starttls_req = True
                current_transport_state = "TLS_REQUESTED"
                events.append(
                    SecurityEvent(
                        event_id=f"evt-{stream_id}-{event_counter}",
                        session_id=session_id,
                        timestamp=p.get("frame.time_epoch"),
                        relative_time_ms=rel_ms,
                        direction="CLIENT_TO_SERVER",
                        event_type="STARTTLS_REQUESTED",
                        title="STARTTLS Requested",
                        description="Client issued STARTTLS command to initiate cryptographic handshake.",
                        transport_state=current_transport_state,
                        security_state="SECURE",
                        evidence_source=f"Frame {frame_num} (STARTTLS Command)",
                        metadata={"command": "STARTTLS"},
                    )
                )
                event_counter += 1

            # 6. TLS Handshake Records
            hs_type = str(p.get("tls.handshake.type") or "")
            if "1" in hs_type.split(",") and not saw_tls_client_hello:
                saw_tls_client_hello = True
                current_transport_state = "TLS_HANDSHAKE"
                events.append(
                    SecurityEvent(
                        event_id=f"evt-{stream_id}-{event_counter}",
                        session_id=session_id,
                        timestamp=p.get("frame.time_epoch"),
                        relative_time_ms=rel_ms,
                        direction="CLIENT_TO_SERVER",
                        event_type="TLS_HANDSHAKE_STARTED",
                        title="TLS Handshake Initiated (ClientHello)",
                        description="Client transmitted TLS ClientHello offering supported cipher suites and versions.",
                        transport_state=current_transport_state,
                        security_state="NEUTRAL",
                        evidence_source=f"Frame {frame_num} (TLS ClientHello)",
                        metadata={"handshake": "ClientHello"},
                    )
                )
                event_counter += 1

            # 7. TLS Established
            tls_v_raw = p.get("tls.handshake.version") or p.get("tls.record.version")
            if "2" in hs_type.split(",") and str(p.get("tcp.srcport")) == str(server_port) and not saw_tls_established:
                saw_tls_established = True
                current_transport_state = "TLS_PROTECTED"
                tls_ver_str = context.tls_version if context else "TLS"
                cipher_str = context.cipher_suite if context else "Negotiated Cipher"
                
                sec_state: SecurityState = "SECURE"
                related_rules = []
                if tls_ver_str in ("TLS 1.0", "TLS 1.1", "SSL 3.0"):
                    sec_state = "WARNING"
                    related_rules.append("SMS-TLSVER-001")
                elif any(k in cipher_str for k in ("RC4", "3DES", "DES", "NULL", "EXPORT")):
                    sec_state = "WARNING"
                    related_rules.append("SMS-CIPHER-001")
                elif tls_ver_str in ("TLS 1.2", "TLS 1.3"):
                    related_rules.append("SMS-TLSVER-002")

                events.append(
                    SecurityEvent(
                        event_id=f"evt-{stream_id}-{event_counter}",
                        session_id=session_id,
                        timestamp=p.get("frame.time_epoch"),
                        relative_time_ms=rel_ms,
                        direction="SERVER_TO_CLIENT",
                        event_type="TLS_ESTABLISHED",
                        title=f"ServerHello selection ({tls_ver_str})",
                        description=f"Server selected {tls_ver_str} with cipher suite {cipher_str}. This event alone does not prove handshake completion or certificate trust.",
                        transport_state=current_transport_state,
                        security_state=sec_state,
                        evidence_source=f"Frame {frame_num} (ServerHello / TLS {tls_ver_str})",
                        related_rule_ids=[r for r in related_rules if r in rule_ids],
                        metadata={"tls_version": tls_ver_str, "cipher_suite": cipher_str},
                    )
                )
                event_counter += 1

            # 8. Authentication Observation
            is_auth_cmd = (
                cmd.startswith("AUTH")
                or "LOGIN" in imap_cmd
                or "AUTHENTICATE" in imap_cmd
                or pop_cmd.startswith("USER")
                or pop_cmd.startswith("PASS")
                or pop_cmd.startswith("AUTH")
            )
            if is_auth_cmd and not saw_auth:
                saw_auth = True
                if current_transport_state in ("CONNECTED_CLEAR", "TLS_AVAILABLE"):
                    # CRITICAL: Authentication before TLS!
                    events.append(
                        SecurityEvent(
                            event_id=f"evt-{stream_id}-{event_counter}",
                            session_id=session_id,
                            timestamp=p.get("frame.time_epoch"),
                            relative_time_ms=rel_ms,
                            direction="CLIENT_TO_SERVER",
                            event_type="AUTHENTICATION_ATTEMPT",
                            title="Authentication Attempt",
                            description="Client initiated authentication handshake over unencrypted cleartext transport.",
                            transport_state=current_transport_state,
                            security_state="CRITICAL",
                            evidence_source=f"Frame {frame_num} (AUTH Command)",
                            related_rule_ids=[r for r in ["SMS-AUTH-001", "SMS-TLS-001"] if r in rule_ids],
                            metadata={"command": "AUTH", "mode": "CLEARTEXT"},
                        )
                    )
                    event_counter += 1

                    events.append(
                        SecurityEvent(
                            event_id=f"evt-{stream_id}-{event_counter}",
                            session_id=session_id,
                            timestamp=p.get("frame.time_epoch"),
                            relative_time_ms=rel_ms + 1.0,
                            direction="INTERNAL",
                            event_type="AUTHENTICATION_BEFORE_TLS",
                            title="Authentication Before TLS",
                            description="Pivotal security exposure: Authentication occurred while transport remained in cleartext without TLS protection.",
                            transport_state=current_transport_state,
                            security_state="CRITICAL",
                            evidence_source=f"Frame {frame_num} (Unencrypted AUTH)",
                            related_rule_ids=[r for r in ["SMS-AUTH-001"] if r in rule_ids],
                            metadata={"impact": "Credential exposure risk on cleartext network"},
                        )
                    )
                    event_counter += 1
                else:
                    # Authenticated under protected TLS
                    events.append(
                        SecurityEvent(
                            event_id=f"evt-{stream_id}-{event_counter}",
                            session_id=session_id,
                            timestamp=p.get("frame.time_epoch"),
                            relative_time_ms=rel_ms,
                            direction="CLIENT_TO_SERVER",
                            event_type="AUTHENTICATION_ATTEMPT",
                            title="Authentication Attempt (Protected)",
                            description="Client transmitted authentication credentials inside the established encrypted TLS tunnel.",
                            transport_state="TLS_PROTECTED",
                            security_state="SECURE",
                            evidence_source=f"Frame {frame_num} (Protected AUTH)",
                            metadata={"command": "AUTH", "mode": "TLS_PROTECTED"},
                        )
                    )
                    event_counter += 1

            # 9. Mail Transaction (MAIL FROM / RCPT TO / DATA / IMAP FETCH)
            is_mail_tx = (
                any(cmd.startswith(k) for k in ("MAIL FROM", "RCPT TO", "DATA", "BDAT"))
                or any(k in imap_cmd for k in ("SELECT", "FETCH", "STORE"))
                or any(pop_cmd.startswith(k) for k in ("RETR", "LIST", "DELE"))
            )
            if is_mail_tx and not saw_mail_tx:
                saw_mail_tx = True
                tx_sec_state: SecurityState = "CRITICAL" if current_transport_state in ("CONNECTED_CLEAR", "TLS_AVAILABLE") else "SECURE"
                tx_desc = (
                    "Client initiated message envelope and payload transfer over unencrypted transport."
                    if tx_sec_state == "CRITICAL"
                    else "Client initiated message envelope and payload transfer inside encrypted TLS channel."
                )
                events.append(
                    SecurityEvent(
                        event_id=f"evt-{stream_id}-{event_counter}",
                        session_id=session_id,
                        timestamp=p.get("frame.time_epoch"),
                        relative_time_ms=rel_ms,
                        direction="CLIENT_TO_SERVER",
                        event_type="MAIL_TRANSACTION_STARTED",
                        title="Mail Transaction",
                        description=tx_desc,
                        transport_state=current_transport_state,
                        security_state=tx_sec_state,
                        evidence_source=f"Frame {frame_num} (Mail Transaction)",
                        related_rule_ids=[r for r in ["SMS-TLS-001"] if r in rule_ids and tx_sec_state == "CRITICAL"],
                        metadata={"phase": "TRANSACTION", "transport": current_transport_state},
                    )
                )
                event_counter += 1

            # 10. QUIT / Session Termination
            if (cmd.startswith("QUIT") or "LOGOUT" in imap_cmd or pop_cmd.startswith("QUIT") or code == "221") and not saw_quit:
                saw_quit = True
                current_transport_state = "SESSION_ENDED"
                events.append(
                    SecurityEvent(
                        event_id=f"evt-{stream_id}-{event_counter}",
                        session_id=session_id,
                        timestamp=p.get("frame.time_epoch"),
                        relative_time_ms=rel_ms,
                        direction="CLIENT_TO_SERVER" if not code == "221" else "SERVER_TO_CLIENT",
                        event_type="SESSION_TERMINATED",
                        title="Session Terminated (QUIT)",
                        description="Client requested connection closure via QUIT.",
                        transport_state=current_transport_state,
                        security_state="NEUTRAL",
                        evidence_source=f"Frame {frame_num} (QUIT / 221)",
                        metadata={"command": "QUIT"},
                    )
                )
                event_counter += 1

        # Determine Highest Security State
        highest_state: SecurityState = "NEUTRAL"
        for evt in events:
            if SEVERITY_ORDER.get(evt.security_state, 0) > SEVERITY_ORDER.get(highest_state, 0):
                highest_state = evt.security_state

        # Determine Critical Moment
        critical_moment: Optional[CriticalMoment] = None
        for evt in events:
            if evt.event_type == "AUTHENTICATION_BEFORE_TLS" or ("SMS-AUTH-001" in evt.related_rule_ids and evt.security_state == "CRITICAL"):
                critical_moment = CriticalMoment(
                    event_id=evt.event_id,
                    title="Authentication Before TLS",
                    reason="Authentication credentials were submitted while the session remained unencrypted.",
                    rule_id="SMS-AUTH-001",
                    severity="CRITICAL",
                )
                break

        if not critical_moment:
            for evt in events:
                if evt.event_type == "STARTTLS_ADVERTISED" and "SMS-STARTTLS-001" in evt.related_rule_ids:
                    critical_moment = CriticalMoment(
                        event_id=evt.event_id,
                        title="STARTTLS Offered But Not Used",
                        reason="Mail server advertised STARTTLS capability, but the client continued in cleartext.",
                        rule_id="SMS-STARTTLS-001",
                        severity="HIGH",
                    )
                    break

        if not critical_moment:
            for evt in events:
                if evt.event_type == "MAIL_TRANSACTION_STARTED" and "SMS-TLS-001" in evt.related_rule_ids:
                    critical_moment = CriticalMoment(
                        event_id=evt.event_id,
                        title="Cleartext Email Transport",
                        reason="Email payload transmitted across the network without transport-layer encryption.",
                        rule_id="SMS-TLS-001",
                        severity="HIGH",
                    )
                    break

        if not critical_moment:
            for evt in events:
                if evt.event_type == "TLS_ESTABLISHED" and ("SMS-TLSVER-001" in evt.related_rule_ids or "SMS-CIPHER-001" in evt.related_rule_ids):
                    rule_id = "SMS-TLSVER-001" if "SMS-TLSVER-001" in evt.related_rule_ids else "SMS-CIPHER-001"
                    critical_moment = CriticalMoment(
                        event_id=evt.event_id,
                        title=evt.title,
                        reason="Session negotiated an obsolete TLS version or insecure cipher suite.",
                        rule_id=rule_id,
                        severity="HIGH",
                    )
                    break

        summary = ReplaySummary(
            session_id=session_id,
            protocol=protocol,
            client_endpoint=client_endpoint,
            server_endpoint=server_endpoint,
            started_at=started_at,
            duration_ms=round(duration_ms, 2),
            initial_transport="CLEARTEXT",
            final_transport="TLS_PROTECTED" if saw_tls_established else "UNKNOWN" if context and context.tls_version == 'UNKNOWN' else "CLEARTEXT",
            event_count=len(events),
            highest_security_state=highest_state,
            critical_event_id=critical_moment.event_id if critical_moment else None,
            critical_event_title=critical_moment.title if critical_moment else None,
            related_findings=rule_ids,
        )

        return SessionReplay(
            session_id=session_id,
            protocol=protocol,
            summary=summary,
            critical_moment=critical_moment,
            events=events,
        )
