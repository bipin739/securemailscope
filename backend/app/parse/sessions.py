from typing import List, Dict, Any, Optional, Set, Tuple
import datetime
from app.models import (
    Investigation,
    SummaryStats,
    NetworkNode,
    NetworkConnection,
    ConnectionEvidence,
    PlainLanguageExploration,
    SecurityFinding,
)
from app.analysis.evidence import Evidence
from app.parse.certificates import extract_certificates
from app.parse.client_hello import extract_client_hellos
from app.analysis.quantum import quantum_indicator
from app.analysis.normalization import normalize_tls_version, normalize_cipher_suite, CIPHER_HEX_MAP
from app.analysis.rules import EmailSessionContext
from app.analysis.scoring import calculate_security_posture
from app.analysis.engine import SecurityAnalysisEngine

MAIL_PORTS = {25, 465, 587, 143, 993, 110, 995}
DIRECT_TLS_PORTS = {465, 993, 995}

def clean_ip(ip_val: Optional[str]) -> Optional[str]:
    """Extracts a clean single IP if TShark outputs comma-separated values (e.g. from ICMP encapsulation)."""
    if not ip_val:
        return None
    val = ip_val.strip()
    if "," in val:
        parts = [p.strip() for p in val.split(",") if p.strip()]
        return parts[-1] if parts else None
    return val

def extract_stream_endpoints(pkts: List[Dict[str, Any]]) -> Tuple[str, int, str, int]:
    """
    Robustly determines the Client and Server IP/Port for a TCP stream by inspecting
    TCP port assignments and SYN handshake frames across all packets in the stream.
    """
    # 1. Search for known mail server ports in destination
    for p in pkts:
        src = clean_ip(p.get("ip.src") or p.get("ipv6.src"))
        dst = clean_ip(p.get("ip.dst") or p.get("ipv6.dst"))
        try:
            s_port = int(p.get("tcp.srcport") or 0)
            d_port = int(p.get("tcp.dstport") or 0)
        except ValueError:
            continue

        if src and dst:
            if d_port in MAIL_PORTS:
                return src, s_port, dst, d_port
            elif s_port in MAIL_PORTS:
                return dst, d_port, src, s_port

    # 2. Check SYN flag packet
    for p in pkts:
        syn = str(p.get("tcp.flags.syn") or "").lower()
        if syn in ("true", "1"):
            src = clean_ip(p.get("ip.src") or p.get("ipv6.src"))
            dst = clean_ip(p.get("ip.dst") or p.get("ipv6.dst"))
            try:
                s_port = int(p.get("tcp.srcport") or 0)
                d_port = int(p.get("tcp.dstport") or 0)
                if src and dst:
                    return src, s_port, dst, d_port
            except ValueError:
                pass

    # 3. Fallback to first packet with valid IP
    for p in pkts:
        src = clean_ip(p.get("ip.src") or p.get("ipv6.src"))
        dst = clean_ip(p.get("ip.dst") or p.get("ipv6.dst"))
        try:
            s_port = int(p.get("tcp.srcport") or 0)
            d_port = int(p.get("tcp.dstport") or 0)
            if src and dst:
                return src, s_port, dst, d_port
        except ValueError:
            pass

    return "0.0.0.0", 0, "0.0.0.0", 0

def reconstruct_investigation_from_packets(
    filename: str,
    sha256_full: str,
    sha256_short: str,
    packet_records: List[Dict[str, Any]],
) -> Investigation:
    """
    Reconstructs email transport sessions from TShark extracted packet records
    and evaluates deterministic, explainable security findings using the Phase 2 engine.
    """
    # 1. Group records by TCP Stream ID
    stream_map: Dict[str, List[Dict[str, Any]]] = {}
    for pkt in packet_records:
        stream_id = pkt.get("tcp.stream")
        if stream_id is None:
            src = clean_ip(pkt.get("ip.src") or pkt.get("ipv6.src")) or "unknown"
            dst = clean_ip(pkt.get("ip.dst") or pkt.get("ipv6.dst")) or "unknown"
            s_port = pkt.get("tcp.srcport") or "0"
            d_port = pkt.get("tcp.dstport") or "0"
            stream_id = f"{src}:{s_port}-{dst}:{d_port}"
        
        stream_map.setdefault(str(stream_id), []).append(pkt)

    session_contexts: List[EmailSessionContext] = []
    
    for stream_id, pkts in stream_map.items():
        if not pkts:
            continue
        pkts.sort(key=lambda p: int(p.get("frame.number") or 0))

        # Extract Client and Server endpoints
        client_ip, client_port, server_ip, server_port = extract_stream_endpoints(pkts)
        if server_ip == "0.0.0.0" and client_ip == "0.0.0.0":
            continue

        # Protocol Identification
        protocol = "UNKNOWN"
        all_protocols = " ".join(
            str(p.get("_ws.col.protocol") or p.get("_ws.col.Protocol") or "") for p in pkts
        ).upper()

        has_smtp_indicators = (
            "SMTP" in all_protocols
            or server_port in {25, 465, 587}
            or any(p.get("smtp.req.command") for p in pkts)
            or any(p.get("smtp.response.code") for p in pkts)
            or any(p.get("smtp.response") for p in pkts)
        )
        has_imap_indicators = (
            "IMAP" in all_protocols
            or server_port in {143, 993}
            or any(p.get("imap.request.command") or p.get("imap.request") for p in pkts)
        )
        has_pop_indicators = (
            "POP" in all_protocols
            or server_port in {110, 995}
            or any(p.get("pop.request.command") or p.get("pop.request") for p in pkts)
        )

        if has_smtp_indicators:
            protocol = "SMTP"
        elif has_imap_indicators:
            protocol = "IMAP"
        elif has_pop_indicators:
            protocol = "POP3"

        # If not a mail transport session, skip stream
        if protocol == "UNKNOWN" and not (server_port in MAIL_PORTS or client_port in MAIL_PORTS):
            continue
        elif protocol == "UNKNOWN":
            protocol = "SMTP"

        # Inspect STARTTLS advertised, STARTTLS used, Auth, Handshake, TLS Version, Cipher, SNI
        starttls_advertised = False
        starttls_used = False
        auth_observed = False
        auth_before_tls = False
        raw_tls_version = None
        raw_cipher = None
        sni = None
        tls_observed = False
        plaintext_observed = False
        key_share = False
        server_key_share_group = None
        requested = False
        accepted = False
        server_hello_frame = None

        for p in pkts:
            cmd = (p.get("smtp.req.command") or "").upper().strip()
            rsp_param = str(p.get("smtp.rsp.parameter") or "").upper()
            rsp_text = str(p.get("smtp.response") or "").upper()
            
            imap_cmd = str(p.get("imap.request.command") or p.get("imap.request") or "").upper()
            imap_rsp = str(p.get("imap.response") or "").upper()

            pop_cmd = str(p.get("pop.request.command") or p.get("pop.request") or "").upper()
            pop_rsp = ' '.join(str(p.get(k) or '') for k in ('pop.response','pop.response.indicator','pop.response.description')).upper()

            # 1. STARTTLS Advertised observation
            if "STARTTLS" in rsp_param or "STARTTLS" in rsp_text or "STARTTLS" in imap_rsp or "STLS" in pop_rsp:
                starttls_advertised = True

            # 2. STARTTLS Used observation
            if cmd == "STARTTLS" or "STARTTLS" in imap_cmd or "STLS" in pop_cmd:
                requested = True

            is_server = str(p.get("tcp.srcport")) == str(server_port)
            if requested and is_server and (
                str(p.get("smtp.response.code") or "") == "220"
                or " OK" in (" " + imap_rsp)
                or "+OK" in pop_rsp
            ):
                accepted = True
            if cmd.split(' ')[0] in ('AUTH', 'MAIL', 'RCPT', 'DATA') or any(k in imap_cmd for k in ('LOGIN', 'AUTHENTICATE', 'SELECT', 'FETCH')) or pop_cmd in ('USER','PASS','AUTH','RETR'):
                plaintext_observed = True

            # 3. Authentication Observation (Metadata only - never store passwords/credentials)
            if cmd in ("AUTH", "AUTH LOGIN", "AUTH PLAIN") or "LOGIN" in imap_cmd or "AUTHENTICATE" in imap_cmd or pop_cmd in ("USER", "PASS", "AUTH"):
                auth_observed = True
                if not raw_tls_version:
                    auth_before_tls = True

            # Only a server's ServerHello proves selection. ClientHello and record
            # legacy versions cannot establish the negotiated version or cipher.
            hs_types = str(p.get("tls.handshake.type") or "").split(",")
            tls_observed |= bool(p.get("tls.record.version") or p.get("tls.handshake.type"))
            if "2" in hs_types and is_server:
                raw_tls_version = str(p.get("tls.handshake.extensions.supported_version") or p.get("tls.handshake.version") or "").split(",")[0] or None
                raw_cipher = str(p.get("tls.handshake.ciphersuite") or "").split(",")[0] or None
                random = str(p.get('tls.handshake.random') or '').replace(':','').lower()
                is_retry = random == 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c'
                server_key_share_group = None if is_retry else str(p.get('tls.handshake.extensions_key_share_group') or '').split(',')[0] or None
                key_share = bool(server_key_share_group)
                server_hello_frame = p.get("frame.number")

            ext_sni = p.get("tls.handshake.extensions_server_name")
            if ext_sni and not sni:
                sni = ext_sni

        starttls_used = requested and accepted and raw_tls_version is not None
        tls_version = normalize_tls_version(raw_tls_version)
        if not raw_tls_version and (tls_observed or requested or server_port in DIRECT_TLS_PORTS or not plaintext_observed):
            tls_version = "UNKNOWN"
        cipher_suite = normalize_cipher_suite(raw_cipher, tls_version)

        # Determine Transport Mode
        if tls_version == "UNKNOWN":
            transport_mode = "UNKNOWN (Handshake not captured)"
        elif server_port in DIRECT_TLS_PORTS and tls_version != "None":
            transport_mode = "Direct TLS (Implicit)"
        elif starttls_used and tls_version != "None":
            transport_mode = "STARTTLS (Explicit)"
        elif tls_version != "None":
            transport_mode = "Explicit TLS"
        elif starttls_advertised and not starttls_used:
            transport_mode = "CLEARTEXT (STARTTLS Offered but Not Used)"
        else:
            transport_mode = "CLEARTEXT"

        # Perfect forward secrecy and AEAD detection
        has_pfs = key_share if tls_version == "TLS 1.3" else any(k in cipher_suite for k in ("ECDHE", "DHE"))
        has_aead = any(k in cipher_suite for k in ("GCM", "POLY1305", "CCM", "TLS_AES_"))

        session_contexts.append(
            EmailSessionContext(
                stream_id=str(stream_id),
                protocol=protocol,
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                transport_mode=transport_mode,
                tls_version=tls_version,
                cipher_suite=cipher_suite,
                raw_version=raw_tls_version,
                raw_cipher=raw_cipher,
                sni=sni,
                has_pfs=has_pfs,
                has_aead=has_aead,
                packet_count=len(pkts),
                starttls_advertised=starttls_advertised,
                starttls_used=starttls_used,
                auth_observed=auth_observed,
                auth_before_tls=auth_before_tls,
                starttls_requested=requested,
                starttls_accepted=accepted,
                plaintext_observed=plaintext_observed,
                tls_observed=tls_observed,
                capture_gaps=any(p.get('tcp.analysis.lost_segment') for p in pkts),
                server_hello_frame=server_hello_frame,
                server_key_share_group=server_key_share_group,
                quantum_readiness=quantum_indicator(tls_version,server_key_share_group,server_hello_frame),
                certificates=extract_certificates(pkts, sni, server_port),
                client_hello_offers=extract_client_hellos(pkts, client_ip, client_port),
            )
        )

    # If no mail sessions found, return empty investigation with clear finding
    if not session_contexts:
        no_mail_finding = SecurityFinding(
            id="FIND-REAL-000",
            title="No Email Transport Sessions Identified",
            severity="INFO",
            category="Capture Scope",
            status="UNKNOWN",
            confidence="HIGH",
            affected_connection_id=None,
            location="Network Capture Scope",
            plain_explanation="No SMTP, IMAP or POP3 sessions were identified in this packet capture.",
            why_it_matters="The capture file does not contain traffic matching standard mail protocols (ports 25, 465, 587, 143, 993, 110, 995).",
            evidence=f"File: {filename} (SHA-256: {sha256_short})",
            evidence_items=[
                Evidence(
                    type="COVERAGE_GAP",
                    field="mail_sessions",
                    value=0,
                    source="Packet Filter Inspection",
                    description=f"File {filename} contains no packets matching SMTP, IMAP, or POP3.",
                )
            ],
            recommendation="Ensure the network capture filter encompasses active mail transport traffic.",
            rule_id="RULE-REAL-NO-MAIL-TRAFFIC",
            references=["RFC 8314"],
        )
        return Investigation(
            id=f"CAP-{sha256_short}",
            filename=filename,
            capture_date=capture_timestamp(packet_records),
            status="completed",
            is_simulated=False,
            data_source="REAL_CAPTURE",
            sha256_hash=sha256_full,
            sha256_short=sha256_short,
            analysis_engine="SecureMailScope Deterministic Rule Engine v0.2",
            summary=SummaryStats(
                sessions_analyzed=0,
                secure_sessions=0,
                warning_sessions=0,
                critical_sessions=0,
            ),
            security_posture=calculate_security_posture([]),
            nodes=[],
            connections=[],
            findings=[no_mail_finding],
        )

    # 2. Run Deterministic Security Analysis Engine
    engine = SecurityAnalysisEngine()
    findings, posture = engine.analyze_sessions(session_contexts)

    # Map findings per connection stream to determine connection security status
    findings_by_stream: Dict[str, List[SecurityFinding]] = {}
    for f in findings:
        for sess in session_contexts:
            if f.affected_connection_id == f"conn-real-{sess.stream_id}":
                findings_by_stream.setdefault(sess.stream_id, []).append(f)

    # 3. Build Observed Topology Nodes, Connections
    nodes: List[NetworkNode] = []
    connections: List[NetworkConnection] = []
    created_node_ids: Set[str] = set()

    secure_count = 0
    warning_count = 0
    critical_count = 0

    for sess in session_contexts:
        conn_id = f"conn-real-{sess.stream_id}"
        session_code = f"{sess.protocol}-STREAM-{sess.stream_id}"
        stream_findings = findings_by_stream.get(sess.stream_id, [])

        # Connection security evaluation based on deterministic findings
        has_critical_finding = any(f.severity == "CRITICAL" for f in stream_findings)
        has_high_fail = any(f.severity == "HIGH" and f.status == "FAIL" for f in stream_findings)
        has_medium_fail = any(f.severity == "MEDIUM" and f.status in ("FAIL", "WARN") for f in stream_findings)

        if has_critical_finding or has_high_fail:
            security_status = "CRITICAL"
            critical_count += 1
        elif has_medium_fail:
            security_status = "WARNING"
            warning_count += 1
        elif sess.tls_version in ("TLS 1.3", "TLS 1.2") and sess.has_aead and sess.has_pfs and not sess.capture_gaps and not any(f.status == "UNKNOWN" for f in stream_findings):
            security_status = "SECURE"
            secure_count += 1
        else:
            security_status = "WARNING"
            warning_count += 1

        # Client Node
        client_node_id = f"node-{sess.client_ip.replace('.', '-').replace(':', '-')}"
        if client_node_id not in created_node_ids:
            nodes.append(NetworkNode(
                id=client_node_id,
                label=f"Client ({sess.client_ip})",
                role=f"Originating {sess.protocol} Client",
                ip_address=sess.client_ip,
                hostname=f"host-{sess.client_ip}",
                is_external=True,
                security_posture="secure" if security_status == "SECURE" else "warning",
            ))
            created_node_ids.add(client_node_id)

        # Server Node
        server_node_id = f"node-{sess.server_ip.replace('.', '-').replace(':', '-')}"
        if server_node_id not in created_node_ids:
            nodes.append(NetworkNode(
                id=server_node_id,
                label=f"Mail Server ({sess.server_ip})",
                role=f"Destination {sess.protocol} Endpoint",
                ip_address=sess.server_ip,
                hostname=sess.sni or f"mx-{sess.server_ip}",
                is_external=False,
                security_posture="secure" if security_status == "SECURE" else "critical" if security_status == "CRITICAL" else "warning",
            ))
            created_node_ids.add(server_node_id)

        # Plain language exploration headline and summary
        if sess.starttls_advertised and not sess.starttls_used:
            headline = "Encryption was available, but session continued without upgrading to TLS"
            summary = f"The mail server ({sess.server_ip}) advertised STARTTLS in the EHLO response, but the client did not issue STARTTLS. The session continued unencrypted."
            why_it_matters = "Transport encryption was offered by the server, but was not utilized by the client. All message transit and metadata remained in cleartext on the wire."
            recommended_action = "Configure the mail client or transfer agent to enforce mandatory TLS (reject plaintext delivery when STARTTLS capability is signaled)."
        elif sess.auth_before_tls:
            headline = "Authentication Occurred Before TLS Protection"
            summary = "The client initiated authentication commands over an unencrypted cleartext session before establishing TLS encryption."
            why_it_matters = "Transmitting authentication credentials over cleartext exposes account credentials to passive network capture and eavesdropping."
            recommended_action = "Configure the mail server to mandate STARTTLS before advertising or accepting AUTH commands."
        elif sess.tls_version in ("TLS 1.0", "TLS 1.1", "SSL 3.0"):
            headline = f"Legacy Transport Protocol Detected ({sess.tls_version})"
            summary = f"Observed {sess.protocol} session negotiated obsolete {sess.tls_version} with cipher {sess.cipher_suite}."
            why_it_matters = f"Legacy protocol {sess.tls_version} lacks authenticated encryption (AEAD) and is vulnerable to downgrade and cryptanalysis."
            recommended_action = f"Disable {sess.tls_version} on {sess.server_ip} and mandate TLS 1.2 or TLS 1.3."
        elif "CLEARTEXT" in sess.transport_mode:
            headline = f"Plaintext {sess.protocol} Transport (No TLS Negotiated)"
            summary = f"Observed {sess.protocol} session transmitting in cleartext without transport-layer encryption."
            why_it_matters = "Email transit metadata and payloads are transmitted without encryption across the captured network segment."
            recommended_action = f"Enable STARTTLS or enforce Direct TLS on {sess.server_ip}:{sess.server_port}."
        elif security_status == "SECURE":
            headline = f"Modern Transport Security ({sess.tls_version})"
            summary = f"Real {sess.protocol} session negotiated modern {sess.tls_version} encryption with {sess.cipher_suite}."
            why_it_matters = "Protects email transit against passive network eavesdropping and traffic modification."
            recommended_action = "Maintain current cryptographic baseline across all server ingress points."
        else:
            headline = "Incomplete or Ambiguous Transport Session"
            summary = f"Captured {sess.protocol} session did not complete standard cryptographic handshake in capture window."
            why_it_matters = "Cannot conclusively verify whether encryption was established."
            recommended_action = "Ensure capture covers complete connection lifecycle from initial TCP handshake."

        connection = NetworkConnection(
            id=conn_id,
            source_node_id=client_node_id,
            target_node_id=server_node_id,
            source_label=f"Client ({sess.client_ip})",
            target_label=f"Server ({sess.server_ip})",
            protocol=sess.protocol,
            transport_mode=sess.transport_mode,
            tls_version=sess.tls_version,
            cipher_suite=sess.cipher_suite,
            security_status=security_status,
            session_id=session_code,
            has_pfs=sess.has_pfs,
            has_aead=sess.has_aead,
            starttls_advertised=sess.starttls_advertised,
            starttls_used=sess.starttls_used,
            auth_observed=sess.auth_observed,
            auth_before_tls=sess.auth_before_tls,
            starttls_requested=sess.starttls_requested,
            starttls_accepted=sess.starttls_accepted,
            server_key_share_group=sess.server_key_share_group,
            quantum_readiness=sess.quantum_readiness,
            certificates=sess.certificates,
            client_hello_offers=sess.client_hello_offers,
            server_hello_frame=sess.server_hello_frame,
            capture_gaps=any(p.get("tcp.analysis.lost_segment") for p in stream_map[sess.stream_id]),
            explanation=PlainLanguageExploration(
                headline=headline,
                summary=summary,
                why_it_matters=why_it_matters,
                evidence_summary=f"Stream {sess.stream_id}: {sess.client_ip}:{sess.client_port} -> {sess.server_ip}:{sess.server_port} ({sess.packet_count} packets, STARTTLS Advertised: {'YES' if sess.starttls_advertised else 'NO'}, STARTTLS Used: {'YES' if sess.starttls_used else 'NO'})",
                recommended_action=recommended_action,
            ),
            evidence=ConnectionEvidence(
                session_id=session_code,
                handshake_record=f"TCP Stream {sess.stream_id} ({sess.transport_mode})",
                cipher_suite_hex=sess.raw_cipher,
                protocol_version_hex=sess.raw_version,
                ports=f"{sess.client_port} -> {sess.server_port}",
                packet_count=sess.packet_count,
            ),
        )
        connections.append(connection)

    inv = Investigation(
        id=f"CAP-{sha256_short}",
        filename=filename,
        capture_date=capture_timestamp(packet_records),
        status="completed",
        is_simulated=False,
        data_source="REAL_CAPTURE",
        sha256_hash=sha256_full,
        sha256_short=sha256_short,
        analysis_engine="SecureMailScope Deterministic Rule Engine v0.3",
        summary=SummaryStats(
            sessions_analyzed=len(session_contexts),
            secure_sessions=secure_count,
            warning_sessions=warning_count,
            critical_sessions=critical_count,
        ),
        security_posture=posture,
        nodes=nodes,
        connections=connections,
        findings=findings,
    )

    from app.simulation.engine import HardeningSimulatorEngine
    inv.observed_clients = HardeningSimulatorEngine().extract_client_capabilities(inv)

    from app.replay.builder import ReplayBuilder
    replay_builder = ReplayBuilder()
    replays = []
    for sess in session_contexts:
        stream_pkts = stream_map.get(sess.stream_id, [])
        session_replay = replay_builder.build_replay(sess.stream_id, stream_pkts, sess, findings)
        replays.append(session_replay)
    inv.replays = replays

    from app.discovery.engine import ClientDiscoveryEngine
    inv.discovery = ClientDiscoveryEngine().discover(inv)
    from app.analysis.prioritization import build_fix_first
    inv.fix_first = build_fix_first(inv)

    return inv


def capture_timestamp(records):
    times = [float(p["frame.time_epoch"]) for p in records if p.get("frame.time_epoch")]
    return datetime.datetime.fromtimestamp(min(times), datetime.timezone.utc).isoformat() if times else "Not available in capture"
