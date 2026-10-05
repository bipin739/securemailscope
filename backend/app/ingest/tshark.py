import os
import shutil
import subprocess
from typing import List, Dict, Any, Optional

STANDARD_WINDOWS_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]

def find_tshark_executable() -> Optional[str]:
    """Locates the tshark binary in PATH, environment, or standard directories."""
    # 1. Custom environment variable override
    env_path = os.environ.get("TSHARK_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    # 2. System PATH lookup
    path_bin = shutil.which("tshark")
    if path_bin:
        return path_bin

    # 3. Known standard Windows installation paths
    for standard_path in STANDARD_WINDOWS_PATHS:
        if os.path.isfile(standard_path):
            return standard_path

    return None

def is_tshark_available() -> bool:
    """Returns True if a valid tshark executable is accessible."""
    return find_tshark_executable() is not None

def get_tshark_version() -> Optional[str]:
    """Retrieves the tshark version string."""
    tshark_bin = find_tshark_executable()
    if not tshark_bin:
        return None

    try:
        res = subprocess.run(
            [tshark_bin, "-v"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            first_line = res.stdout.splitlines()[0] if res.stdout else "TShark (version available)"
            return first_line.strip()
    except Exception:
        return None

    return None

def extract_packet_records(pcap_path: str) -> List[Dict[str, Any]]:
    """
    Executes TShark subprocess with explicit argument array to extract transport
    and protocol metadata from SMTP, IMAP, and POP3 network streams.
    Never uses shell=True.
    """
    tshark_bin = find_tshark_executable()
    if not tshark_bin:
        raise RuntimeError("TShark is required for real packet analysis. Please install Wireshark/TShark and add it to your PATH.")

    # Explicit field extraction array
    args = [
        tshark_bin,
        "-n", "-r", pcap_path,
        "-2", "-o", "tcp.desegment_tcp_streams:TRUE",
        "-o", "tcp.reassemble_out_of_order:TRUE",
        "-o", "tls.desegment_ssl_records:TRUE",
        "-o", "tls.desegment_ssl_application_data:TRUE",
        "-Y", "smtp or imap or pop or tls or tcp.port in {25, 465, 587, 143, 993, 110, 995}",
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=\t",
        "-E", "occurrence=a",
        "-E", "aggregator=,",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.time_relative",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ipv6.src",
        "-e", "ipv6.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.stream",
        "-e", "tcp.flags.syn",
        "-e", "_ws.col.Protocol",
        "-e", "smtp.req.command",
        "-e", "smtp.command_line",
        "-e", "smtp.response.code",
        "-e", "smtp.rsp.parameter",
        "-e", "smtp.response",
        "-e", "imap.request.command",
        "-e", "imap.response",
        "-e", "pop.request.command",
        "-e", "pop.response",
        "-e", "pop.response.indicator",
        "-e", "pop.response.description",
        "-e", "tcp.flags.fin",
        "-e", "tcp.flags.reset",
        "-e", "tcp.analysis.lost_segment",
        "-e", "tcp.analysis.retransmission",
        "-e", "tls.record.content_type",
        "-e", "tls.handshake.certificate",
        "-e", "tls.handshake.extensions_key_share_group",
        "-e", "tls.record.version",
        "-e", "tls.handshake.type",
        "-e", "tls.handshake.version",
        "-e", "tls.handshake.random",
        "-e", "tls.handshake.ciphersuite",
        "-e", "tls.handshake.ciphersuites",
        "-e", "tls.handshake.extensions.supported_version",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "tls.handshake.extensions_supported_group",
        "-e", "tls.handshake.ja3",
    ]

    try:
        proc = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("TShark extraction timed out (30s limit exceeded).")
    except Exception as e:
        raise RuntimeError(f"Failed to execute TShark subprocess: {str(e)}")

    if proc.returncode != 0:
        error_msg = proc.stderr.strip() if proc.stderr else f"Exit code {proc.returncode}"
        raise RuntimeError(f"TShark packet dissection failed: {error_msg}")

    lines = proc.stdout.splitlines()
    if not lines:
        return []

    # Map header fields (both raw and lowercased for safe lookup)
    raw_headers = lines[0].split("\t")
    records: List[Dict[str, Any]] = []

    for line in lines[1:]:
        if not line.strip():
            continue
        parts = line.split("\t")
        record: Dict[str, Any] = {}
        for i, col_name in enumerate(raw_headers):
            val = parts[i].strip() if i < len(parts) else ""
            cleaned_val = val if val else None
            # Store with both original key and lowercased key for case-insensitive lookup
            record[col_name] = cleaned_val
            record[col_name.lower()] = cleaned_val

        # Wireshark represents STARTTLS as STAR in smtp.req.command. Read only
        # the verb from its command line, then discard all command arguments.
        command_line = record.pop("smtp.command_line", None)
        if command_line:
            verb = command_line.replace(r'\r', ' ').replace(r'\n', ' ').split()[0].upper()
            if verb in {"EHLO", "HELO", "STARTTLS", "AUTH", "MAIL", "RCPT", "DATA", "QUIT", "RSET", "NOOP"}:
                record["smtp.req.command"] = verb
        records.append(record)

    return records
