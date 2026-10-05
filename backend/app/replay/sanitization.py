import re
from typing import Dict, Any, Tuple, Optional

# Regex patterns to detect potential email addresses or base64 tokens
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
BASE64_TOKEN_REGEX = re.compile(r"^[A-Za-z0-9+/=]{8,}$")

def sanitize_smtp_command(cmd: Optional[str], param: Optional[str]) -> Tuple[str, str, Dict[str, Any]]:
    """
    Sanitizes SMTP client commands into privacy-safe descriptions and metadata.
    Never exposes credentials, email addresses, or message content.
    """
    if not cmd:
        return "Client Message", "Client transmitted data to server.", {}

    clean_cmd = cmd.strip().upper()
    
    if clean_cmd.startswith("EHLO") or clean_cmd.startswith("HELO"):
        return "Client Greeting", f"Client initiated communication via {clean_cmd.split()[0]}.", {"command": clean_cmd.split()[0]}
    
    if clean_cmd in ("STARTTLS", "STLS"):
        return "STARTTLS Requested", "Client requested transport layer security upgrade via STARTTLS.", {"command": "STARTTLS"}
    
    if any(k in clean_cmd for k in ("AUTH", "AUTH LOGIN", "AUTH PLAIN")):
        return "Authentication Attempt", "Client transmitted authentication credentials.", {"command": "AUTH", "mechanism": "AUTHENTICATE"}
    
    if any(clean_cmd.startswith(k) for k in ("MAIL FROM", "RCPT TO", "DATA", "BDAT")):
        return "Mail Transaction", "Client initiated email envelope / message transaction.", {"transaction_phase": clean_cmd.split()[0]}
    
    if clean_cmd.startswith("QUIT"):
        return "Session Termination", "Client requested connection closure via QUIT.", {"command": "QUIT"}
    
    if clean_cmd.startswith("RSET"):
        return "Session Reset", "Client reset the current mail transaction state.", {"command": "RSET"}

    return f"Client Command ({clean_cmd[:8]})", "Client issued protocol command.", {"command": clean_cmd[:8]}

def sanitize_smtp_response(code: Optional[str], param: Optional[str], text: Optional[str]) -> Tuple[str, str, Dict[str, Any]]:
    """
    Sanitizes SMTP server responses into privacy-safe descriptions and metadata.
    """
    clean_code = str(code or "").strip()
    clean_param = str(param or "").upper()
    clean_text = str(text or "").upper()

    if clean_code == "220" and "STARTTLS" not in clean_text:
        return "Server Greeting", "Mail server signaled service ready (220).", {"code": "220"}

    if "STARTTLS" in clean_param or "STARTTLS" in clean_text or "STLS" in clean_text:
        return "STARTTLS Advertised", "Mail server advertised STARTTLS encryption capability in feature list.", {"code": clean_code or "250", "capability": "STARTTLS"}

    if clean_code == "220" and ("READY" in clean_text or "TLS" in clean_text):
        return "STARTTLS Acknowledged", "Mail server ready to begin TLS handshake negotiation (220 Ready for TLS).", {"code": "220"}

    if clean_code == "235":
        return "Authentication Successful", "Mail server accepted client authentication credentials (235 OK).", {"code": "235"}

    if clean_code in ("535", "534", "530"):
        return "Authentication / Policy Error", f"Mail server rejected authentication or required encryption ({clean_code}).", {"code": clean_code}

    if clean_code == "250":
        return "Server Acknowledged (250 OK)", "Mail server confirmed previous command completed successfully.", {"code": "250"}

    if clean_code == "354":
        return "Start Mail Input", "Mail server acknowledged ready to receive message payload (354).", {"code": "354"}

    if clean_code == "221":
        return "Service Closing", "Mail server acknowledged session closure (221 Bye).", {"code": "221"}

    return f"Server Response ({clean_code or 'INFO'})", "Mail server returned status response.", {"code": clean_code or "INFO"}

def sanitize_imap_pop_activity(protocol: str, is_client: bool, cmd: Optional[str], rsp: Optional[str]) -> Tuple[str, str, Dict[str, Any]]:
    """
    Sanitizes IMAP and POP3 commands and responses into privacy-safe descriptions.
    """
    if is_client:
        c = str(cmd or "").upper().strip()
        if "LOGIN" in c or "AUTHENTICATE" in c or c.startswith("USER") or c.startswith("PASS"):
            return "Authentication Attempt", f"Client attempted {protocol} authentication.", {"command": "AUTH"}
        if "STARTTLS" in c or "STLS" in c:
            return "STARTTLS Requested", f"Client requested {protocol} TLS upgrade.", {"command": "STARTTLS"}
        if "CAPABILITY" in c or "CAPA" in c:
            return "Capability Query", f"Client queried {protocol} server capabilities.", {"command": "CAPABILITY"}
        if any(k in c for k in ("SELECT", "FETCH", "STORE", "LIST", "RETR", "DELE", "STAT")):
            return "Mailbox Transaction", f"Client performed {protocol} mailbox operations.", {"command": "TRANSACTION"}
        if "LOGOUT" in c or "QUIT" in c:
            return "Session Termination", f"Client initiated {protocol} session termination.", {"command": "QUIT"}
        return f"{protocol} Client Command", f"Client sent {protocol} command.", {}
    else:
        r = str(rsp or "").upper().strip()
        if "STARTTLS" in r or "STLS" in r:
            return "STARTTLS Advertised", f"Server advertised {protocol} STARTTLS capability.", {"capability": "STARTTLS"}
        if "OK" in r or "+OK" in r:
            return f"{protocol} Server OK", f"Server confirmed operation (+OK).", {}
        if "NO" in r or "BAD" in r or "-ERR" in r:
            return f"{protocol} Server Error", f"Server returned error response.", {}
        return f"{protocol} Server Response", f"Server returned {protocol} response.", {}
