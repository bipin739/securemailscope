import hashlib
from typing import Optional
from pydantic import BaseModel

MAX_CAPTURE_SIZE = 50 * 1024 * 1024  # 50 Megabytes limit for Phase 1 prototype

PCAP_MAGIC_BYTES = {
    b"\xa1\xb2\xc3\xd4": "PCAP (Microsecond, Big-Endian)",
    b"\xd4\xc3\xb2\xa1": "PCAP (Microsecond, Little-Endian)",
    b"\xa1\xb2\x3c\x4d": "PCAP (Nanosecond, Big-Endian)",
    b"\x4d\x3c\xb2\xa1": "PCAP (Nanosecond, Little-Endian)",
    b"\x0a\x0d\x0d\x0a": "PCAPNG (Section Header Block)",
}

class ValidationResult(BaseModel):
    is_valid: bool
    format_detected: str
    sha256_full: str
    sha256_short: str
    file_size_bytes: int
    error_message: Optional[str] = None

def validate_pcap_file(filename: str, file_bytes: bytes) -> ValidationResult:
    """
    Validates uploaded network capture against supported extensions,
    magic byte signatures, and size constraints.
    Computes deterministic SHA-256 capture hash.
    """
    file_size = len(file_bytes)
    
    # 1. Size constraint validation
    if file_size == 0:
        return ValidationResult(
            is_valid=False,
            format_detected="EMPTY",
            sha256_full="",
            sha256_short="",
            file_size_bytes=0,
            error_message="Uploaded capture file is empty (0 bytes).",
        )

    if file_size > MAX_CAPTURE_SIZE:
        return ValidationResult(
            is_valid=False,
            format_detected="OVERSIZED",
            sha256_full="",
            sha256_short="",
            file_size_bytes=file_size,
            error_message=f"Capture exceeds maximum size of {MAX_CAPTURE_SIZE // (1024 * 1024)} MB.",
        )

    # 2. Filename extension validation
    lower_filename = filename.lower()
    valid_extensions = (".pcap", ".pcapng", ".cap")
    if not any(lower_filename.endswith(ext) for ext in valid_extensions):
        return ValidationResult(
            is_valid=False,
            format_detected="UNSUPPORTED_EXTENSION",
            sha256_full="",
            sha256_short="",
            file_size_bytes=file_size,
            error_message=f"Unsupported file extension. Allowed formats: .pcap, .pcapng",
        )

    # 3. Magic header byte inspection
    if len(file_bytes) < 4:
        return ValidationResult(
            is_valid=False,
            format_detected="TRUNCATED",
            sha256_full="",
            sha256_short="",
            file_size_bytes=file_size,
            error_message="Capture file header is truncated (less than 4 bytes).",
        )

    magic_header = file_bytes[:4]
    detected_format = PCAP_MAGIC_BYTES.get(magic_header)

    if not detected_format:
        return ValidationResult(
            is_valid=False,
            format_detected="INVALID_MAGIC",
            sha256_full="",
            sha256_short="",
            file_size_bytes=file_size,
            error_message="Invalid capture file format: unrecognized PCAP/PCAPNG header signature.",
        )

    # 4. SHA-256 computation
    sha256_full = hashlib.sha256(file_bytes).hexdigest()
    sha256_short = sha256_full[:12]

    return ValidationResult(
        is_valid=True,
        format_detected=detected_format,
        sha256_full=sha256_full,
        sha256_short=sha256_short,
        file_size_bytes=file_size,
        error_message=None,
    )
