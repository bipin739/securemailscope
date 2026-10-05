from fastapi import APIRouter
from app.models import HealthResponse
from app.ingest.tshark import is_tshark_available, get_tshark_version

router = APIRouter()

@router.get("/health", response_model=HealthResponse)
async def get_health():
    """Health check endpoint confirming service status and TShark engine availability."""
    tshark_ok = is_tshark_available()
    tshark_ver = get_tshark_version() if tshark_ok else None

    return HealthResponse(
        status="ok",
        service="SecureMailScope",
        version="1.0.0",
        is_simulated_mode=False,
        tshark_available=tshark_ok,
        tshark_version=tshark_ver,
    )

