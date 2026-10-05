import os
import tempfile
from typing import List, Optional, Dict, Any
from starlette.concurrency import run_in_threadpool
from fastapi import APIRouter, UploadFile, File, HTTPException, Body, status, Response
from app.models import Investigation
from app.mock_data import DEMO_INVESTIGATION
from app.ingest.validator import validate_pcap_file
from app.ingest.tshark import is_tshark_available, extract_packet_records
from app.parse.sessions import reconstruct_investigation_from_packets
from app.simulation.models import (
    HardeningPolicy,
    SimulationRequest,
    SimulationResult,
    ObservedClientCapability,
)
from app.simulation.policies import POLICY_REGISTRY
from app.simulation.engine import HardeningSimulatorEngine
from app.discovery.models import ClientDiscoveryResult
from app.discovery.engine import ClientDiscoveryEngine
from app.reporting.models import InvestigationReport
from app.reporting.report_builder import build_investigation_report
from app.reporting.integrity import verify_report_manifest
from app.reporting.exporters import export_report_to_json, export_report_to_html

router = APIRouter()

@router.post('/report/export/pdf')
def export_report_pdf(investigation: Investigation = Body(...)):
    from app.reporting.pdf_export import export_pdf
    report = build_investigation_report(investigation)
    return Response(content=export_pdf(investigation, report), media_type='application/pdf',
                    headers={'Content-Disposition':'attachment; filename="SecureMailScope_Forensic_Report.pdf"'})

@router.get("/demo", response_model=Investigation)
async def get_demo_investigation():
    """
    Returns the realistic mock investigation for the SecureMailScope prototype.
    All data is clearly labelled as simulated prototype demonstration.
    """
    return DEMO_INVESTIGATION

@router.get("/policies", response_model=List[HardeningPolicy])
async def get_hardening_policies():
    """
    Returns all registered deterministic hardening policies for simulation.
    """
    return [evaluator.get_policy() for evaluator in POLICY_REGISTRY.values()]

@router.post("/simulate", response_model=SimulationResult)
async def simulate_policies(
    request: SimulationRequest = Body(...),
):
    """
    Executes passive hardening impact simulation for selected policies against
    observed client capabilities in the provided or demo investigation.
    """
    engine = HardeningSimulatorEngine()
    policy_ids = request.get_policy_ids()
    if not policy_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one policy ID must be provided for simulation."
        )
    
    # Determine source investigation
    target_inv = request.investigation or DEMO_INVESTIGATION
    
    # Extract client capabilities if not already present
    if hasattr(target_inv, "observed_clients") and target_inv.observed_clients:
        if isinstance(target_inv.observed_clients[0], dict):
            clients = [ObservedClientCapability(**c) for c in target_inv.observed_clients]
        elif isinstance(target_inv.observed_clients[0], ObservedClientCapability):
            clients = target_inv.observed_clients
        else:
            clients = engine.extract_client_capabilities(target_inv)
    elif isinstance(target_inv, dict) and target_inv.get("observed_clients"):
        clients = [ObservedClientCapability(**c) for c in target_inv["observed_clients"]]
    else:
        clients = engine.extract_client_capabilities(target_inv)

    return engine.simulate(clients, policy_ids)

@router.post("/{investigation_id}/simulate", response_model=SimulationResult)
async def simulate_investigation_policies(
    investigation_id: str,
    request: SimulationRequest = Body(...),
    investigation: Optional[Investigation] = Body(None),
):
    """
    Executes passive policy simulation for a specific investigation identifier.
    """
    return await simulate_policies(request=request, investigation=investigation)

@router.get("/demo/discovery", response_model=ClientDiscoveryResult)
async def get_demo_discovery():
    """
    Returns the observed client inventory, deterministic indicators, and AI anomaly prioritization
    for the simulated demonstration investigation.
    """
    engine = ClientDiscoveryEngine()
    return engine.discover(DEMO_INVESTIGATION)

@router.post("/discovery", response_model=ClientDiscoveryResult)
async def discover_clients(
    investigation: Optional[Investigation] = Body(None),
):
    """
    Executes observed client discovery and AI anomaly prioritization for the provided investigation.
    """
    target_inv = investigation or DEMO_INVESTIGATION
    engine = ClientDiscoveryEngine()
    return engine.discover(target_inv)

@router.post("/{investigation_id}/discovery", response_model=ClientDiscoveryResult)
async def discover_investigation_clients(
    investigation_id: str,
    investigation: Optional[Investigation] = Body(None),
):
    """
    Executes observed client discovery and AI anomaly prioritization for a specific investigation.
    """
    return await discover_clients(investigation=investigation)

@router.post("/analyze", response_model=Investigation)
async def analyze_capture(file: UploadFile = File(...)):
    """
    Ingests and analyzes an authorized .pcap or .pcapng network capture.
    Extracts transport-layer session metadata with TShark and reconstructs
    the mail security journey without reading email message bodies or credentials.
    """
    # 1. Read uploaded capture bytes
    try:
        file_bytes = await file.read(50 * 1024 * 1024 + 1)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded capture: {str(e)}",
        )

    # 2. Validate file extension, size, and PCAP/PCAPNG magic bytes
    validation = validate_pcap_file(file.filename or "capture.pcap", file_bytes)
    if not validation.is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=validation.error_message or "Invalid capture file format.",
        )

    # 3. Check TShark binary availability
    if not is_tshark_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="TShark is required for real packet analysis. Please install Wireshark/TShark and add it to your system PATH.",
        )

    # 4. Save to temporary file for TShark processing
    temp_file_path = None
    try:
        suffix = ".pcapng" if (file.filename or "").lower().endswith(".pcapng") else ".pcap"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temp_f:
            temp_f.write(file_bytes)
            temp_file_path = temp_f.name

        # 5. Extract packet records via TShark
        packet_records = await run_in_threadpool(extract_packet_records, temp_file_path)

        # 6. Reconstruct mail transport sessions
        investigation = await run_in_threadpool(reconstruct_investigation_from_packets,
            filename=file.filename or "uploaded_capture.pcap",
            sha256_full=validation.sha256_full,
            sha256_short=validation.sha256_short,
            packet_records=packet_records,
        )

        from app.routes.samples import list_samples
        if any(s['sha256'] == validation.sha256_full for s in list_samples()):
            investigation.capture_origin = 'SYNTHETIC_LAB'
        return investigation

    except RuntimeError as r_err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(r_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while analyzing network capture: {str(exc)}",
        )
    finally:
        # Secure cleanup: remove temporary capture file immediately
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except OSError:
                pass


# ==========================================
# REPORTING & EVIDENCE INTEGRITY ENDPOINTS
# ==========================================

@router.get("/demo/report", response_model=InvestigationReport)
async def get_demo_report():
    """
    Generates and returns the authoritative, tamper-evident InvestigationReport
    for the simulated demonstration investigation.
    """
    return build_investigation_report(DEMO_INVESTIGATION)


@router.post("/report", response_model=InvestigationReport)
async def generate_investigation_report(
    investigation: Optional[Investigation] = Body(None),
):
    """
    Generates and returns the authoritative, tamper-evident InvestigationReport
    for the provided or demo investigation.
    """
    target_inv = investigation or DEMO_INVESTIGATION
    return build_investigation_report(target_inv)


@router.post("/{investigation_id}/report", response_model=InvestigationReport)
async def generate_report_by_id(
    investigation_id: str,
    investigation: Optional[Investigation] = Body(None),
):
    """
    Generates and returns the authoritative InvestigationReport for a specific investigation ID.
    """
    return await generate_investigation_report(investigation=investigation)


@router.post("/report/verify")
async def verify_report_integrity(
    report: Dict[str, Any] = Body(...),
):
    """
    Verifies the cryptographic evidence manifest, component digests, and Merkle Evidence Root
    for a provided InvestigationReport payload.
    """
    return verify_report_manifest(report)


@router.get("/demo/report/export/json")
async def export_demo_report_json():
    """
    Exports the demo investigation report as a machine-readable JSON document download.
    """
    report = build_investigation_report(DEMO_INVESTIGATION)
    json_content = export_report_to_json(report)
    return Response(
        content=json_content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="SecureMailScope_Report_{report.report_metadata.report_id}.json"'
        },
    )


@router.post("/report/export/json")
async def export_report_json(
    investigation: Optional[Investigation] = Body(None),
):
    """
    Exports the provided investigation report as a machine-readable JSON document download.
    """
    target_inv = investigation or DEMO_INVESTIGATION
    report = build_investigation_report(target_inv)
    json_content = export_report_to_json(report)
    return Response(
        content=json_content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="SecureMailScope_Report_{report.report_metadata.report_id}.json"'
        },
    )


@router.get("/demo/report/export/html")
async def export_demo_report_html():
    """
    Exports the demo investigation report as a standalone, printable HTML document.
    """
    report = build_investigation_report(DEMO_INVESTIGATION)
    html_content = export_report_to_html(report)
    return Response(
        content=html_content,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": f'inline; filename="SecureMailScope_Report_{report.report_metadata.report_id}.html"'
        },
    )


@router.post("/report/export/html")
async def export_report_html(
    investigation: Optional[Investigation] = Body(None),
):
    """
    Exports the provided investigation report as a standalone, printable HTML document.
    """
    target_inv = investigation or DEMO_INVESTIGATION
    report = build_investigation_report(target_inv)
    html_content = export_report_to_html(report)
    return Response(
        content=html_content,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": f'inline; filename="SecureMailScope_Report_{report.report_metadata.report_id}.html"'
        },
    )

