"""A bounded catalog of reproducible lab PCAPs. Never takes arbitrary paths."""
import json
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router=APIRouter()
SAMPLES=Path(__file__).resolve().parents[3]/'sample-captures'


@router.get('/samples')
def list_samples():
    manifest=SAMPLES/'manifest.json'
    return json.loads(manifest.read_text()) if manifest.exists() else []


@router.get('/samples/{name}')
def get_sample(name: str):
    names={x['filename'] for x in list_samples()}
    if name not in names:raise HTTPException(status_code=404,detail='Unknown lab capture')
    return FileResponse(SAMPLES/name,filename=name,media_type='application/vnd.tcpdump.pcap')
