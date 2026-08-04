import shutil
import tempfile
import uuid
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import FileResponse

from ..plugins.forensics.pcap_analyzer import analyze_pcap

router = APIRouter(prefix="/api/forensics", tags=["forensics"])

_SESSION_ROOT = Path(tempfile.gettempdir()) / "ctf_nexus_forensics_sessions"
_SESSION_ROOT.mkdir(exist_ok=True)

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # pcaps get big fast - 200MB ceiling


@router.post("/pcap")
async def analyze_pcap_ep(file: UploadFile = File(...)):
    session_id = str(uuid.uuid4())[:12]
    scratch = _SESSION_ROOT / session_id
    scratch.mkdir(parents=True, exist_ok=True)

    dest = scratch / (file.filename or "capture.pcap")
    size = 0
    with open(dest, "wb") as f:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                shutil.rmtree(scratch, ignore_errors=True)
                raise HTTPException(413, f"File exceeds {MAX_UPLOAD_BYTES // (1024*1024)}MB limit")
            f.write(chunk)

    try:
        result = analyze_pcap(str(dest), str(scratch))
    except Exception as e:
        shutil.rmtree(scratch, ignore_errors=True)
        raise HTTPException(500, f"analysis failed: {e}")

    if result.error:
        raise HTTPException(422, result.error)

    body = result.to_dict()
    body["session_id"] = session_id
    return body


@router.get("/download/{session_id}/{filename:path}")
def download_extracted(session_id: str, filename: str):
    scratch = (_SESSION_ROOT / session_id).resolve()
    target = (scratch / filename).resolve()
    if not str(target).startswith(str(scratch)) or not target.exists():
        raise HTTPException(404, "file not found")
    return FileResponse(str(target), filename=target.name)
