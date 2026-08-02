import os
import shutil
import tempfile
import uuid
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import FileResponse

from ..plugins.stego.analyzer import analyze_file

router = APIRouter(prefix="/api/stego", tags=["stego"])

# Extraction results are kept around briefly so the user can download files
# binwalk pulled out, keyed by a random session id. A background sweep
# would evict these after N minutes in a real deployment; kept simple here.
_SESSION_ROOT = Path(tempfile.gettempdir()) / "ctf_nexus_sessions"
_SESSION_ROOT.mkdir(exist_ok=True)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB - generous for CTF stego files, not for disk images


@router.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    session_id = str(uuid.uuid4())[:12]
    scratch = _SESSION_ROOT / session_id
    scratch.mkdir(parents=True, exist_ok=True)

    dest = scratch / (file.filename or "upload.bin")
    size = 0
    with open(dest, "wb") as f:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                shutil.rmtree(scratch, ignore_errors=True)
                raise HTTPException(413, f"File exceeds {MAX_UPLOAD_BYTES // (1024*1024)}MB limit")
            f.write(chunk)

    try:
        result = analyze_file(str(dest), str(scratch))
    except Exception as e:
        shutil.rmtree(scratch, ignore_errors=True)
        raise HTTPException(500, f"analysis failed: {e}")

    body = result.to_dict()
    body["session_id"] = session_id
    return body


@router.get("/download/{session_id}/{filename:path}")
def download_extracted(session_id: str, filename: str):
    # defend against path traversal - resolve and confirm it's still inside the session dir
    scratch = (_SESSION_ROOT / session_id).resolve()
    target = (scratch / filename).resolve()
    if not str(target).startswith(str(scratch)) or not target.exists():
        raise HTTPException(404, "file not found")
    return FileResponse(str(target), filename=target.name)
