import shutil
import tempfile
import uuid
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel

from ..plugins.reverse.analyzer import analyze_binary
from ..plugins.reverse.decompiled_analyzer import analyze_decompiled_code, generate_dynamic_plan

router = APIRouter(prefix="/api/reverse", tags=["reverse"])

_SESSION_ROOT = Path(tempfile.gettempdir()) / "ctf_nexus_reverse_sessions"
_SESSION_ROOT.mkdir(exist_ok=True)
MAX_UPLOAD_BYTES = 100 * 1024 * 1024


class DecompiledRequest(BaseModel):
    code: str


class DynamicPlanRequest(BaseModel):
    checksec_output: str | None = None
    binary_name: str = "./chall"


@router.post("/binary")
async def analyze_binary_ep(file: UploadFile = File(...)):
    session_id = str(uuid.uuid4())[:12]
    scratch = _SESSION_ROOT / session_id
    scratch.mkdir(parents=True, exist_ok=True)
    dest = scratch / (file.filename or "binary")
    size = 0
    with open(dest, "wb") as f:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                shutil.rmtree(scratch, ignore_errors=True)
                raise HTTPException(413, f"File exceeds {MAX_UPLOAD_BYTES // (1024*1024)}MB limit")
            f.write(chunk)
    dest.chmod(0o644)  # explicitly non-executable in our own scratch dir - we never run this file

    try:
        result = analyze_binary(str(dest))
    except Exception as e:
        raise HTTPException(500, f"analysis failed: {e}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    body = result.to_dict()

    # auto-chain: if checksec output was gathered, immediately generate the
    # dynamic-analysis plan from it too, so one upload gives both static
    # triage and a ready pwntools skeleton without a second request.
    checksec_finding = next((f for f in result.findings if f.label == "checksec"), None)
    if checksec_finding and checksec_finding.data:
        plan = generate_dynamic_plan(checksec_finding.data, file.filename or "./chall")
        body["dynamic_plan"] = plan.to_dict()

    return body


@router.post("/decompiled")
def analyze_decompiled_ep(req: DecompiledRequest):
    result = analyze_decompiled_code(req.code)
    return result.to_dict()


@router.post("/dynamic-plan")
def dynamic_plan_ep(req: DynamicPlanRequest):
    result = generate_dynamic_plan(req.checksec_output, req.binary_name)
    return result.to_dict()
