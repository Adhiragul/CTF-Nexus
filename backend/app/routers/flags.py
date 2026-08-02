from fastapi import APIRouter, HTTPException

from ..models import FlagProfileCreate, FlagScanRequest
from .. import flag_formats

router = APIRouter(prefix="/api/flags", tags=["flags"])


@router.get("/profiles")
def list_profiles():
    return {"profiles": flag_formats.list_profiles(), "presets": flag_formats.BUILTIN_PRESETS}


@router.post("/profiles")
def create_profile(req: FlagProfileCreate):
    try:
        return flag_formats.create_profile(req.name, req.prefix, req.custom_regex)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(400, f"invalid regex: {e}")


@router.delete("/profiles/{profile_id}")
def delete_profile(profile_id: str):
    if not flag_formats.delete_profile(profile_id):
        raise HTTPException(404, "profile not found")
    return {"deleted": profile_id}


@router.post("/scan")
def scan(req: FlagScanRequest):
    return {"matches": flag_formats.scan(req.text)}
