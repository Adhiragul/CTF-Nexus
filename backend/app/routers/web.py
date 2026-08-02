from fastapi import APIRouter, HTTPException

from ..models import WebRequest
from ..plugins.web.recon import analyze_url

router = APIRouter(prefix="/api/web", tags=["web"])


@router.post("/analyze")
def analyze(req: WebRequest):
    result = analyze_url(req.url)
    if result.error:
        raise HTTPException(502, result.error)
    return result.to_dict()
