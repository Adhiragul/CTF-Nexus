from fastapi import APIRouter

from ..models import CryptoRequest
from ..plugins.crypto.detector import analyze_crypto

router = APIRouter(prefix="/api/crypto", tags=["crypto"])


@router.post("/analyze")
def analyze(req: CryptoRequest):
    result = analyze_crypto(req.text)
    return result.to_dict()
