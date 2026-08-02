"""
CTF Nexus backend entrypoint.

Run locally with:
    uvicorn app.main:app --reload --port 8000

Or via Docker (see ../Dockerfile / ../../docker-compose.yml at repo root).
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers import crypto, stego, web, misc, flags

app = FastAPI(
    title="CTF Nexus",
    description="Automated first-pass analysis for CTF challenges: crypto/hash ID, stego pipeline, web recon, and misc decoders.",
    version="0.1.0",
)

# Wide-open CORS is fine here: this runs on localhost for a single user
# during a competition, not as a multi-tenant public service.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(crypto.router)
app.include_router(stego.router)
app.include_router(web.router)
app.include_router(misc.router)
app.include_router(flags.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "modules": ["crypto", "stego", "web", "misc", "flags"]}
