import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure the backend directory is in sys.path so 'app.*' imports resolve
# whether invoked from repository root or from inside backend/
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.api.kerberos import router as kerberos_router

app = FastAPI(
    title="Kerberos Authentication Server (AS) Exchange API",
    description="Educational Simulation of the Kerberos AS Exchange for Cryptography & Network Security (BCS703)",
    version="2.0.0",
)

# Allowed CORS origins for local development and production Vercel frontend
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://kerberos-as-simulation.vercel.app",
    "https://kerberos-as-simulation.vercel.app/",
]

# Support additional custom origins via environment variable if configured
env_origins = os.getenv("ALLOWED_ORIGINS")
if env_origins:
    for item in env_origins.split(","):
        cleaned = item.strip()
        if cleaned and cleaned not in origins:
            origins.append(cleaned)

# Apply CORS middleware before router registration
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Kerberos Protocol Router
app.include_router(
    kerberos_router,
    prefix="/api/kerberos",
    tags=["Kerberos AS Exchange"],
)


class HealthResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    course: str
    semester: str
    college: str
    team_members: List[str]
    phase: str
    ready_for_kerberos: bool
    message: str


@app.get("/")
def root():
    return {
        "title": "Kerberos Authentication Server (AS) Simulation API",
        "course": "Cryptography & Network Security (BCS703)",
        "college": "Canara Engineering College",
        "team": ["4CB23CS160", "4CB23CS161"],
        "docs_url": "/docs",
        "health_endpoint": "/api/health",
        "kerberos_as_request": "/api/kerberos/as-request",
        "kerberos_principals": "/api/kerberos/principals",
    }


@app.get("/api/health", response_model=HealthResponse)
def health_check():
    """Health check endpoint to test backend connectivity from the React frontend."""
    return HealthResponse(
        status="healthy",
        service="Kerberos Authentication Server (AS) Backend Service",
        timestamp=datetime.now(timezone.utc).isoformat(),
        course="Cryptography & Network Security (BCS703)",
        semester="VII",
        college="Canara Engineering College",
        team_members=["4CB23CS160", "4CB23CS161"],
        phase="Phase 2: Kerberos AS Exchange Backend Active",
        ready_for_kerberos=True,
        message="Backend is operational with complete Kerberos AS protocol exchange engine and cryptographic services.",
    )
