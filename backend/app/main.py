from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import health, investigations
from app.routes import samples

app = FastAPI(
    title="SecureMailScope API",
    description="Offline-First Cryptographic Security Posture Assessment for Secure Email Communications",
    version="1.0.0",
)

# Configure CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://localhost:4173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register route modules
app.include_router(health.router, prefix="/api", tags=["Health"])
app.include_router(samples.router, prefix="/api", tags=["Synthetic lab captures"])
app.include_router(investigations.router, prefix="/api/investigations", tags=["Investigations"])

@app.get("/api")
async def root():
    return {
        "service": "SecureMailScope API",
        "version": "1.0.0",
        "mode": "SIH_RESEARCH_PROTOTYPE",
        "docs_url": "/docs",
        "health_url": "/api/health",
        "demo_investigation_url": "/api/investigations/demo"
    }

# A production build can be served by the same local process as the API.
from pathlib import Path
from fastapi.staticfiles import StaticFiles
frontend_dist = Path(__file__).resolve().parents[2] / 'frontend' / 'dist'
if frontend_dist.exists():
    app.mount('/', StaticFiles(directory=frontend_dist, html=True), name='workspace')
