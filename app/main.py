"""FastAPI application entry point for CyberSentinel AI platform.

This module initializes the database on startup via lifespan, seeds demo users
and initial telemetry if empty, loads ML models, registers all API routers,
and serves the CyberSentinel SOC Web Command Center.
"""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.core.config import get_settings
from app.database import init_db, SessionLocal
from app.models.user import User
from app.models.event import SecurityEvent
from app.routers.auth import seed_demo_users_internal
from app.routers import (
    auth,
    events,
    alerts,
    dashboard,
    ml,
    chat,
    audit,
    settings as settings_router,
    scans,
)
from app.ml.model_manager import model_manager
from app.ml.data_generator import generate_dataset

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler: initialize DB, seed demo accounts & telemetry, load models."""
    init_db()

    # 1. Seed demo users (admin & analyst)
    with SessionLocal() as db:
        seed_demo_users_internal(db)

    # 2. Ensure models are loaded or trained
    loaded = model_manager.load()
    if not loaded:
        print("[CyberSentinel] Training initial ML models on benchmark dataset...")
        benchmark_data = generate_dataset(n_normal=200, n_per_attack=30)
        model_manager.train(benchmark_data)
        print("[CyberSentinel] Initial ML models trained successfully!")

    # 3. If database has no telemetry events, seed an initial realistic batch
    with SessionLocal() as db:
        if db.query(SecurityEvent).count() == 0:
            print("[CyberSentinel] Seeding initial SOC threat telemetry events...")
            from app.routers.events import seed_synthetic_events
            seed_synthetic_events(n_normal=60, n_per_attack=12, db=db)
            print("[CyberSentinel] Initial threat telemetry and alerts created!")
    yield


app = FastAPI(
    title="CyberSentinel AI",
    description="Next-generation Explainable AI (XAI) security platform with behavioral anomaly detection.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url, "http://localhost:5173", "http://127.0.0.1:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all API routers
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(events.router, prefix="/api/events", tags=["events"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["alerts"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(ml.router, prefix="/api/ml", tags=["ml"])
app.include_router(chat.router, prefix="/api/chat", tags=["chat"])
app.include_router(audit.router, prefix="/api/audit", tags=["audit"])
app.include_router(settings_router.router, prefix="/api/settings", tags=["settings"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])

# Mount static files & serve web UI
STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def serve_index():
    """Serve the CyberSentinel SOC Web Application."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "CyberSentinel AI backend online. Visit /docs for API documentation."}


# Health check endpoint
@app.get("/health", tags=["health"])
async def health_check():
    """Simple health check – returns OK when the service is running."""
    return {
        "status": "ok",
        "service": "CyberSentinel AI",
        "version": "1.0.0",
        "models_loaded": model_manager.is_loaded,
    }


# If executed directly, run via uvicorn
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
