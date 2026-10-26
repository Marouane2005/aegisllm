import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded

from app.core.config import get_settings
from app.core.scheduler import start_scheduler
from app.core.rate_limit import limiter
from app.api import auth, admin, proxy

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AegisLLM starting up...")
    start_scheduler()
    yield
    logger.info("AegisLLM shutting down...")
    from app.services.proxy_service import close_client
    await close_client()


app = FastAPI(title=settings.APP_NAME, version="0.1.0", lifespan=lifespan, docs_url="/docs" if settings.DEBUG else None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, lambda r, e: JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"}))

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.ALLOWED_ORIGINS.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Aegis-Provider"],
    max_age=600,
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(admin.router, prefix="/api/admin", tags=["admin"])
app.include_router(proxy.router, prefix="/v1", tags=["proxy"])


@app.get("/healthz", tags=["system"])
async def healthcheck():
    return {"status": "ok", "service": settings.APP_NAME}


# Serve React SPA (mounted LAST so it doesn't shadow API routes)
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
if STATIC_DIR.is_dir():
    assets_dir = STATIC_DIR / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="static-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_catchall(full_path: str):
        if full_path.startswith(("api/", "v1/", "healthz", "openapi.json", "docs", "redoc")):
            return JSONResponse({"detail": "Not found"}, status_code=404)
        index = STATIC_DIR / "index.html"
        if index.exists():
            return FileResponse(index)
        return JSONResponse({"detail": "Not found"}, status_code=404)
