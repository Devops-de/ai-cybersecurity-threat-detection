import asyncio
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import settings
from app.core.dependencies import (
    get_alert_engine,
    get_anomaly_detector,
    get_ai_summarizer,
    get_malware_classifier,
    get_phishing_detector,
    get_threat_intel,
    get_traffic_monitor,
    get_ws_manager,
)
from app.core.logging_config import logger
from app.routers import (
    alerts as alerts_router,
    health as health_router,
    incidents as incidents_router,
    malware as malware_router,
    phishing as phishing_router,
    telemetry as telemetry_router,
    threat_intel as threat_intel_router,
)
from app.routers.telemetry import handle_telemetry_websocket

# Backwards-compatible module-level singletons
anomaly_detector = get_anomaly_detector()
phishing_detector = get_phishing_detector()
malware_classifier = get_malware_classifier()
ai_summarizer = get_ai_summarizer()
traffic_monitor = get_traffic_monitor()
threat_intel = get_threat_intel()
alert_engine = get_alert_engine()
ws_manager = get_ws_manager()


async def traffic_generator_background_loop() -> None:
    """Continuously generates network flows, evaluates anomalies, and broadcasts via WebSockets."""
    logger.info("Starting background real-time telemetry generation loop...")
    while True:
        try:
            flow = traffic_monitor.generate_flow()
            alert = alert_engine.evaluate_network_flow(flow)

            payload = {
                "type": "TRAFFIC_UPDATE",
                "flow": flow,
                "stats": traffic_monitor.get_aggregate_stats(),
                "alert": alert,
            }

            await ws_manager.broadcast_json(payload)

        except asyncio.CancelledError:
            logger.info("Background traffic loop received cancellation.")
            break
        except Exception as exc:
            logger.error(f"Error in traffic generation loop: {exc}")

        await asyncio.sleep(settings.TRAFFIC_TICK_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manages application startup and graceful shutdown."""
    if settings.TESTING:
        logger.info(f"{settings.PROJECT_NAME} running in test mode (background loop skipped).")
        yield
        return

    task = asyncio.create_task(traffic_generator_background_loop())
    logger.info(f"{settings.PROJECT_NAME} v{settings.VERSION} initialized.")
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        logger.info(f"{settings.PROJECT_NAME} shutdown complete.")


# Instantiate FastAPI Application
app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.DESCRIPTION,
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ----------------- MIDDLEWARE -----------------
class TimingAndRequestIdMiddleware:
    """Pure ASGI middleware enriching responses with processing duration and a correlation Request-ID."""

    def __init__(self, app_instance) -> None:
        self.app = app_instance

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start_time = time.perf_counter()
        request_id = str(uuid.uuid4())

        async def send_wrapper(message) -> None:
            if message["type"] == "http.response.start":
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                headers = list(message.get("headers", []))
                headers.append((b"x-process-time", f"{duration_ms:.2f}ms".encode("latin1")))
                headers.append((b"x-request-id", request_id.encode("latin1")))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


app.add_middleware(TimingAndRequestIdMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------- EXCEPTION HANDLERS -----------------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled server error on {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error encountered while processing security telemetry."},
    )


# ----------------- ROUTER REGISTRATION -----------------
api_prefix = settings.API_PREFIX

app.include_router(health_router.router, prefix=api_prefix)
app.include_router(telemetry_router.router, prefix=api_prefix)
app.include_router(phishing_router.router, prefix=api_prefix)
app.include_router(malware_router.router, prefix=api_prefix)
app.include_router(incidents_router.router, prefix=api_prefix)
app.include_router(threat_intel_router.router, prefix=api_prefix)
app.include_router(alerts_router.router, prefix=api_prefix)


# ----------------- WEBSOCKET ROUTES -----------------
@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket) -> None:
    """Primary telemetry stream for live dashboard subscribers."""
    await handle_telemetry_websocket(websocket)


@app.websocket("/api/ws/telemetry")
async def websocket_telemetry_api_endpoint(websocket: WebSocket) -> None:
    """Proxy-friendly telemetry stream endpoint."""
    await handle_telemetry_websocket(websocket)


# ----------------- FRONTEND STATIC MOUNT -----------------
static_dir = str(settings.STATIC_DIR)
if os.path.isdir(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="frontend_static")
    logger.info(f"Mounted production frontend from: {static_dir}")
