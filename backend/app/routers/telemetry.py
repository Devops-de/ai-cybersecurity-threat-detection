import json
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.dependencies import (
    TrafficMonitorDep,
    WsManagerDep,
    get_traffic_monitor,
    get_ws_manager,
)
from app.schemas import (
    AttackSimulationRequest,
    AttackSimulationResponse,
    NetworkStatsResponse,
    RecentTrafficResponse,
)

logger = logging.getLogger("cybersentinel.telemetry")
router = APIRouter(prefix="/traffic", tags=["Traffic & Telemetry"])


@router.get("/recent", response_model=RecentTrafficResponse)
async def get_recent_traffic(monitor: TrafficMonitorDep) -> RecentTrafficResponse:
    """Returns the buffer of recent network flows alongside aggregate bandwidth statistics."""
    return RecentTrafficResponse(
        flows=monitor.recent_flows,
        stats=NetworkStatsResponse(**monitor.get_aggregate_stats()),
    )


@router.get("/stats", response_model=NetworkStatsResponse)
async def get_traffic_stats(monitor: TrafficMonitorDep) -> NetworkStatsResponse:
    """Provides high-level SOC dashboard metrics."""
    return NetworkStatsResponse(**monitor.get_aggregate_stats())


@router.post("/simulate-attack", response_model=AttackSimulationResponse)
async def simulate_attack(
    payload: AttackSimulationRequest,
    monitor: TrafficMonitorDep,
) -> AttackSimulationResponse:
    """Injects or clears an adversary attack vector in the real-time telemetry stream."""
    attack_type = payload.attack_type
    monitor.set_simulation_attack(attack_type)
    label = attack_type or "Normal Enterprise Baseline"
    return AttackSimulationResponse(
        status="success",
        current_simulation=attack_type,
        message=f"Network traffic stream adjusted to: {label}",
    )


async def handle_telemetry_websocket(websocket: WebSocket) -> None:
    """Handles client WebSocket lifecycle for live flow telemetry broadcast."""
    ws_manager = get_ws_manager()
    monitor = get_traffic_monitor()

    await ws_manager.connect(websocket)
    try:
        while True:
            raw_text = await websocket.receive_text()
            try:
                msg = json.loads(raw_text)
                if msg.get("action") == "SET_ATTACK_SIMULATION":
                    attack_type = msg.get("attack_type")
                    monitor.set_simulation_attack(attack_type)
                    logger.info(f"Attack simulation set via WebSocket: {attack_type}")
            except json.JSONDecodeError:
                logger.warning("Received invalid non-JSON payload over WebSocket.")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.error(f"WebSocket error: {exc}")
        ws_manager.disconnect(websocket)
