import json
import logging
from typing import Any, Dict, List
from fastapi import WebSocket

logger = logging.getLogger("cybersentinel.websocket")


class ConnectionManager:
    """Manages active WebSocket telemetry connections and message broadcasting."""

    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accepts a WebSocket client and records the connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            f"Client connected to telemetry stream. Active clients: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket) -> None:
        """Removes a disconnected client."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(
                f"Client disconnected from telemetry stream. Remaining: {len(self.active_connections)}"
            )

    async def broadcast_json(self, message: Dict[str, Any]) -> None:
        """Safely broadcasts a JSON message to all active subscribers, removing dead ones."""
        if not self.active_connections:
            return

        serialized = json.dumps(message)
        dead_connections: List[WebSocket] = []

        for connection in list(self.active_connections):
            try:
                await connection.send_text(serialized)
            except Exception as exc:
                logger.debug(f"Failed to send to client, marking for cleanup: {exc}")
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)

    @property
    def client_count(self) -> int:
        return len(self.active_connections)
