"""WebSocket endpoint for real-time progress updates. Uses Redis pub/sub for multi-instance."""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio
import json
import logging

router = APIRouter(prefix="/ws", tags=["websocket"])
logger = logging.getLogger(__name__)

WS_REDIS_CHANNEL = "ws:updates"


class ConnectionManager:
    def __init__(self):
        self.active: dict[str, list[WebSocket]] = {}  # project_id -> [ws]

    async def connect(self, websocket: WebSocket, project_id: str):
        await websocket.accept()
        if project_id not in self.active:
            self.active[project_id] = []
        self.active[project_id].append(websocket)

    def disconnect(self, websocket: WebSocket, project_id: str):
        if project_id in self.active:
            self.active[project_id] = [ws for ws in self.active[project_id] if ws != websocket]
            if not self.active[project_id]:
                del self.active[project_id]

    async def _dispatch_local(self, project_id: str, message: dict):
        """Send to local WebSocket connections only (used by Redis subscriber)."""
        if project_id in self.active:
            for ws in self.active[project_id][:]:
                try:
                    await ws.send_json(message)
                except Exception:
                    pass

    async def broadcast(self, project_id: str, message: dict):
        """Publish to Redis so all app instances (including this) push to their local connections."""
        try:
            from app.core.redis_client import get_redis
            r = await get_redis()
            await r.publish(WS_REDIS_CHANNEL, json.dumps({"project_id": project_id, "data": message}))
        except Exception as e:
            logger.warning("WebSocket Redis publish failed, dispatching locally only: %s", e)
            await self._dispatch_local(project_id, message)


manager = ConnectionManager()


def get_manager():
    return manager


async def _redis_ws_listener():
    """Background task: subscribe to Redis and dispatch to local WebSockets."""
    while True:
        try:
            from app.core.redis_client import get_redis
            r = await get_redis()
            pubsub = r.pubsub()
            await pubsub.subscribe(WS_REDIS_CHANNEL)
            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue
                try:
                    payload = json.loads(message["data"])
                    project_id = payload.get("project_id")
                    data = payload.get("data")
                    if project_id and data is not None:
                        await manager._dispatch_local(project_id, data)
                except (json.JSONDecodeError, KeyError) as e:
                    logger.debug("WebSocket Redis message parse error: %s", e)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning("WebSocket Redis listener error: %s", e)
            await asyncio.sleep(5)


def start_redis_ws_listener():
    """Call from app startup to start the Redis pub/sub listener task."""
    return asyncio.create_task(_redis_ws_listener())


@router.websocket("/project/{project_id}")
async def project_websocket(websocket: WebSocket, project_id: str):
    """Connect to project room for real-time updates. Auth via query token."""
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001)
        return
    # Simplified: accept and add to room. Full auth would decode JWT.
    await manager.connect(websocket, project_id)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo or handle commands
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket, project_id)
