"""WebSocket endpoint for real-time progress updates."""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import json
from app.core.security import decode_token

router = APIRouter(prefix="/ws", tags=["websocket"])

# Simple in-memory connection manager (use Redis pub/sub for multi-instance)
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

    async def broadcast(self, project_id: str, message: dict):
        if project_id in self.active:
            for ws in self.active[project_id]:
                try:
                    await ws.send_json(message)
                except Exception:
                    pass

manager = ConnectionManager()


def get_manager():
    return manager


@router.websocket("/project/{project_id}")
async def project_websocket(websocket: WebSocket, project_id: str):
    """Connect to project room for real-time updates. Auth via query token."""
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001)
        return
    payload = decode_token(token)
    if not payload:
        await websocket.close(code=4001)
        return
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
