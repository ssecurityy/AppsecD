"""Evidence upload API — upload and serve evidence files for findings/test results."""
import uuid
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import get_settings
from app.core.database import get_db
from app.api.auth import get_current_user
from app.services.project_permissions import user_can_read_project, user_can_write_project
from app.models.user import User
import aiofiles

router = APIRouter(prefix="/projects", tags=["evidence"])
settings = get_settings()

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".txt", ".json", ".xml", ".har"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

# Magic bytes for image validation (industry standard: verify content matches extension)
IMAGE_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": {".png"},
    b"\xff\xd8\xff": {".jpg", ".jpeg"},
    b"GIF87a": {".gif"},
    b"GIF89a": {".gif"},
    b"RIFF": {".webp"},  # WebP: RIFF....WEBP
}
PDF_SIGNATURE = b"%PDF-"


def _validate_file_content(content: bytes, ext: str) -> bool:
    """Verify file content matches declared extension (prevents malicious uploads)."""
    ext_lower = ext.lower()
    if ext_lower in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
        for sig, exts in IMAGE_SIGNATURES.items():
            if ext_lower in exts and content.startswith(sig):
                if sig == b"RIFF" and len(content) >= 12:
                    return content[8:12] == b"WEBP"
                return True
        return False
    if ext_lower == ".pdf":
        return content.startswith(PDF_SIGNATURE)
    # txt, json, xml, har — allow (no strict magic bytes)
    return True


def _upload_dir(project_id: str) -> Path:
    d = Path(settings.uploads_path) / str(project_id)
    d.mkdir(parents=True, exist_ok=True)
    return d


@router.post("/{project_id}/evidence")
async def upload_evidence(
    project_id: str,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Upload evidence file. Returns {url, filename} for use in evidence array."""
    if not await user_can_write_project(db, current_user, project_id):
        raise HTTPException(403, "Write access denied to this project")

    ext = Path(file.filename or "file").suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"File type not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}")

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(400, f"File too large. Max {MAX_FILE_SIZE // 1024 // 1024}MB")
    if len(content) == 0:
        raise HTTPException(400, "Empty file not allowed")

    if not _validate_file_content(content, ext):
        raise HTTPException(400, "File content does not match extension. Possible spoofed file.")

    file_id = str(uuid.uuid4())
    safe_name = f"{file_id}{ext}"
    upload_path = _upload_dir(project_id) / safe_name

    async with aiofiles.open(upload_path, "wb") as f:
        await f.write(content)

    url = f"/projects/{project_id}/evidence/{safe_name}"
    return {"url": url, "filename": file.filename or "evidence" + ext}


@router.get("/{project_id}/evidence/{filename}")
async def get_evidence(
    project_id: str,
    filename: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Serve evidence file. Validates project access."""
    if not await user_can_read_project(db, current_user, project_id):
        raise HTTPException(403, "Access denied to this project")

    # Security: ensure filename is a simple uuid + ext (no path traversal)
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(400, "Invalid filename")
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, "Invalid file type")

    file_path = _upload_dir(project_id) / filename
    if not file_path.exists():
        raise HTTPException(404, "File not found")

    media_types = {
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".gif": "image/gif", ".webp": "image/webp", ".pdf": "application/pdf",
        ".txt": "text/plain", ".json": "application/json", ".xml": "application/xml",
        ".har": "application/json",
    }
    media_type = media_types.get(ext, "application/octet-stream")
    return FileResponse(file_path, media_type=media_type, filename=filename)
