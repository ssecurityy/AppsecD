"""Storage abstraction for uploads and org logos: local filesystem or R2 (S3-compatible)."""
from __future__ import annotations

import asyncio
import io
from pathlib import Path
from typing import BinaryIO, Optional

from app.core.config import get_settings


def _get_storage():
    """Return the active storage backend (local or R2)."""
    settings = get_settings()
    if settings.storage_backend == "r2" and settings.r2_bucket and settings.r2_endpoint_url:
        return R2Storage()
    return LocalStorage()


# Module-level singleton for lazy init
_storage: Optional[object] = None


def get_storage():
    """Get the configured storage backend (cached)."""
    global _storage
    if _storage is None:
        _storage = _get_storage()
    return _storage


class LocalStorage:
    """Store files under config.uploads_path (uploads/ and org_logos/)."""

    def __init__(self):
        self.base = Path(get_settings().uploads_path)

    def _path(self, key: str) -> Path:
        # key: "uploads/{project_id}/{filename}" -> base/{project_id}/{filename}
        # key: "org_logos/{org_id}.ext" -> base/org_logos/{org_id}.ext
        if key.startswith("uploads/"):
            return self.base / key.split("/", 1)[1]
        return self.base / key

    def upload(self, key: str, body: bytes) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)

    def get(self, key: str) -> Optional[bytes]:
        path = self._path(key)
        if not path.exists():
            return None
        return path.read_bytes()

    def exists(self, key: str) -> bool:
        return self._path(key).exists()

    def delete(self, key: str) -> bool:
        path = self._path(key)
        if path.exists():
            path.unlink()
            return True
        return False

    async def upload_async(self, key: str, body: bytes) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self.upload(key, body))

    async def get_async(self, key: str) -> Optional[bytes]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.get(key))


class R2Storage:
    """Store files in Cloudflare R2 (S3-compatible) via boto3."""

    def __init__(self):
        settings = get_settings()
        self.bucket = settings.r2_bucket
        self._client = None
        self._async_client = None

    def _client_sync(self):
        if self._client is None:
            import boto3
            from app.core.config import get_settings
            s = get_settings()
            self._client = boto3.client(
                "s3",
                endpoint_url=s.r2_endpoint_url,
                region_name=s.r2_region or "auto",
                aws_access_key_id=s.r2_access_key_id,
                aws_secret_access_key=s.r2_secret_access_key,
            )
        return self._client

    def upload(self, key: str, body: bytes) -> None:
        self._client_sync().put_object(
            Bucket=self.bucket,
            Key=key,
            Body=body,
            ContentType=_content_type_for_key(key),
        )

    def get(self, key: str) -> Optional[bytes]:
        try:
            resp = self._client_sync().get_object(Bucket=self.bucket, Key=key)
            return resp["Body"].read()
        except Exception:
            return None

    def exists(self, key: str) -> bool:
        try:
            self._client_sync().head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False

    def delete(self, key: str) -> bool:
        try:
            self._client_sync().delete_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False

    async def get_async(self, key: str) -> Optional[bytes]:
        """Async get for FastAPI handlers."""
        import aioboto3
        from app.core.config import get_settings
        s = get_settings()
        async with aioboto3.Session().client(
            "s3",
            endpoint_url=s.r2_endpoint_url,
            region_name=s.r2_region or "auto",
            aws_access_key_id=s.r2_access_key_id,
            aws_secret_access_key=s.r2_secret_access_key,
        ) as client:
            try:
                resp = await client.get_object(Bucket=self.bucket, Key=key)
                async with resp["Body"] as stream:
                    return await stream.read()
            except Exception:
                return None

    async def upload_async(self, key: str, body: bytes) -> None:
        """Async upload for FastAPI handlers."""
        import aioboto3
        from app.core.config import get_settings
        s = get_settings()
        async with aioboto3.Session().client(
            "s3",
            endpoint_url=s.r2_endpoint_url,
            region_name=s.r2_region or "auto",
            aws_access_key_id=s.r2_access_key_id,
            aws_secret_access_key=s.r2_secret_access_key,
        ) as client:
            await client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=body,
                ContentType=_content_type_for_key(key),
            )


def _content_type_for_key(key: str) -> str:
    key_lower = key.lower()
    if key_lower.endswith(".png"):
        return "image/png"
    if key_lower.endswith(".jpg") or key_lower.endswith(".jpeg"):
        return "image/jpeg"
    if key_lower.endswith(".gif"):
        return "image/gif"
    if key_lower.endswith(".webp"):
        return "image/webp"
    if key_lower.endswith(".pdf"):
        return "application/pdf"
    if key_lower.endswith(".txt"):
        return "text/plain"
    if key_lower.endswith(".json"):
        return "application/json"
    if key_lower.endswith(".xml"):
        return "application/xml"
    if key_lower.endswith(".har"):
        return "application/json"
    return "application/octet-stream"


# Key layout constants
KEY_PREFIX_UPLOADS = "uploads"
KEY_PREFIX_ORG_LOGOS = "org_logos"
KEY_PREFIX_WORDLISTS = "wordlists"


def evidence_key(project_id: str, filename: str) -> str:
    return f"{KEY_PREFIX_UPLOADS}/{project_id}/{filename}"


def org_logo_key(org_id: str, ext: str) -> str:
    return f"{KEY_PREFIX_ORG_LOGOS}/{org_id}{ext}"
