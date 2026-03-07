#!/usr/bin/env python3
"""One-time migration: upload existing files from uploads_path to R2.
Requires STORAGE_BACKEND=r2 and R2_* env vars set. Run from backend dir:
  python scripts/migrate_uploads_to_r2.py
"""
import os
import sys
from pathlib import Path

# Ensure app is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings
from app.core.storage import evidence_key, org_logo_key, KEY_PREFIX_ORG_LOGOS, KEY_PREFIX_UPLOADS


def main():
    settings = get_settings()
    if settings.storage_backend != "r2" or not settings.r2_bucket or not settings.r2_endpoint_url:
        print("Set STORAGE_BACKEND=r2 and R2_ENDPOINT_URL, R2_BUCKET, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY in .env")
        sys.exit(1)

    base = Path(settings.uploads_path)
    if not base.exists():
        print(f"Uploads path does not exist: {base}")
        sys.exit(0)

    from app.core.storage import get_storage
    storage = get_storage()
    if not hasattr(storage, "_client_sync"):
        print("Storage is not R2; aborting.")
        sys.exit(1)

    uploaded = 0
    skipped = 0

    # org_logos: base/org_logos/{org_id}.ext -> key org_logos/{org_id}.ext
    org_logos_dir = base / "org_logos"
    if org_logos_dir.exists():
        for f in org_logos_dir.iterdir():
            if f.is_file():
                key = f"{KEY_PREFIX_ORG_LOGOS}/{f.name}"
                if storage.exists(key):
                    skipped += 1
                    continue
                try:
                    storage.upload(key, f.read_bytes())
                    uploaded += 1
                    print(f"  {key}")
                except Exception as e:
                    print(f"  ERROR {key}: {e}")

    # uploads: base/{project_id}/{filename} -> key uploads/{project_id}/{filename}
    for project_dir in base.iterdir():
        if not project_dir.is_dir() or project_dir.name == "org_logos":
            continue
        project_id = project_dir.name
        for f in project_dir.iterdir():
            if f.is_file():
                key = evidence_key(project_id, f.name)
                if storage.exists(key):
                    skipped += 1
                    continue
                try:
                    storage.upload(key, f.read_bytes())
                    uploaded += 1
                    print(f"  {key}")
                except Exception as e:
                    print(f"  ERROR {key}: {e}")

    print(f"Done. Uploaded: {uploaded}, Skipped (already exist): {skipped}")


if __name__ == "__main__":
    main()
