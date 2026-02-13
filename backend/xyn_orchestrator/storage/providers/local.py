import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def _safe_name(name: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9._-]+", "-", (name or "file").strip())
    return value or "file"


class LocalStorageProvider:
    provider_type = "local"

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.base_path = Path(str(self.config.get("base_path") or os.environ.get("XYN_UPLOADS_LOCAL_PATH") or "/tmp/xyn-uploads"))

    def store_attachment_bytes(
        self,
        *,
        report_id: str,
        attachment_id: str,
        filename: str,
        content_type: str,
        data: bytes,
    ) -> Dict[str, Any]:
        safe = _safe_name(filename)
        rel_path = Path("reports") / str(report_id) / f"{attachment_id}-{safe}"
        full_path = self.base_path / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_bytes(data)
        return {
            "provider": "local",
            "key": str(rel_path),
            "path": str(full_path),
            "content_type": content_type,
            "size_bytes": len(data),
            "url_expires_at": datetime.now(timezone.utc).isoformat(),
        }

    def build_download_reference(self, metadata: Dict[str, Any], ttl_seconds: int = 86400) -> str:
        return metadata.get("path") or metadata.get("key") or ""
