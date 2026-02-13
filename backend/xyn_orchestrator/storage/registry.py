from typing import Any, Dict, Optional

from .providers.local import LocalStorageProvider
from .providers.s3 import S3StorageProvider


class StorageProviderRegistry:
    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        storage = self.config.get("storage") if isinstance(self.config.get("storage"), dict) else {}
        self._storage = storage
        self._providers_by_name = {}
        for provider in storage.get("providers") or []:
            if not isinstance(provider, dict):
                continue
            name = str(provider.get("name") or "").strip()
            if not name:
                continue
            ptype = str(provider.get("type") or "").strip().lower()
            if ptype == "s3":
                self._providers_by_name[name] = S3StorageProvider(provider.get("s3") or {})
            elif ptype == "local":
                self._providers_by_name[name] = LocalStorageProvider(provider.get("local") or {})

    def get_provider(self, name: str):
        provider = self._providers_by_name.get(name)
        if provider:
            return provider
        return LocalStorageProvider({})

    def get_primary_provider(self):
        primary = self._storage.get("primary") if isinstance(self._storage.get("primary"), dict) else {}
        pname = str(primary.get("name") or "").strip()
        if pname:
            return self.get_provider(pname)
        if self._providers_by_name:
            first = next(iter(self._providers_by_name.keys()))
            return self._providers_by_name[first]
        return LocalStorageProvider({})

    def store_attachment_bytes(
        self,
        *,
        report_id: str,
        attachment_id: str,
        filename: str,
        content_type: str,
        data: bytes,
    ) -> Dict[str, Any]:
        provider = self.get_primary_provider()
        stored = provider.store_attachment_bytes(
            report_id=report_id,
            attachment_id=attachment_id,
            filename=filename,
            content_type=content_type,
            data=data,
        )
        return stored

    def build_download_reference(self, metadata: Dict[str, Any], ttl_seconds: int = 86400) -> Optional[str]:
        provider_type = str(metadata.get("provider") or "").strip().lower()
        for provider in self._providers_by_name.values():
            if getattr(provider, "provider_type", "") == provider_type:
                return provider.build_download_reference(metadata, ttl_seconds=ttl_seconds)
        fallback = self.get_primary_provider()
        return fallback.build_download_reference(metadata, ttl_seconds=ttl_seconds)
