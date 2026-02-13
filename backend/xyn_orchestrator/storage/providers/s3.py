import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import boto3


def _safe_name(name: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9._-]+", "-", (name or "file").strip())
    return value or "file"


class S3StorageProvider:
    provider_type = "s3"

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.bucket = str(self.config.get("bucket") or "").strip()
        self.region = str(self.config.get("region") or os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "").strip()
        self.prefix = str(self.config.get("prefix") or "xyn").strip().strip("/")
        self.kms_key_id = str(self.config.get("kms_key_id") or "").strip()
        self.acl = str(self.config.get("acl") or "private").strip() or "private"
        self.client = boto3.client("s3", region_name=self.region) if self.region else boto3.client("s3")

    def _key(self, report_id: str, attachment_id: str, filename: str) -> str:
        safe = _safe_name(filename)
        return f"{self.prefix}/reports/{report_id}/{attachment_id}-{safe}"

    def store_attachment_bytes(
        self,
        *,
        report_id: str,
        attachment_id: str,
        filename: str,
        content_type: str,
        data: bytes,
    ) -> Dict[str, Any]:
        if not self.bucket:
            raise RuntimeError("s3 bucket is required")
        key = self._key(report_id, attachment_id, filename)
        extra: Dict[str, Any] = {"ContentType": content_type}
        if self.kms_key_id:
            extra["ServerSideEncryption"] = "aws:kms"
            extra["SSEKMSKeyId"] = self.kms_key_id
        self.client.put_object(Bucket=self.bucket, Key=key, Body=data, ACL=self.acl, **extra)
        return {
            "provider": "s3",
            "bucket": self.bucket,
            "region": self.region,
            "key": key,
            "size_bytes": len(data),
            "url_expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        }

    def build_download_reference(self, metadata: Dict[str, Any], ttl_seconds: int = 86400) -> str:
        bucket = metadata.get("bucket") or self.bucket
        key = metadata.get("key")
        if not bucket or not key:
            return ""
        return self.client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=ttl_seconds,
        )
