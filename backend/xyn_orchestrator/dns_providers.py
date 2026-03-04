from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Protocol

import boto3


class DnsProvider(Protocol):
    def upsert_record(self, *, fqdn: str, record_type: str, value: str, ttl: int = 60) -> Dict[str, Any]:
        ...


@dataclass
class Route53DnsProvider:
    hosted_zone_id: str
    region: str | None = None
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_session_token: str | None = None

    def _client(self):
        kwargs: Dict[str, Any] = {}
        if self.region:
            kwargs["region_name"] = self.region
        if self.aws_access_key_id and self.aws_secret_access_key:
            kwargs["aws_access_key_id"] = self.aws_access_key_id
            kwargs["aws_secret_access_key"] = self.aws_secret_access_key
            if self.aws_session_token:
                kwargs["aws_session_token"] = self.aws_session_token
        return boto3.client("route53", **kwargs)

    def upsert_record(self, *, fqdn: str, record_type: str, value: str, ttl: int = 60) -> Dict[str, Any]:
        normalized_name = (fqdn.rstrip(".") + ".") if fqdn else ""
        normalized_type = str(record_type or "").upper().strip()
        if normalized_type not in {"A", "CNAME"}:
            raise ValueError("record_type must be A or CNAME")
        change = {
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": normalized_name,
                "Type": normalized_type,
                "TTL": int(ttl),
                "ResourceRecords": [{"Value": value}],
            },
        }
        response = self._client().change_resource_record_sets(
            HostedZoneId=self.hosted_zone_id,
            ChangeBatch={"Changes": [change]},
        )
        return {
            "provider": "route53",
            "hosted_zone_id": self.hosted_zone_id,
            "record": {
                "name": normalized_name,
                "type": normalized_type,
                "value": value,
                "ttl": int(ttl),
            },
            "change_id": str(((response or {}).get("ChangeInfo") or {}).get("Id") or ""),
            "status": str(((response or {}).get("ChangeInfo") or {}).get("Status") or ""),
            "raw": response,
        }
