from __future__ import annotations

import datetime as dt
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from django.http import HttpRequest, JsonResponse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

from .blueprints import _require_staff

EMS_DEVICE_STATES = ["unregistered", "registered", "provisioning", "provisioned", "online", "offline", "error"]

EMS_DATASET_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "ems_devices": {
        "name": "ems_devices",
        "primary_key": "device_id",
        "columns": [
            {"key": "device_id", "label": "Device ID", "type": "string", "filterable": True, "sortable": True, "searchable": False},
            {"key": "serial", "label": "Serial", "type": "string", "filterable": True, "sortable": True, "searchable": True},
            {"key": "mac", "label": "MAC", "type": "string", "filterable": True, "sortable": True, "searchable": True},
            {"key": "model", "label": "Model", "type": "string", "filterable": True, "sortable": True, "searchable": True},
            {"key": "state", "label": "State", "type": "string", "filterable": True, "sortable": True, "enum": EMS_DEVICE_STATES},
            {"key": "last_seen_at", "label": "Last Seen", "type": "datetime", "filterable": True, "sortable": True},
            {"key": "registered_at", "label": "Registered", "type": "datetime", "filterable": True, "sortable": True},
            {"key": "workspace", "label": "Workspace", "type": "string", "filterable": True, "sortable": True, "searchable": True},
            {"key": "customer", "label": "Customer", "type": "string", "filterable": True, "sortable": True, "searchable": True},
            {"key": "firmware_profile", "label": "Firmware Profile", "type": "string", "filterable": True, "sortable": True, "searchable": True},
            {"key": "ip_address", "label": "IP", "type": "string", "filterable": True, "sortable": True, "searchable": True},
            {"key": "created_at", "label": "Created", "type": "datetime", "filterable": True, "sortable": True},
            {"key": "updated_at", "label": "Updated", "type": "datetime", "filterable": True, "sortable": True},
        ],
    },
    "ems_registrations": {
        "name": "ems_registrations",
        "primary_key": "registration_id",
        "columns": [
            {"key": "registration_id", "label": "Registration ID", "type": "string", "filterable": True, "sortable": True},
            {"key": "device_id", "label": "Device ID", "type": "string", "filterable": True, "sortable": True},
            {"key": "serial", "label": "Serial", "type": "string", "filterable": True, "sortable": True, "searchable": True},
            {"key": "mac", "label": "MAC", "type": "string", "filterable": True, "sortable": True, "searchable": True},
            {"key": "workspace", "label": "Workspace", "type": "string", "filterable": True, "sortable": True, "searchable": True},
            {"key": "customer", "label": "Customer", "type": "string", "filterable": True, "sortable": True, "searchable": True},
            {"key": "registered_by", "label": "Registered By", "type": "string", "filterable": True, "sortable": True, "searchable": True},
            {"key": "registered_at", "label": "Registered At", "type": "datetime", "filterable": True, "sortable": True},
            {"key": "method", "label": "Method", "type": "string", "filterable": True, "sortable": True, "enum": ["manual", "netboot", "agent", "import"]},
            {"key": "notes", "label": "Notes", "type": "string", "filterable": True, "sortable": False, "searchable": True},
        ],
    },
    "ems_device_status_rollup": {
        "name": "ems_device_status_rollup",
        "primary_key": "bucket",
        "columns": [
            {"key": "bucket", "label": "State", "type": "string", "filterable": True, "sortable": True, "enum": EMS_DEVICE_STATES},
            {"key": "count", "label": "Count", "type": "integer", "filterable": False, "sortable": True},
            {"key": "as_of", "label": "As Of", "type": "datetime", "filterable": True, "sortable": True},
        ],
    },
    "ems_registrations_timeseries": {
        "name": "ems_registrations_timeseries",
        "primary_key": "bucket_start",
        "columns": [
            {"key": "bucket_start", "label": "Bucket Start", "type": "datetime", "filterable": True, "sortable": True},
            {"key": "bucket_end", "label": "Bucket End", "type": "datetime", "filterable": True, "sortable": True},
            {"key": "count", "label": "Count", "type": "integer", "filterable": False, "sortable": True},
        ],
    },
}

ALLOWED_OPS = {"eq", "neq", "contains", "in", "gte", "lte", "gt", "lt"}


def _iso_utc(value: dt.datetime) -> str:
    if timezone.is_naive(value):
        value = timezone.make_aware(value, dt.timezone.utc)
    else:
        value = value.astimezone(dt.timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def _now_minus(duration: str) -> Optional[dt.datetime]:
    token = str(duration or "").strip().lower()
    if not token:
        return None
    match = re.match(r"^now-(\d+)([mhd])$", token)
    if match:
        amount = max(0, int(match.group(1)))
        unit = match.group(2)
        if unit == "m":
            return timezone.now() - dt.timedelta(minutes=amount)
        if unit == "h":
            return timezone.now() - dt.timedelta(hours=amount)
        return timezone.now() - dt.timedelta(days=amount)
    parsed = parse_datetime(token)
    if not parsed:
        try:
            parsed = dt.datetime.fromisoformat(token.replace("Z", "+00:00"))
        except ValueError:
            return None
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _sample_devices() -> List[Dict[str, Any]]:
    now = timezone.now()
    rows = [
        {"device_id": "dev-001", "serial": "SN-1001", "mac": "00:11:22:33:44:01", "model": "XR-Edge-100", "state": "unregistered", "hours_ago": 2, "workspace": "Civic Lab", "customer": "Civic Lab", "firmware_profile": "edge-stable", "ip_address": "10.0.10.21"},
        {"device_id": "dev-002", "serial": "SN-1002", "mac": "00:11:22:33:44:02", "model": "XR-Edge-100", "state": "registered", "hours_ago": 5, "workspace": "Civic Lab", "customer": "Civic Lab", "firmware_profile": "edge-stable", "ip_address": "10.0.10.22"},
        {"device_id": "dev-003", "serial": "SN-1003", "mac": "00:11:22:33:44:03", "model": "XR-Edge-200", "state": "provisioned", "hours_ago": 8, "workspace": "Platform Builder", "customer": "ACME Co", "firmware_profile": "edge-canary", "ip_address": "10.2.30.12"},
        {"device_id": "dev-004", "serial": "SN-1004", "mac": "00:11:22:33:44:04", "model": "XR-Edge-300", "state": "online", "hours_ago": 1, "workspace": "Platform Builder", "customer": "ACME Co", "firmware_profile": "edge-canary", "ip_address": "10.2.30.13"},
        {"device_id": "dev-005", "serial": "SN-1005", "mac": "00:11:22:33:44:05", "model": "XR-Edge-300", "state": "offline", "hours_ago": 36, "workspace": "Platform Builder", "customer": "ACME Co", "firmware_profile": "edge-stable", "ip_address": "10.2.30.14"},
        {"device_id": "dev-006", "serial": "SN-1006", "mac": "00:11:22:33:44:06", "model": "XR-Edge-200", "state": "error", "hours_ago": 12, "workspace": "Neto Operations", "customer": "NetoAI", "firmware_profile": "lab", "ip_address": "10.3.40.51"},
    ]
    output: List[Dict[str, Any]] = []
    for row in rows:
        created = now - dt.timedelta(hours=int(row["hours_ago"]))
        registered = created if row["state"] in {"registered", "provisioning", "provisioned", "online", "offline", "error"} else None
        output.append(
            {
                "device_id": row["device_id"],
                "serial": row["serial"],
                "mac": row["mac"],
                "model": row["model"],
                "state": row["state"],
                "last_seen_at": _iso_utc(created),
                "registered_at": _iso_utc(registered) if registered else None,
                "workspace": row["workspace"],
                "customer": row["customer"],
                "firmware_profile": row["firmware_profile"],
                "ip_address": row["ip_address"],
                "created_at": _iso_utc(created),
                "updated_at": _iso_utc(created),
            }
        )
    return output


def _sample_registrations(devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    methods = ["manual", "netboot", "agent", "import"]
    rows: List[Dict[str, Any]] = []
    idx = 0
    for device in devices:
        if not device.get("registered_at"):
            continue
        rows.append(
            {
                "registration_id": f"reg-{idx+1:03d}",
                "device_id": device["device_id"],
                "serial": device["serial"],
                "mac": device["mac"],
                "workspace": device["workspace"],
                "customer": device["customer"],
                "registered_by": "demo-operator@xyence.io",
                "registered_at": device["registered_at"],
                "method": methods[idx % len(methods)],
                "notes": "Demo registration row",
            }
        )
        idx += 1
    return rows


def _dataset_map() -> Dict[str, List[Dict[str, Any]]]:
    devices = _sample_devices()
    registrations = _sample_registrations(devices)
    return {
        "ems_devices": devices,
        "ems_registrations": registrations,
    }


def _coerce_value(field_type: str, value: Any) -> Any:
    if field_type == "integer":
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    if field_type == "boolean":
        token = str(value or "").strip().lower()
        if token in {"true", "1", "yes"}:
            return True
        if token in {"false", "0", "no"}:
            return False
        return None
    if field_type == "datetime":
        return _now_minus(value)
    if field_type == "string[]":
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return [str(value).strip()] if str(value or "").strip() else []
    return str(value or "").strip()


def _matches(row: Dict[str, Any], *, field: str, op: str, value: Any, field_type: str) -> bool:
    left = row.get(field)
    right = _coerce_value(field_type, value)
    if field_type == "datetime":
        left_dt = _now_minus(left)
        if not left_dt or not right:
            return False
        if op == "eq":
            return left_dt == right
        if op == "neq":
            return left_dt != right
        if op == "gte":
            return left_dt >= right
        if op == "lte":
            return left_dt <= right
        if op == "gt":
            return left_dt > right
        if op == "lt":
            return left_dt < right
        return False
    left_text = str(left or "").lower()
    if isinstance(right, list):
        right_text = [str(item).lower() for item in right]
    else:
        right_text = str(right or "").lower()
    if op == "eq":
        return left_text == str(right_text)
    if op == "neq":
        return left_text != str(right_text)
    if op == "contains":
        return str(right_text) in left_text
    if op == "in":
        return left_text in set(right_text if isinstance(right_text, list) else [right_text])
    if op == "gte":
        return left_text >= str(right_text)
    if op == "lte":
        return left_text <= str(right_text)
    if op == "gt":
        return left_text > str(right_text)
    if op == "lt":
        return left_text < str(right_text)
    return False


def _parse_query(request: HttpRequest, *, entity: str, columns: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], Optional[str]]:
    column_by_key = {str(col.get("key")): col for col in columns}
    try:
        limit = max(1, min(500, int(request.GET.get("limit") or 50)))
    except (TypeError, ValueError):
        limit = 50
    try:
        offset = max(0, int(request.GET.get("offset") or 0))
    except (TypeError, ValueError):
        offset = 0
    filters_raw = request.GET.get("filters") or "[]"
    sort_raw = request.GET.get("sort") or "[]"
    try:
        filters = json.loads(filters_raw)
        sort = json.loads(sort_raw)
    except json.JSONDecodeError:
        return {}, "invalid query payload"
    if not isinstance(filters, list) or not isinstance(sort, list):
        return {}, "filters and sort must be arrays"
    for row in filters:
        field = str((row or {}).get("field") or "")
        op = str((row or {}).get("op") or "")
        if field not in column_by_key:
            return {}, f"unknown filter field: {field}"
        if op not in ALLOWED_OPS:
            return {}, f"unsupported filter op: {op}"
    for row in sort:
        field = str((row or {}).get("field") or "")
        if field not in column_by_key:
            return {}, f"unknown sort field: {field}"
    if not sort:
        sort = [{"field": "updated_at" if entity == "ems_devices" else "registered_at", "dir": "desc"}]
    return {"entity": entity, "filters": filters, "sort": sort, "limit": limit, "offset": offset}, None


def _apply_query(rows: List[Dict[str, Any]], *, query: Dict[str, Any], columns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    column_by_key = {str(col.get("key")): col for col in columns}
    filtered = list(rows)
    for filt in query.get("filters") or []:
        field = str(filt.get("field") or "")
        op = str(filt.get("op") or "")
        field_type = str((column_by_key.get(field) or {}).get("type") or "string")
        filtered = [row for row in filtered if _matches(row, field=field, op=op, value=filt.get("value"), field_type=field_type)]
    for spec in reversed(query.get("sort") or []):
        field = str(spec.get("field") or "")
        direction = str(spec.get("dir") or "asc").lower()
        field_type = str((column_by_key.get(field) or {}).get("type") or "string")

        def key_fn(row: Dict[str, Any]) -> Any:
            value = row.get(field)
            if field_type == "datetime":
                parsed = _now_minus(value)
                return parsed.timestamp() if parsed else 0
            return str(value or "").lower()

        filtered.sort(key=key_fn, reverse=direction == "desc")
    return filtered


def _canvas_table_payload(*, title: str, dataset_name: str, schema: Dict[str, Any], rows: List[Dict[str, Any]], query: Dict[str, Any]) -> Dict[str, Any]:
    total = len(rows)
    offset = int(query.get("offset") or 0)
    limit = int(query.get("limit") or 50)
    paged = rows[offset : offset + limit]
    return {
        "type": "canvas.table",
        "title": title,
        "dataset": {
            "name": dataset_name,
            "primary_key": schema["primary_key"],
            "columns": schema["columns"],
            "rows": paged,
            "total_count": total,
        },
        "query": query,
    }


@csrf_exempt
@login_required
def ems_devices_table(request: HttpRequest) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error
    schema = EMS_DATASET_SCHEMAS["ems_devices"]
    query, err = _parse_query(request, entity="ems_devices", columns=schema["columns"])
    if err:
        return JsonResponse({"error": err}, status=400)
    rows = _apply_query(_dataset_map()["ems_devices"], query=query, columns=schema["columns"])
    return JsonResponse(_canvas_table_payload(title="EMS Devices", dataset_name="ems_devices", schema=schema, rows=rows, query=query))


@csrf_exempt
@login_required
def ems_registrations_table(request: HttpRequest) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error
    schema = EMS_DATASET_SCHEMAS["ems_registrations"]
    query, err = _parse_query(request, entity="ems_registrations", columns=schema["columns"])
    if err:
        return JsonResponse({"error": err}, status=400)
    rows = _apply_query(_dataset_map()["ems_registrations"], query=query, columns=schema["columns"])
    return JsonResponse(_canvas_table_payload(title="EMS Registrations", dataset_name="ems_registrations", schema=schema, rows=rows, query=query))


@csrf_exempt
@login_required
def ems_device_status_rollup_table(request: HttpRequest) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error
    schema = EMS_DATASET_SCHEMAS["ems_device_status_rollup"]
    as_of = _iso_utc(timezone.now())
    counts = {state: 0 for state in EMS_DEVICE_STATES}
    for row in _dataset_map()["ems_devices"]:
        state = str(row.get("state") or "").strip().lower()
        counts[state] = int(counts.get(state) or 0) + 1
    rows = [{"bucket": key, "count": int(counts.get(key) or 0), "as_of": as_of} for key in EMS_DEVICE_STATES]
    query = {
        "entity": "ems_device_status_rollup",
        "filters": [],
        "sort": [{"field": "bucket", "dir": "asc"}],
        "limit": len(rows),
        "offset": 0,
    }
    return JsonResponse(_canvas_table_payload(title="EMS Device Status Rollup", dataset_name="ems_device_status_rollup", schema=schema, rows=rows, query=query))


@csrf_exempt
@login_required
def ems_registrations_timeseries_table(request: HttpRequest) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error
    schema = EMS_DATASET_SCHEMAS["ems_registrations_timeseries"]
    range_value = str(request.GET.get("range") or "now-24h").strip().lower()
    bucket_value = str(request.GET.get("bucket") or "1h").strip().lower()
    match = re.match(r"^(\d+)([mhd])$", bucket_value)
    bucket_hours = 1
    if match:
        amount = max(1, int(match.group(1)))
        unit = match.group(2)
        if unit == "m":
            bucket_hours = max(1, amount // 60)
        elif unit == "h":
            bucket_hours = amount
        else:
            bucket_hours = amount * 24
    cutoff = _now_minus(range_value) or (timezone.now() - dt.timedelta(hours=24))
    registrations = _dataset_map()["ems_registrations"]
    buckets: Dict[str, int] = {}
    for row in registrations:
        registered = _now_minus(row.get("registered_at"))
        if not registered or registered < cutoff:
            continue
        floored = registered.astimezone(dt.timezone.utc).replace(minute=0, second=0, microsecond=0)
        if bucket_hours > 1:
            hour = (floored.hour // bucket_hours) * bucket_hours
            floored = floored.replace(hour=hour)
        key = _iso_utc(floored)
        buckets[key] = int(buckets.get(key) or 0) + 1
    rows: List[Dict[str, Any]] = []
    for key in sorted(buckets.keys()):
        start = _now_minus(key)
        if not start:
            continue
        end = start + dt.timedelta(hours=bucket_hours)
        rows.append({"bucket_start": _iso_utc(start), "bucket_end": _iso_utc(end), "count": int(buckets[key])})
    query = {
        "entity": "ems_registrations_timeseries",
        "filters": [{"field": "bucket_start", "op": "gte", "value": range_value}],
        "sort": [{"field": "bucket_start", "dir": "asc"}],
        "limit": len(rows) or 50,
        "offset": 0,
    }
    return JsonResponse(
        _canvas_table_payload(
            title=f"EMS Registrations Timeseries ({range_value})",
            dataset_name="ems_registrations_timeseries",
            schema=schema,
            rows=rows,
            query=query,
        )
    )


@csrf_exempt
@login_required
def ems_dataset_schema(request: HttpRequest, dataset: str) -> JsonResponse:
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error
    dataset_key = str(dataset or "").strip()
    schema = EMS_DATASET_SCHEMAS.get(dataset_key)
    if not schema:
        return JsonResponse({"error": "unknown dataset"}, status=404)
    rows = [
        {
            "key": str(col.get("key") or ""),
            "label": str(col.get("label") or ""),
            "type": str(col.get("type") or ""),
            "filterable": bool(col.get("filterable")),
            "sortable": bool(col.get("sortable")),
            "searchable": bool(col.get("searchable")),
        }
        for col in schema.get("columns") or []
    ]
    return JsonResponse(
        {
            "type": "canvas.table",
            "title": f"Dataset Schema: {dataset_key}",
            "dataset": {
                "name": "dataset_schema",
                "primary_key": "key",
                "columns": [
                    {"key": "key", "label": "Key", "type": "string", "filterable": True, "sortable": True},
                    {"key": "label", "label": "Label", "type": "string", "filterable": True, "sortable": True},
                    {"key": "type", "label": "Type", "type": "string", "filterable": True, "sortable": True},
                    {"key": "filterable", "label": "Filterable", "type": "boolean", "filterable": True, "sortable": True},
                    {"key": "sortable", "label": "Sortable", "type": "boolean", "filterable": True, "sortable": True},
                    {"key": "searchable", "label": "Searchable", "type": "boolean", "filterable": True, "sortable": True},
                ],
                "rows": rows,
                "total_count": len(rows),
            },
            "query": {"entity": "dataset_schema", "filters": [], "sort": [{"field": "key", "dir": "asc"}], "limit": len(rows), "offset": 0},
        }
    )
