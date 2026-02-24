import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from django.db.models import Q

from .models import RoleBinding, UserIdentity


@dataclass(frozen=True)
class PermissionDefinition:
    key: str
    name: str
    description: str
    category: str
    tags: Tuple[str, ...] = ()
    is_dangerous: bool = False


ROLE_DEFINITIONS: List[Dict[str, Any]] = [
    {"id": "platform_owner", "name": "Platform Owner", "description": "Top-level owner authority.", "tier": 0},
    {"id": "platform_admin", "name": "Platform Admin", "description": "Platform administrative authority.", "tier": 1},
    {"id": "platform_architect", "name": "Platform Architect", "description": "Control-plane planning and architecture.", "tier": 2},
    {"id": "platform_operator", "name": "Platform Operator", "description": "Operational workflows and runtime management.", "tier": 3},
    {"id": "app_user", "name": "App User", "description": "Standard authenticated user.", "tier": 4},
]

PERMISSIONS: List[PermissionDefinition] = [
    PermissionDefinition("view_platform", "View Platform", "View platform control-plane pages.", "platform"),
    PermissionDefinition("manage_tenants", "Manage Tenants", "Create/update tenant records.", "tenants", ("write",), True),
    PermissionDefinition("manage_users", "Manage Users", "Manage user identities and role assignments.", "access", ("write",), True),
    PermissionDefinition("assign_roles", "Assign Roles", "Assign platform roles to users.", "access", ("write",), True),
    PermissionDefinition("manage_idp", "Manage Identity Providers", "Create/update IdP and OIDC client configuration.", "identity", ("write",), True),
    PermissionDefinition("manage_secrets", "Manage Secrets", "Manage secret stores and references.", "security", ("write",), True),
    PermissionDefinition("manage_ai_config", "Manage AI Config", "Manage AI credentials, models, agents, purposes.", "ai", ("write",), True),
    PermissionDefinition("manage_branding", "Manage Branding", "Update platform branding settings.", "platform", ("write",), False),
    PermissionDefinition("manage_platform_settings", "Manage Platform Settings", "Update platform-level settings.", "platform", ("write",), True),
    PermissionDefinition("manage_control_plane", "Manage Control Plane", "Deploy/rollback control-plane targets.", "deploy", ("execute",), True),
    PermissionDefinition("publish_control_plane", "Publish Control Plane", "Publish control-plane releases.", "deploy", ("execute",), True),
    PermissionDefinition("view_audit_logs", "View Audit Logs", "View audit and activity telemetry.", "audit", ("read",), True),
    PermissionDefinition("export_data", "Export Data", "Export governance and operational data.", "audit", ("export",), True),
    PermissionDefinition("manage_workspace_artifacts", "Manage Workspace Artifacts", "Create and update workspace artifacts.", "workspace", ("write",), False),
    PermissionDefinition("view_workspace", "View Workspace", "Read workspace-scoped content.", "workspace", ("read",), False),
]


ROLE_PERMISSION_MAP: Dict[str, List[Dict[str, Any]]] = {
    "platform_owner": [
        {"permissionKey": perm.key, "scope": None, "effect": "allow"}
        for perm in PERMISSIONS
    ],
    "platform_admin": [
        {"permissionKey": "view_platform", "scope": None, "effect": "allow"},
        {"permissionKey": "manage_tenants", "scope": None, "effect": "allow"},
        {"permissionKey": "manage_users", "scope": None, "effect": "allow"},
        {"permissionKey": "assign_roles", "scope": None, "effect": "allow"},
        {"permissionKey": "manage_idp", "scope": None, "effect": "allow"},
        {"permissionKey": "manage_secrets", "scope": None, "effect": "allow"},
        {"permissionKey": "manage_ai_config", "scope": None, "effect": "allow"},
        {"permissionKey": "manage_branding", "scope": None, "effect": "allow"},
        {"permissionKey": "manage_platform_settings", "scope": None, "effect": "allow"},
        {"permissionKey": "manage_control_plane", "scope": None, "effect": "allow"},
        {"permissionKey": "publish_control_plane", "scope": None, "effect": "allow"},
        {"permissionKey": "view_audit_logs", "scope": None, "effect": "allow"},
        {"permissionKey": "export_data", "scope": None, "effect": "allow"},
        {"permissionKey": "manage_workspace_artifacts", "scope": {"scope_kind": "workspace"}, "effect": "allow"},
        {"permissionKey": "view_workspace", "scope": {"scope_kind": "workspace"}, "effect": "allow"},
    ],
    "platform_architect": [
        {"permissionKey": "view_platform", "scope": None, "effect": "allow"},
        {"permissionKey": "manage_ai_config", "scope": None, "effect": "allow"},
        {"permissionKey": "manage_control_plane", "scope": None, "effect": "allow"},
        {"permissionKey": "publish_control_plane", "scope": None, "effect": "allow"},
        {"permissionKey": "view_audit_logs", "scope": None, "effect": "allow"},
        {"permissionKey": "view_workspace", "scope": {"scope_kind": "workspace"}, "effect": "allow"},
    ],
    "platform_operator": [
        {"permissionKey": "view_platform", "scope": None, "effect": "allow"},
        {"permissionKey": "view_workspace", "scope": {"scope_kind": "workspace"}, "effect": "allow"},
        {"permissionKey": "manage_workspace_artifacts", "scope": {"scope_kind": "workspace"}, "effect": "allow"},
    ],
    "app_user": [
        {"permissionKey": "view_workspace", "scope": {"scope_kind": "workspace"}, "effect": "allow"},
    ],
}


_registry_cache: Dict[str, Any] = {"value": None, "ts": 0.0}
REGISTRY_CACHE_TTL_SECONDS = 60


def merge_scope(role_scope: Dict[str, Any] | None, perm_scope: Dict[str, Any] | None) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    if isinstance(role_scope, dict):
        merged.update({k: v for k, v in role_scope.items() if v not in (None, "", [])})
    if isinstance(perm_scope, dict):
        merged.update({k: v for k, v in perm_scope.items() if v not in (None, "", [])})
    return merged


def _scope_key(scope: Dict[str, Any]) -> str:
    return json.dumps(scope or {}, sort_keys=True, separators=(",", ":"))


def canonical_registry() -> Dict[str, Any]:
    now = time.time()
    cached = _registry_cache.get("value")
    if cached and now - float(_registry_cache.get("ts") or 0) < REGISTRY_CACHE_TTL_SECONDS:
        return cached
    permission_payload = [
        {
            "key": perm.key,
            "name": perm.name,
            "description": perm.description,
            "category": perm.category,
            "tags": list(perm.tags),
            "isDangerous": perm.is_dangerous,
        }
        for perm in PERMISSIONS
    ]
    role_permissions: List[Dict[str, Any]] = []
    for role_id, perms in ROLE_PERMISSION_MAP.items():
        for row in perms:
            role_permissions.append(
                {
                    "roleId": role_id,
                    "permissionKey": row.get("permissionKey"),
                    "scope": row.get("scope"),
                    "effect": row.get("effect", "allow"),
                }
            )
    payload = {
        "permissions": permission_payload,
        "roles": ROLE_DEFINITIONS,
        "rolePermissions": role_permissions,
    }
    _registry_cache["value"] = payload
    _registry_cache["ts"] = now
    return payload


def search_users(query: str = "", limit: int = 200) -> List[Dict[str, Any]]:
    qs = UserIdentity.objects.all().order_by("display_name", "email", "subject")
    query = (query or "").strip()
    if query:
        qs = qs.filter(
            Q(display_name__icontains=query)
            | Q(email__icontains=query)
            | Q(subject__icontains=query)
        )
    users: List[Dict[str, Any]] = []
    for user in qs[: max(1, min(limit, 500))]:
        users.append(
            {
                "id": str(user.id),
                "name": user.display_name or user.email or user.subject,
                "email": user.email or "",
            }
        )
    return users


def _binding_scope(binding: RoleBinding) -> Dict[str, Any]:
    scope: Dict[str, Any] = {}
    if binding.scope_kind:
        scope["scope_kind"] = binding.scope_kind
    if binding.scope_id:
        scope["scope_id"] = str(binding.scope_id)
    return scope


def user_roles(user_id: str) -> List[Dict[str, Any]]:
    rows = RoleBinding.objects.filter(user_identity_id=user_id).order_by("role", "created_at")
    role_name_map = {item["id"]: item["name"] for item in ROLE_DEFINITIONS}
    return [
        {
            "roleId": row.role,
            "roleName": role_name_map.get(row.role, row.role),
            "scope": _binding_scope(row),
            "assignedAt": row.created_at,
        }
        for row in rows
    ]


def role_detail(role_id: str) -> Dict[str, Any]:
    role = next((item for item in ROLE_DEFINITIONS if item["id"] == role_id), None)
    if not role:
        raise KeyError(role_id)
    permissions = ROLE_PERMISSION_MAP.get(role_id, [])
    return {
        "role": role,
        "permissions": [
            {
                "permissionKey": row.get("permissionKey"),
                "scope": row.get("scope"),
                "effect": row.get("effect", "allow"),
            }
            for row in permissions
        ],
    }


def compute_effective_permissions(user_id: str) -> Dict[str, Any]:
    bindings = list(RoleBinding.objects.filter(user_identity_id=user_id).order_by("role", "created_at"))
    permission_map = {perm.key: perm for perm in PERMISSIONS}
    effective_map: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    for binding in bindings:
        role_perms = ROLE_PERMISSION_MAP.get(binding.role, [])
        role_scope = _binding_scope(binding)
        for rp in role_perms:
            permission_key = str(rp.get("permissionKey") or "").strip()
            if not permission_key:
                continue
            effect = str(rp.get("effect") or "allow")
            perm_scope = rp.get("scope") if isinstance(rp.get("scope"), dict) else {}
            merged_scope = merge_scope(role_scope, perm_scope)
            key = (permission_key, _scope_key(merged_scope), effect)
            if key not in effective_map:
                effective_map[key] = {
                    "permissionKey": permission_key,
                    "scope": merged_scope,
                    "effect": effect,
                    "sources": [],
                }
            effective_map[key]["sources"].append(
                {
                    "viaRoleId": binding.role,
                    "viaRoleName": next((r["name"] for r in ROLE_DEFINITIONS if r["id"] == binding.role), binding.role),
                    "roleScope": role_scope,
                    "permScope": perm_scope,
                    "mergedScope": merged_scope,
                    "ruleId": f"{binding.role}:{permission_key}",
                }
            )

    effective = list(effective_map.values())
    effective.sort(key=lambda item: (item["permissionKey"], _scope_key(item.get("scope") or {})))

    category_counts: Dict[str, int] = {}
    for row in effective:
        category = permission_map.get(row["permissionKey"]).category if permission_map.get(row["permissionKey"]) else "uncategorized"
        category_counts[category] = category_counts.get(category, 0) + 1

    summary = {
        "totalEffective": len(effective),
        "categories": [{"category": key, "count": count} for key, count in sorted(category_counts.items())],
    }

    return {"effective": effective, "summary": summary}
