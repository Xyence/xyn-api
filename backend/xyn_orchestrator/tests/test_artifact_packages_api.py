import io
import json
import zipfile

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from xyn_orchestrator.models import (
    Artifact,
    ArtifactBindingValue,
    ArtifactInstallReceipt,
    ArtifactPackage,
    ArtifactRuntimeRole,
    ArtifactSurface,
    RoleBinding,
    UserIdentity,
)


class ArtifactPackagesApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(
            username="pkg-admin",
            password="pass",
            is_staff=True,
            email="pkg-admin@example.com",
        )
        self.client.force_login(self.user)
        self.identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer",
            subject="pkg-admin",
            email="pkg-admin@example.com",
            display_name="Pkg Admin",
        )
        session = self.client.session
        session["user_identity_id"] = str(self.identity.id)
        session.save()

    def _package_blob(self, *, artifacts, package_name="ems-hello", package_version="0.1.0", mutate_checksums=False):
        files = {}
        manifest_artifacts = []
        for item in artifacts:
            artifact_payload = {
                "artifact": {
                    "type": item["type"],
                    "slug": item["slug"],
                    "version": item["version"],
                    "title": item.get("title") or item["slug"],
                    "description": item.get("description") or "",
                },
                "content": item.get("content") or {},
            }
            base = f"artifacts/{item['type']}/{item['slug']}/{item['version']}"
            artifact_path = f"{base}/artifact.json"
            payload_path = f"{base}/payload/payload.json"
            surfaces_path = f"{base}/surfaces.json"
            runtime_roles_path = f"{base}/runtime_roles.json"
            files[artifact_path] = json.dumps(artifact_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            files[payload_path] = json.dumps(item.get("content") or {}, separators=(",", ":"), sort_keys=True).encode("utf-8")
            files[surfaces_path] = json.dumps(item.get("surfaces") or [], separators=(",", ":"), sort_keys=True).encode("utf-8")
            files[runtime_roles_path] = json.dumps(item.get("runtime_roles") or [], separators=(",", ":"), sort_keys=True).encode("utf-8")
            manifest_artifacts.append(
                {
                    "type": item["type"],
                    "slug": item["slug"],
                    "version": item["version"],
                    "artifact_id": item.get("artifact_id") or f"{item['type']}-{item['slug']}-{item['version']}",
                    "artifact_hash": "",
                    "dependencies": item.get("dependencies") or [],
                    "bindings": item.get("bindings") or [],
                }
            )

        checksums = {}
        import hashlib

        for path, blob in files.items():
            checksums[path] = hashlib.sha256(blob).hexdigest()

        manifest = {
            "format_version": 1,
            "package_name": package_name,
            "package_version": package_version,
            "built_at": "2026-02-28T00:00:00Z",
            "platform_compatibility": {"min_version": "1.0.0", "required_features": ["artifact_packages_v1"]},
            "artifacts": manifest_artifacts,
            "checksums": checksums,
        }
        manifest_blob = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")
        files["manifest.json"] = manifest_blob
        if mutate_checksums:
            manifest["checksums"][next(iter(checksums.keys()))] = "deadbeef"
            files["manifest.json"] = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for path, blob in sorted(files.items()):
                archive.writestr(path, blob)
        return buffer.getvalue()

    def _import_package(self, blob: bytes):
        upload = SimpleUploadedFile("bundle.zip", blob, content_type="application/zip")
        return self.client.post("/xyn/api/artifacts/packages/import", data={"file": upload})

    def _grant_debug_view(self):
        RoleBinding.objects.get_or_create(
            user_identity=self.identity,
            scope_kind="platform",
            role="platform_admin",
        )

    def test_manifest_validation_rejects_invalid_package_version(self):
        blob = self._package_blob(
            artifacts=[{"type": "app_shell", "slug": "ems-app", "version": "1.0.0", "content": {}}],
            package_version="invalid",
        )
        response = self._import_package(blob)
        self.assertEqual(response.status_code, 400)
        self.assertIn("package_version", json.dumps(response.json()))

    def test_checksum_verification_rejects_mismatch(self):
        blob = self._package_blob(
            artifacts=[{"type": "app_shell", "slug": "ems-app", "version": "1.0.0", "content": {}}],
            mutate_checksums=True,
        )
        response = self._import_package(blob)
        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertIn("checksum mismatch", " ".join(payload.get("details") or []))

    def test_validate_returns_dependency_order_and_unresolved_bindings(self):
        blob = self._package_blob(
            artifacts=[
                {
                    "type": "ui_view",
                    "slug": "ems-devices-view",
                    "version": "1.0.0",
                    "content": {"view": "list"},
                },
                {
                    "type": "app_shell",
                    "slug": "ems-shell",
                    "version": "1.0.0",
                    "content": {"routes": ["/ems/devices"]},
                    "dependencies": [{"type": "ui_view", "slug": "ems-devices-view", "version_range": "^1.0.0"}],
                    "bindings": [
                        {
                            "name": "BASE_URL",
                            "required": True,
                            "type": "url",
                            "resolution_strategy": "instance_setting",
                        }
                    ],
                },
            ]
        )
        imported = self._import_package(blob)
        self.assertEqual(imported.status_code, 200, imported.content.decode())
        package_id = imported.json()["package"]["id"]

        validate = self.client.post(
            f"/xyn/api/artifacts/packages/{package_id}/validate",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(validate.status_code, 200)
        payload = validate.json()
        self.assertFalse(payload["valid"])
        self.assertIn("binding unresolved: BASE_URL", payload["errors"])
        plan = payload["dependency_plan"]
        self.assertEqual(plan[0]["type"], "ui_view")
        self.assertEqual(plan[1]["type"], "app_shell")

    def test_install_is_idempotent_and_upgrade_records_receipt(self):
        ArtifactBindingValue.objects.create(name="BASE_URL", binding_type="url", value="https://ems.local")

        v1_blob = self._package_blob(
            artifacts=[
                {
                    "type": "data_model",
                    "slug": "ems_device",
                    "version": "1.0.0",
                    "content": {
                        "schema": {
                            "table_name": "ems_device",
                            "columns": [
                                {"name": "id", "type": "text", "nullable": False},
                                {"name": "name", "type": "text", "nullable": False},
                            ],
                        }
                    },
                },
                {
                    "type": "app_shell",
                    "slug": "ems-shell",
                    "version": "1.0.0",
                    "content": {"routes": ["/ems/devices"]},
                    "dependencies": [{"type": "data_model", "slug": "ems_device", "version_range": "^1.0.0"}],
                    "bindings": [{"name": "BASE_URL", "required": True, "type": "url", "resolution_strategy": "instance_setting"}],
                },
            ],
            package_version="1.0.0",
        )
        imported = self._import_package(v1_blob)
        self.assertEqual(imported.status_code, 200, imported.content.decode())
        pkg_v1 = imported.json()["package"]["id"]

        install1 = self.client.post(f"/xyn/api/artifacts/packages/{pkg_v1}/install", data=json.dumps({}), content_type="application/json")
        self.assertEqual(install1.status_code, 200, install1.content.decode())
        receipt1 = install1.json()["receipt"]
        self.assertEqual(receipt1["status"], "success")

        install2 = self.client.post(f"/xyn/api/artifacts/packages/{pkg_v1}/install", data=json.dumps({}), content_type="application/json")
        self.assertEqual(install2.status_code, 200, install2.content.decode())
        receipt2 = install2.json()["receipt"]
        actions = [row.get("action") for row in receipt2.get("artifact_changes") or []]
        self.assertIn("skip", actions)
        self.assertEqual(Artifact.objects.filter(type__slug="app_shell", slug="ems-shell").count(), 1)

        v2_blob = self._package_blob(
            artifacts=[
                {
                    "type": "data_model",
                    "slug": "ems_device",
                    "version": "1.1.0",
                    "content": {
                        "schema": {
                            "table_name": "ems_device",
                            "columns": [
                                {"name": "id", "type": "text", "nullable": False},
                                {"name": "name", "type": "text", "nullable": False},
                                {"name": "status", "type": "text", "nullable": True},
                            ],
                        }
                    },
                },
                {
                    "type": "app_shell",
                    "slug": "ems-shell",
                    "version": "1.1.0",
                    "content": {"routes": ["/ems/devices", "/ems/devices/:id"]},
                    "dependencies": [{"type": "data_model", "slug": "ems_device", "version_range": "^1.1.0"}],
                    "bindings": [{"name": "BASE_URL", "required": True, "type": "url", "resolution_strategy": "instance_setting"}],
                },
            ],
            package_version="1.1.0",
        )
        imported2 = self._import_package(v2_blob)
        self.assertEqual(imported2.status_code, 200, imported2.content.decode())
        pkg_v2 = imported2.json()["package"]["id"]
        install3 = self.client.post(f"/xyn/api/artifacts/packages/{pkg_v2}/install", data=json.dumps({}), content_type="application/json")
        self.assertEqual(install3.status_code, 200, install3.content.decode())
        receipt3 = install3.json()["receipt"]
        self.assertEqual(receipt3["install_mode"], "upgrade")

        shell = Artifact.objects.get(type__slug="app_shell", slug="ems-shell")
        self.assertEqual(shell.package_version, "1.1.0")
        self.assertEqual(ArtifactPackage.objects.count(), 2)
        self.assertEqual(ArtifactInstallReceipt.objects.count(), 3)

    def test_raw_endpoints_require_artifact_debug_permission(self):
        blob = self._package_blob(
            artifacts=[{"type": "app_shell", "slug": "ems-app", "version": "1.0.0", "content": {"view": "hello"}}]
        )
        imported = self._import_package(blob)
        self.assertEqual(imported.status_code, 200, imported.content.decode())
        package_id = imported.json()["package"]["id"]

        response = self.client.get(f"/xyn/api/artifacts/packages/{package_id}/raw/manifest")
        self.assertEqual(response.status_code, 403)

    def test_package_raw_tree_and_file_preview(self):
        self._grant_debug_view()
        blob = self._package_blob(
            artifacts=[{"type": "app_shell", "slug": "ems-app", "version": "1.0.0", "content": {"view": "hello"}}]
        )
        imported = self._import_package(blob)
        self.assertEqual(imported.status_code, 200, imported.content.decode())
        package_id = imported.json()["package"]["id"]

        tree = self.client.get(f"/xyn/api/artifacts/packages/{package_id}/raw/tree", {"path": "/"})
        self.assertEqual(tree.status_code, 200, tree.content.decode())
        entries = tree.json().get("entries") or []
        self.assertTrue(any(entry.get("name") == "manifest.json" for entry in entries))

        preview = self.client.get(
            f"/xyn/api/artifacts/packages/{package_id}/raw/file",
            {"path": "/manifest.json"},
        )
        self.assertEqual(preview.status_code, 200, preview.content.decode())

    def test_install_registers_surfaces_and_runtime_roles(self):
        self._grant_debug_view()
        blob = self._package_blob(
            artifacts=[
                {
                    "type": "app_shell",
                    "slug": "ems-surfaces",
                    "version": "1.0.0",
                    "content": {"view": "hello"},
                    "surfaces": [
                        {
                            "key": "dashboard",
                            "title": "EMS Dashboard",
                            "description": "Ops dashboard",
                            "surface_kind": "dashboard",
                            "route": "/app/a/ems/dashboard",
                            "nav_visibility": "always",
                            "nav_label": "EMS Dashboard",
                            "nav_icon": "Layers",
                            "nav_group": "Build",
                            "renderer": {"type": "ui_component_ref", "payload": {"component_key": "articles.index"}},
                            "context": {"required": [], "bindings": {}},
                            "permissions": {"required_roles": ["platform_admin"]},
                            "sort_order": 5,
                        }
                    ],
                    "runtime_roles": [
                        {"role_kind": "route_provider", "enabled": True, "spec": {"routes": ["/app/a/ems/dashboard"]}}
                    ],
                }
            ]
        )
        imported = self._import_package(blob)
        self.assertEqual(imported.status_code, 200, imported.content.decode())
        package_id = imported.json()["package"]["id"]

        install = self.client.post(f"/xyn/api/artifacts/packages/{package_id}/install", data=json.dumps({}), content_type="application/json")
        self.assertEqual(install.status_code, 200, install.content.decode())

        artifact = Artifact.objects.get(type__slug="app_shell", slug="ems-surfaces")
        surface = ArtifactSurface.objects.get(artifact=artifact, key="dashboard")
        runtime_role = ArtifactRuntimeRole.objects.get(artifact=artifact, role_kind="route_provider")
        self.assertEqual(surface.route, "/app/a/ems/dashboard")
        self.assertTrue(runtime_role.enabled)

    def test_surface_resolve_endpoint_matches_declared_route(self):
        self._grant_debug_view()
        blob = self._package_blob(
            artifacts=[
                {
                    "type": "app_shell",
                    "slug": "ems-router",
                    "version": "1.0.0",
                    "content": {"view": "hello"},
                    "surfaces": [
                        {
                            "key": "detail",
                            "title": "EMS Detail",
                            "surface_kind": "editor",
                            "route": "/app/a/ems/:artifactId",
                            "nav_visibility": "hidden",
                            "renderer": {"type": "ui_component_ref", "payload": {"component_key": "articles.draft_editor"}},
                        }
                    ],
                }
            ]
        )
        imported = self._import_package(blob)
        package_id = imported.json()["package"]["id"]
        install = self.client.post(f"/xyn/api/artifacts/packages/{package_id}/install", data=json.dumps({}), content_type="application/json")
        self.assertEqual(install.status_code, 200, install.content.decode())
        artifact = Artifact.objects.get(type__slug="app_shell", slug="ems-router")

        resolved = self.client.get("/xyn/api/artifact-surfaces/resolve", {"path": f"/app/a/ems/{artifact.id}"})
        self.assertEqual(resolved.status_code, 200, resolved.content.decode())
        payload = resolved.json()
        self.assertEqual(payload.get("surface", {}).get("key"), "detail")
        self.assertEqual(payload.get("params", {}).get("artifactId"), str(artifact.id))
        payload = preview.json()
        self.assertTrue(payload.get("inline"))
        self.assertIn("format_version", str(payload.get("content") or ""))

    def test_installed_artifact_raw_endpoints(self):
        self._grant_debug_view()
        ArtifactBindingValue.objects.create(name="BASE_URL", binding_type="url", value="https://ems.local")
        blob = self._package_blob(
            artifacts=[
                {
                    "type": "app_shell",
                    "slug": "ems-shell",
                    "version": "1.0.0",
                    "content": {"routes": ["/ems/devices"]},
                    "bindings": [{"name": "BASE_URL", "required": True, "type": "url", "resolution_strategy": "instance_setting"}],
                }
            ],
            package_version="1.0.0",
        )
        imported = self._import_package(blob)
        self.assertEqual(imported.status_code, 200, imported.content.decode())
        package_id = imported.json()["package"]["id"]
        installed = self.client.post(f"/xyn/api/artifacts/packages/{package_id}/install", data=json.dumps({}), content_type="application/json")
        self.assertEqual(installed.status_code, 200, installed.content.decode())

        artifact = Artifact.objects.get(type__slug="app_shell", slug="ems-shell")
        metadata = self.client.get(f"/xyn/api/artifacts/{artifact.id}/raw/metadata")
        self.assertEqual(metadata.status_code, 200, metadata.content.decode())
        self.assertEqual(metadata.json().get("artifact", {}).get("slug"), "ems-shell")

        listing = self.client.get(f"/xyn/api/artifacts/{artifact.id}/raw/files", {"path": "/"})
        self.assertEqual(listing.status_code, 200, listing.content.decode())
        entries = listing.json().get("entries") or []
        self.assertTrue(any(entry.get("name") == "artifact.json" for entry in entries))

        invalid = self.client.get(f"/xyn/api/artifacts/{artifact.id}/raw/files", {"path": "../"})
        self.assertEqual(invalid.status_code, 400)
