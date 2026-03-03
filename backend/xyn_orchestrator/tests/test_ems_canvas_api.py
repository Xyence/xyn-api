import json

from django.contrib.auth import get_user_model
from django.test import TestCase


class EmsCanvasApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.staff = user_model.objects.create_user(username="staff", email="staff@example.com", password="pass", is_staff=True)
        self.client.force_login(self.staff)

    def test_devices_canvas_table_filters_state(self):
        response = self.client.get(
            "/api/ems/devices",
            {
                "filters": json.dumps([{"field": "state", "op": "eq", "value": "unregistered"}]),
                "sort": json.dumps([{"field": "created_at", "dir": "desc"}]),
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload.get("type"), "canvas.table")
        self.assertEqual((payload.get("dataset") or {}).get("name"), "ems_devices")
        rows = (payload.get("dataset") or {}).get("rows") or []
        self.assertTrue(rows)
        self.assertTrue(all(str(row.get("state") or "") == "unregistered" for row in rows))

    def test_registrations_canvas_supports_relative_time_filter(self):
        response = self.client.get(
            "/api/ems/registrations",
            {
                "filters": json.dumps([{"field": "registered_at", "op": "gte", "value": "now-24h"}]),
                "sort": json.dumps([{"field": "registered_at", "dir": "desc"}]),
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual((payload.get("dataset") or {}).get("name"), "ems_registrations")
        self.assertIn("query", payload)

    def test_status_rollup_and_dataset_schema(self):
        rollup = self.client.get("/api/ems/reports/device-status-rollup")
        self.assertEqual(rollup.status_code, 200)
        rollup_rows = (rollup.json().get("dataset") or {}).get("rows") or []
        self.assertTrue(any(str(row.get("bucket") or "") == "offline" for row in rollup_rows))

        schema = self.client.get("/api/ems/datasets/ems_devices/schema")
        self.assertEqual(schema.status_code, 200)
        schema_rows = (schema.json().get("dataset") or {}).get("rows") or []
        self.assertTrue(any(str(row.get("key") or "") == "state" for row in schema_rows))
