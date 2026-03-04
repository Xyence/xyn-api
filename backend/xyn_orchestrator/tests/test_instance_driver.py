from django.test import SimpleTestCase

from xyn_orchestrator.instance_drivers import (
    SshDockerComposeInstanceDriver,
    allocate_remote_ports,
    compute_base_urls,
)


class InstanceDriverUtilsTests(SimpleTestCase):
    def test_allocate_remote_ports_prefers_requested_when_free(self):
        ui, api = allocate_remote_ports([80, 443], requested_ui=42100, requested_api=42101)
        self.assertEqual(ui, 42100)
        self.assertEqual(api, 42101)

    def test_allocate_remote_ports_chooses_first_available(self):
        ui, api = allocate_remote_ports([42000, 42001, 42003], requested_ui=None, requested_api=None, start=42000, end=42005)
        self.assertEqual(ui, 42002)
        self.assertEqual(api, 42004)

    def test_compute_base_urls_prefers_fqdn(self):
        urls = compute_base_urls(
            fqdn="ems.xyence.io",
            scheme="https",
            public_hostname="",
            public_ipv4="54.1.2.3",
            ui_port=42000,
            api_port=42001,
        )
        self.assertEqual(urls["base_url"], "https://ems.xyence.io")
        self.assertEqual(urls["api_url"], "https://ems.xyence.io/xyn/api")

    def test_compute_base_urls_falls_back_to_ip(self):
        urls = compute_base_urls(
            fqdn="",
            scheme="http",
            public_hostname="",
            public_ipv4="54.1.2.3",
            ui_port=42000,
            api_port=42001,
        )
        self.assertEqual(urls["base_url"], "http://54.1.2.3:42000")
        self.assertEqual(urls["api_url"], "http://54.1.2.3:42001")

    def test_driver_prepare_dry_run_generates_compose(self):
        driver = SshDockerComposeInstanceDriver(dry_run=True)
        plan = driver.prepare(
            instance={
                "network": {"public_ipv4": "54.1.2.3"},
                "access": {
                    "ssh": {
                        "host": "54.1.2.3",
                        "user": "ubuntu",
                        "port": 22,
                        "resolved": {"private_key": "dummy"},
                    }
                },
            },
            release_spec={
                "name": "demo",
                "parameters": {"instance_label": "demo-1", "fqdn": "", "scheme": "http"},
                "components": [
                    {"slug": "xyn-api", "enabled": True, "image_ref": "xyn-api:dev"},
                    {"slug": "xyn-ui", "enabled": True, "image_ref": "xyn-ui:dev"},
                ],
            },
        )
        self.assertIn("xyn-api", plan.compose_yaml)
        self.assertIn("xyn-ui", plan.compose_yaml)
        self.assertTrue(plan.compose_project.startswith("xyn-"))
