import os
import unittest

import django
import requests


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xyence.settings")
django.setup()

from articles.admin import _format_xyn_seed_error  # noqa: E402


def _http_error(status_code: int) -> requests.HTTPError:
    response = requests.Response()
    response.status_code = status_code
    return requests.HTTPError(response=response)


class XynSeedErrorFormatTests(unittest.TestCase):
    def test_auth_error(self):
        message = _format_xyn_seed_error(_http_error(401))
        self.assertIn("authorization", message.lower())

    def test_forbidden_error(self):
        message = _format_xyn_seed_error(_http_error(403))
        self.assertIn("authorization", message.lower())

    def test_other_error(self):
        message = _format_xyn_seed_error(_http_error(500))
        self.assertIn("http 500", message.lower())


if __name__ == "__main__":
    unittest.main()
