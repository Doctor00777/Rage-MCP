"""#5 Golden corpus: run the real scanner end-to-end against a known-vulnerable
local app and a clean one, asserting recall (finds the planted bugs) and precision
(stays quiet on the safe equivalents). Deterministic, no network, CI-friendly.
"""

import argparse
import unittest

from _helpers import rage
from fixtures import CORPUS_MODULES, CorpusServer


def _scan(base_url):
    args = argparse.Namespace(
        target=base_url, modules=list(CORPUS_MODULES), authorized=True,
        time_based=False, active_auth=False, oob=None,
        cookie=None, header=[], login_url=None, login_data=None,
        headless=False, sqlmap=False, nuclei=False, tls_audit=False,
        openapi=False, openapi_spec=None, thorough=False,
        max_pages=15, max_requests=2000, delay=0.0,
        timeout=5.0, port_timeout=0.2, insecure=True, json=None,
    )
    return rage.run(args)


def _modules_with_real_findings(report):
    real = {"critical", "high", "medium", "low"}
    return {f.module for f in report.findings if f.severity in real}


class TestVulnerableAppRecall(unittest.TestCase):
    """Every planted bug must be found."""

    @classmethod
    def setUpClass(cls):
        with CorpusServer(vulnerable=True) as srv:
            cls.report = _scan(srv.base_url)
        cls.hit = _modules_with_real_findings(cls.report)

    def _titles(self, module):
        return [f.title for f in self.report.findings if f.module == module]

    def test_missing_security_headers_found(self):
        self.assertIn("headers", self.hit)

    def test_aws_key_found(self):
        self.assertIn("secrets", self.hit)

    def test_reflected_xss_found(self):
        xss_high = [f for f in self.report.findings if f.module == "xss" and f.severity == "high"]
        self.assertTrue(xss_high, f"expected a high XSS finding; got {self._titles('xss')}")

    def test_sql_error_found(self):
        self.assertIn("sqli", self.hit)

    def test_open_redirect_found(self):
        self.assertIn("redirect", self.hit)

    def test_dotenv_exposure_found(self):
        self.assertIn("auth", self.hit)

    def test_exposed_spec_found(self):
        self.assertIn("files", self.hit)


class TestCleanAppPrecision(unittest.TestCase):
    """The safe equivalents must produce none of those findings."""

    @classmethod
    def setUpClass(cls):
        with CorpusServer(vulnerable=False) as srv:
            cls.report = _scan(srv.base_url)
        cls.hit = _modules_with_real_findings(cls.report)

    def test_no_injection_or_access_findings(self):
        for module in ("xss", "sqli", "redirect", "secrets", "auth", "files"):
            with self.subTest(module=module):
                self.assertNotIn(module, self.hit,
                                 f"clean app wrongly flagged by {module}: "
                                 f"{[f.title for f in self.report.findings if f.module == module]}")

    def test_no_missing_security_headers(self):
        missing = [f for f in self.report.findings
                   if f.module == "headers" and f.title.startswith("Missing header")]
        self.assertEqual(missing, [], f"clean app should set all headers; got {missing}")


if __name__ == "__main__":
    unittest.main()
