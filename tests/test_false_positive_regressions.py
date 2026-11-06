"""Regression tests: every false positive we have hunted down and fixed is frozen
here as a case that must stay fixed, each paired with a positive control proving
the module still catches the real thing.

Policy: when a new false positive is found and fixed, add a case here (the benign
input that must NOT fire) plus a control (the genuine vuln that MUST fire). That
turns 'ongoing false-positive tuning' into 'a test goes red if it regresses'.
"""

import unittest

from _helpers import FakeHttp, findings_from, new_report, rage, resp

XSS_ECHO = rage.XSS_PAYLOAD  # the exact marker+payload rage injects


class TestReflectedXssNeedsHtml(unittest.TestCase):
    """A JSON API that echoes input (FastAPI 422, etc.) is NOT reflected XSS."""

    def _responder_echo(self, content_type):
        def r(url, method, data, headers):
            # Echo whatever marker is in the query back in the body (like a 422).
            body = '{"detail":[{"loc":["query"],"input":"%s"}]}' % XSS_ECHO
            if "html" in content_type:
                body = "<html><body>%s</body></html>" % XSS_ECHO
            return resp(body=body, content_type=content_type,
                        status=200 if "html" in content_type else 422)
        return r

    def test_json_echo_is_not_xss(self):
        http = FakeHttp(self._responder_echo("application/json"))
        report = new_report()
        url = "https://target.example/api/v1/jobs?engagement_id=1"
        rage.module_xss(http, report, [url], [])
        self.assertEqual(findings_from(report, "xss"), [],
                         "JSON echo must not produce any XSS finding (high OR encoded-medium)")

    def test_html_reflection_is_xss(self):  # positive control
        http = FakeHttp(self._responder_echo("text/html"))
        report = new_report()
        url = "https://target.example/search?q=1"
        rage.module_xss(http, report, [url], [])
        xss = findings_from(report, "xss")
        self.assertTrue(any(f.severity == "high" for f in xss),
                        "unescaped reflection in an HTML page must be flagged high")


class TestJwtIsNotASecret(unittest.TestCase):
    """A JWT in page source (e.g. a signed media URL) is not a leaked credential."""

    JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
           "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
           "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")

    def test_jwt_media_token_not_reported_as_secret(self):
        http = FakeHttp()  # not used: pages supplied directly
        report = new_report()
        body = '<img src="https://cdn.example/media/x.png?jwt=%s">' % self.JWT
        pages = [rage.Page("https://target.example/", body, {"content-type": "text/html"})]
        rage.module_secrets(http, report, pages, [], "https://target.example/")
        self.assertEqual(findings_from(report, "secrets"), [],
                         "a JWT must not be reported as an exposed secret")

    def test_real_aws_key_still_reported(self):  # positive control
        http = FakeHttp()
        report = new_report()
        body = "<script>const k='AKIAIOSFODNN7EXAMPLE';</script>"
        pages = [rage.Page("https://target.example/", body, {"content-type": "text/html"})]
        rage.module_secrets(http, report, pages, [], "https://target.example/")
        self.assertTrue(findings_from(report, "secrets"),
                        "a real AWS access key id must still be reported")


class TestNextParamIsNotSsrf(unittest.TestCase):
    """`next`/`redirect`/`continue` are open-redirect candidates, not SSRF."""

    def test_next_param_produces_no_ssrf_finding(self):
        http = FakeHttp(lambda *a, **k: resp(body="ok"))
        report = new_report()
        url = "https://target.example/login?next=https://wherever.example/"
        rage.module_ssrf(http, report, [url], None)
        self.assertEqual(findings_from(report, "ssrf"), [],
                         "a redirect-style 'next' param must not be flagged as SSRF")

    def test_url_param_is_ssrf_candidate(self):  # positive control
        http = FakeHttp(lambda *a, **k: resp(body="ok"))
        report = new_report()
        url = "https://target.example/fetch?url=https://wherever.example/"
        rage.module_ssrf(http, report, [url], None)
        ssrf = findings_from(report, "ssrf")
        self.assertTrue(ssrf, "a URL-taking 'url' param should be an SSRF candidate")
        self.assertEqual(ssrf[0].severity, "low")


class TestLoginThrottleHeuristicIsLow(unittest.TestCase):
    """The 'no throttling observed' signal is an unreliable heuristic (SPA/flow
    APIs break it), so it must stay severity low, never medium/high."""

    def test_no_throttle_finding_is_low_severity(self):
        # Every login POST returns a boring 200 — no 429, no 'too many'.
        http = FakeHttp(lambda *a, **k: resp(body="<html>login</html>", status=200))
        report = new_report()
        login = rage.Form(action="https://target.example/login", method="post",
                          inputs={"username": "", "password": ""}, has_password=True)
        rage.module_authactive(http, report, [login], active_auth=True)
        throttle = [f for f in findings_from(report, "authactive")
                    if "throttl" in f.title.lower()]
        self.assertTrue(throttle, "expected the 'no throttling observed' heuristic note")
        for f in throttle:
            self.assertEqual(f.severity, "low",
                             "login-throttle heuristic must remain low severity")


class TestSignedMediaTokenNotSensitiveUrl(unittest.TestCase):
    """A token in a static-asset URL (CDN signature) is not 'sensitive data in URL'."""

    def test_token_on_static_asset_not_flagged(self):
        report = new_report()
        urls = ["https://target.example/media/logo.png?token=abc123signature"]
        rage.module_mixed(report, [], urls, "https://target.example/")
        self.assertEqual(findings_from(report, "mixed"), [],
                         "a token on a static asset URL must not be flagged")

    def test_token_on_app_route_is_flagged(self):  # positive control
        report = new_report()
        urls = ["https://target.example/account?token=abc123"]
        rage.module_mixed(report, [], urls, "https://target.example/")
        mixed = findings_from(report, "mixed")
        self.assertTrue(mixed, "a credential-like token in a non-asset URL should be flagged")


if __name__ == "__main__":
    unittest.main()
