"""Unit tests for the shared verifier helpers and detection-gating constants.

These are the small, centralised gates that several modules share. Pinning them
here means a change that would re-introduce a known false positive fails fast,
in one obvious place, instead of only showing up as noise on a live scan.
"""

import unittest

from _helpers import rage, resp


class TestIsHtml(unittest.TestCase):
    """A reflected marker is only XSS if the response is actually rendered as HTML."""

    def test_html_is_html(self):
        self.assertTrue(rage._is_html(resp(content_type="text/html; charset=utf-8")))

    def test_json_is_not_html(self):
        # FastAPI 422 validation errors echo input as JSON — not an XSS sink.
        self.assertFalse(rage._is_html(resp(content_type="application/json")))

    def test_plaintext_is_not_html(self):
        self.assertFalse(rage._is_html(resp(content_type="text/plain")))

    def test_none_response_is_not_html(self):
        self.assertFalse(rage._is_html(None))

    def test_missing_content_type_is_not_html(self):
        r = resp()
        r.headers.pop("content-type", None)
        self.assertFalse(rage._is_html(r))


class TestIsWeakCipher(unittest.TestCase):
    """TLS 1.3 / strong 1.2 suites must never be flagged 'weak'."""

    STRONG = [
        "TLS_AES_256_GCM_SHA384",          # TLS 1.3
        "TLS_AES_128_GCM_SHA256",          # TLS 1.3
        "TLS_CHACHA20_POLY1305_SHA256",    # TLS 1.3
        "ECDHE-RSA-AES256-GCM-SHA384",     # strong TLS 1.2
        "ECDHE-ECDSA-AES128-GCM-SHA256",   # strong TLS 1.2
    ]
    WEAK = [
        "RC4-MD5",
        "DES-CBC3-SHA",
        "ECDHE-RSA-DES-CBC3-SHA",
        "EXP-RC2-CBC-MD5",
        "NULL-SHA",
    ]

    def test_strong_ciphers_not_flagged(self):
        for name in self.STRONG:
            with self.subTest(cipher=name):
                self.assertFalse(rage._is_weak_cipher(name), f"{name} wrongly flagged weak")

    def test_weak_ciphers_flagged(self):
        for name in self.WEAK:
            with self.subTest(cipher=name):
                self.assertTrue(rage._is_weak_cipher(name), f"{name} should be flagged weak")

    def test_empty_name_is_not_weak(self):
        self.assertFalse(rage._is_weak_cipher(""))


class TestIsStaticAsset(unittest.TestCase):
    """Signed-media/static-asset URLs legitimately carry tokens in the query string."""

    ASSETS = [
        "https://t/img/logo.png?token=abc",
        "https://t/app.1a2b.js?v=3",
        "https://t/styles.css?token=x",
        "https://t/fonts/f.woff2?sig=y",
        "https://t/pic.JPG?Signature=z",
        "https://t/app.js.map?token=q",
    ]
    NON_ASSETS = [
        "https://t/account?token=abc",
        "https://t/api/v1/jobs?session=xyz",
        "https://t/download?file=report.pdf",
    ]

    def test_assets_detected(self):
        for url in self.ASSETS:
            with self.subTest(url=url):
                self.assertTrue(rage._is_static_asset(url))

    def test_non_assets_not_detected(self):
        for url in self.NON_ASSETS:
            with self.subTest(url=url):
                self.assertFalse(rage._is_static_asset(url))


class TestParamClassification(unittest.TestCase):
    """Redirect-style param names are open-redirect candidates, NOT SSRF."""

    REDIRECTISH = ["next", "redirect", "return", "returnurl", "continue", "goto", "dest"]

    def test_redirectish_not_in_ssrf_params(self):
        for name in self.REDIRECTISH:
            with self.subTest(param=name):
                self.assertNotIn(name, rage.SSRF_PARAMS)

    def test_redirectish_in_redirect_params(self):
        for name in self.REDIRECTISH:
            with self.subTest(param=name):
                self.assertIn(name, rage.REDIRECT_PARAMS)

    def test_fetch_params_still_ssrf(self):
        for name in ("url", "uri", "image", "webhook", "fetch"):
            with self.subTest(param=name):
                self.assertIn(name, rage.SSRF_PARAMS)


class TestSecretPatterns(unittest.TestCase):
    """JWTs are commonly public (signed media URLs) and must NOT be 'secrets';
    genuine credential formats must still match."""

    # A realistic-looking but non-sensitive JWT (header.payload.sig).
    SAMPLE_JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
                  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    REAL_SECRETS = [
        "AKIAIOSFODNN7EXAMPLE",                       # AWS access key id
        "-----BEGIN RSA PRIVATE KEY-----",            # private key
        "ghp_0123456789abcdefghijklmnopqrstuvwxyz0",  # GitHub PAT (36 chars)
    ]

    def test_jwt_not_matched_by_any_secret_pattern(self):
        for rx, _sev, label in rage.SECRET_PATTERNS:
            with self.subTest(pattern=label):
                self.assertIsNone(rx.search(self.SAMPLE_JWT),
                                  f"JWT wrongly matched secret pattern: {label}")

    def test_real_secrets_still_matched(self):
        for secret in self.REAL_SECRETS:
            with self.subTest(secret=secret[:12]):
                hit = any(rx.search(secret) for rx, _s, _l in rage.SECRET_PATTERNS)
                self.assertTrue(hit, f"expected a secret pattern to match: {secret[:12]}...")


if __name__ == "__main__":
    unittest.main()
