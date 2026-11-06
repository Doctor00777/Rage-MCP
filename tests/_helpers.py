"""Shared test helpers: path setup + a network-free fake HTTP client.

rage's modules all take an `http` object with a `.request(...)` method and read
canned `HttpResponse` objects. By swapping in `FakeHttp` we can drive every
detection module with a frozen response and assert exactly what it reports — with
no network, no live target, and deterministic results in CI.
"""

from __future__ import annotations

import os
import sys

# Make `import rage` work no matter where the tests are launched from.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import rage  # noqa: E402  (import after sys.path tweak)


def resp(body: str = "",
         content_type: str = "text/html; charset=utf-8",
         status: int = 200,
         headers: dict | None = None,
         url: str = "https://target.example/",
         elapsed: float = 0.01) -> "rage.HttpResponse":
    """Build an HttpResponse. Header keys are lower-cased like the real client."""
    h = {"content-type": content_type}
    if headers:
        h.update({k.lower(): v for k, v in headers.items()})
    return rage.HttpResponse(status=status, headers=h, body=body, url=url, elapsed=elapsed)


class FakeHttp:
    """Drop-in for rage.Http. `responder(url, method, data, headers)` returns an
    HttpResponse (or None). Default returns None (target unreachable)."""

    def __init__(self, responder=None):
        self._responder = responder or (lambda *a, **k: None)
        self.requests: list[dict] = []
        self.extra_headers: dict[str, str] = {}
        self.count = 0

    def request(self, url, method="GET", data=None, headers=None, allow_redirects=True):
        self.count += 1
        self.requests.append({"url": url, "method": method, "data": data,
                              "headers": headers, "allow_redirects": allow_redirects})
        return self._responder(url, method, data, headers)


def new_report(target: str = "https://target.example/") -> "rage.Report":
    return rage.Report(target=target)


def findings_from(report: "rage.Report", module: str) -> list:
    return [f for f in report.findings if f.module == module]
