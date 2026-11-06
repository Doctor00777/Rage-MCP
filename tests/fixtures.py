"""Golden-corpus fixture apps for end-to-end tests.

Two tiny stdlib HTTP servers on 127.0.0.1 (ephemeral port, no network, no Docker):

  * a DELIBERATELY VULNERABLE app with a known set of planted bugs, and
  * a CLEAN app serving the safe equivalent of each route.

Running the real `rage.run()` against both lets us assert the scanner catches the
planted bugs (recall) AND stays quiet on the clean app (precision) — a deterministic
substitute for pointing rage at OWASP Juice Shop in CI. A live Juice Shop smoke test
could be added later as an optional, network-gated extra.

Planted vulnerabilities (vulnerable app):
  module     route                         why it fires
  --------   ---------------------------   ----------------------------------------
  headers    /                             no security headers at all
  secrets    /  (AWS key in HTML)          AKIA... string in delivered source
  xss        /search?q=                    reflects q unescaped into an HTML page
  sqli       /item?id=                      a quote elicits a SQL error string
  redirect   /go?next=                      302 to an attacker-controlled Location
  auth       /.env                          200 body matching a secrets signature
  files      /openapi.json                  spec exposed (also feeds openapi module)
"""

from __future__ import annotations

import http.server
import json
import threading
import urllib.parse

# Modules exercised by the corpus test — the ones with planted bugs. Kept tight so
# the run is fast and deterministic (no TLS/port scanning of the host).
CORPUS_MODULES = ["headers", "files", "secrets", "redirect", "sqli", "xss", "auth"]

_SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
}

_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # canonical AWS docs example key (not a real secret)

_INDEX = """<!doctype html><html><head><title>corpus</title></head><body>
<h1>Corpus app</h1>
<a href="/search?q=hello">search</a>
<a href="/item?id=1">item</a>
<a href="/go?next=/home">go home</a>
<!-- deploy key {key} -->
</body></html>"""

_RESULTS = "<!doctype html><html><body><h1>Results</h1><p>No matches.</p></body></html>"
_ITEM_OK = "<!doctype html><html><body><h1>Item 1</h1><p>A widget.</p></body></html>"
_HOME = "<!doctype html><html><body><h1>Home</h1></body></html>"
_SQL_ERROR = ("<!doctype html><html><body><h1>Error</h1><pre>You have an error in your "
              "SQL syntax; check the manual near ''' at line 1</pre></body></html>")
_OPENAPI = json.dumps({
    "openapi": "3.0.0", "info": {"title": "Corpus API", "version": "1"},
    "paths": {"/item": {"get": {"parameters": [
        {"name": "id", "in": "query", "schema": {"type": "string"}}]}}},
})


def _make_handler(vulnerable: bool):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # keep test output clean
            pass

        def _respond(self, status, body, ctype="text/html; charset=utf-8", location=None):
            data = body.encode("utf-8")
            # send_response_only avoids the default Server/Date headers, so the
            # clean app's header set is exactly what we choose below.
            self.send_response_only(status)
            if not vulnerable:
                for k, v in _SECURITY_HEADERS.items():
                    self.send_header(k, v)
            if location is not None:
                self.send_header("Location", location)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def do_GET(self):
            pr = urllib.parse.urlparse(self.path)
            path = pr.path
            q = urllib.parse.parse_qs(pr.query)

            if path in ("/", "/index.html"):
                return self._respond(200, _INDEX.format(key=_AWS_KEY if vulnerable else "redacted"))

            if path == "/home":
                return self._respond(200, _HOME)

            if path == "/search":
                val = (q.get("q", [""])[0])
                if vulnerable:
                    return self._respond(200, f"<!doctype html><html><body><h1>Search</h1>"
                                              f"<p>You searched: {val}</p></body></html>")
                return self._respond(200, _RESULTS)

            if path == "/item":
                val = (q.get("id", [""])[0])
                if vulnerable and ("'" in val or '"' in val):
                    return self._respond(200, _SQL_ERROR)
                return self._respond(200, _ITEM_OK)

            if path == "/go":
                nxt = (q.get("next", [""])[0])
                if vulnerable:
                    return self._respond(302, "redirecting", location=nxt)
                return self._respond(200, _HOME)  # clean: ignore next, no redirect

            if path == "/.env":
                if vulnerable:
                    return self._respond(200, "SECRET_KEY=deadbeefcafe\nDB_PASSWORD=hunter2\n",
                                         ctype="text/plain")
                return self._respond(404, "Not Found")

            if path == "/openapi.json":
                if vulnerable:
                    return self._respond(200, _OPENAPI, ctype="application/json")
                return self._respond(404, "Not Found")

            return self._respond(404, "Not Found")

    return Handler


class CorpusServer:
    """Context manager that serves one corpus app and tears it down."""

    def __init__(self, vulnerable: bool):
        self._httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(vulnerable))
        self.port = self._httpd.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}/"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)
