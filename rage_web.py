#!/usr/bin/env python3
"""
rage_web — a local web UI for the `rage` security recon scanner.

Serves a form on http://127.0.0.1:<port> (localhost only). Enter a target,
pick modules, confirm authorization, and view a color-coded, OWASP-mapped
report. Reuses rage.py's scan engine directly, so behavior matches the CLI.

Stdlib only. Bound to loopback by default. Scans run synchronously.

USE ONLY ON SYSTEMS YOU OWN OR ARE EXPLICITLY AUTHORIZED TO TEST.
"""

from __future__ import annotations

import argparse
import html
import http.server
import socketserver
import urllib.parse

import rage

SEV_COLORS = {
    "critical": "#7f1d1d", "high": "#b91c1c", "medium": "#b45309",
    "low": "#2563eb", "info": "#4b5563",
}

MODULE_LABELS = {
    "headers": "Security headers (A02)", "misconfig": "Misconfig / errors (A02/A10)",
    "files": "Backup / API-doc discovery (A02)", "secrets": "Secrets in source (A02)",
    "ports": "Risky ports (A02)", "tls": "TLS / crypto (A04)",
    "ciphers": "Weak ciphers (A04)", "mixed": "Mixed content / URL data (A04)",
    "cors": "CORS (A01)", "methods": "HTTP methods / TRACE (A01)",
    "redirect": "Open redirect (A01)", "ssrf": "SSRF (A01)",
    "traversal": "Path traversal / LFI (A01)", "sqli": "SQL injection (A05)",
    "xss": "XSS (A05)", "ssti": "Template injection (A05)",
    "cmdi": "Command injection (A05)", "crlf": "CRLF / host-header (A05)",
    "injerr": "NoSQL / LDAP / XPath (A05)", "csrf": "CSRF token (A01)",
    "jwt": "JWT flaws (A07)", "auth": "Auth / access (A01/A07)",
    "authactive": "Login rate-limit / enum (A07)", "fingerprint": "Tech / takeover (A03)",
    "integrity": "SRI / supply chain (A03/A08)",
    "sqlmap": "sqlmap confirm (A05)", "nuclei": "nuclei templates",
    "tlsaudit": "TLS audit — sslyze/testssl (A04)",
    "openapi": "OpenAPI endpoint fuzzing (A05)",
}

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rage — web security recon</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; max-width: 920px; margin: 2rem auto;
         padding: 0 1rem; line-height: 1.5; }}
  h1 {{ margin-bottom: 0; }}
  .sub {{ color: #6b7280; margin-top: .25rem; }}
  form {{ background: rgba(127,127,127,.08); padding: 1rem 1.25rem; border-radius: 10px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: .3rem .9rem; }}
  label {{ display: block; }}
  input[type=text] {{ width: 100%; padding: .55rem; font-size: 1rem; box-sizing: border-box;
                      border: 1px solid #9994; border-radius: 6px; }}
  .row {{ margin: .7rem 0; }}
  button {{ background: #b91c1c; color: #fff; border: 0; padding: .6rem 1.4rem;
           font-size: 1rem; border-radius: 6px; cursor: pointer; }}
  button:hover {{ background: #991b1b; }}
  .warn {{ background: #b45309; color:#fff; padding:.5rem .75rem; border-radius:6px; font-size:.9rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #9993;
           vertical-align: top; font-size: .92rem; }}
  .sev {{ color:#fff; padding: .12rem .5rem; border-radius: 4px; font-size:.78rem;
         font-weight:600; white-space:nowrap; }}
  .owasp {{ font-size:.75rem; color:#6b7280; white-space:nowrap; }}
  code {{ word-break: break-all; }}
  fieldset {{ border:1px solid #9994; border-radius:8px; }}
</style></head><body>
<h1>rage</h1>
<p class="sub">Authorized-only web security recon — mapped to OWASP Top 10 (2026)</p>
<p class="warn">Only scan systems you own or have written permission to test.</p>
<form method="post" action="/scan">
  <div class="row"><input type="text" name="target" placeholder="https://beta.example.com"
       value="{target}" autofocus required></div>
  <fieldset><legend>Checks</legend><div class="grid">{modules_html}</div></fieldset>
  <div class="row">
    <label style="display:inline;"><input type="checkbox" name="time_based" {time_based}>
      Time-based SQLi &amp; command-injection probes</label>
    &nbsp;&nbsp;<label style="display:inline;"><input type="checkbox" name="active_auth" {active_auth}>
      Login rate-limit / enumeration probes</label>
    &nbsp;&nbsp;<label style="display:inline;">Delay (s)
      <input type="text" name="delay" value="{delay}" style="width:4rem;display:inline;"></label>
  </div>
  <div class="row">
    <label style="display:inline;"><input type="checkbox" name="headless" {headless}>
      Headless crawl (JS/SPA, Playwright)</label>
    &nbsp;&nbsp;<label style="display:inline;"><input type="checkbox" name="nuclei" {nuclei}>
      nuclei templates</label>
    &nbsp;&nbsp;<label style="display:inline;"><input type="checkbox" name="sqlmap" {sqlmap}>
      sqlmap confirm</label>
    &nbsp;&nbsp;<label style="display:inline;" title="Enable headless + sqlmap + nuclei + TLS audit + OpenAPI fuzzing at once">
      <input type="checkbox" name="thorough" {thorough}>
      <strong>Thorough</strong> (lean on all engines)</label>
  </div>
  <div class="row"><label style="display:inline;">SSRF out-of-band URL (optional)
    <input type="text" name="oob" value="{oob}" placeholder="https://your-collaborator"
           style="width:16rem;display:inline;"></label></div>
  <fieldset><legend>Authenticated scan (optional)</legend>
    <div class="row"><label style="display:inline;">Cookie
      <input type="text" name="cookie" value="{cookie}" placeholder="session=abc123"
             style="width:18rem;display:inline;"></label></div>
    <div class="row"><label style="display:inline;">Login URL
      <input type="text" name="login_url" value="{login_url}" placeholder="https://site/login"
             style="width:15rem;display:inline;"></label>
      &nbsp;<label style="display:inline;">Login data
      <input type="text" name="login_data" value="{login_data}" placeholder="user=a&amp;pass=b"
             style="width:13rem;display:inline;"></label></div>
  </fieldset>
  <div class="row">
    <label style="display:inline;"><input type="checkbox" name="authorized" required {authorized}>
      I am authorized to test this target</label>
  </div>
  <div class="row"><button type="submit">Scan</button></div>
</form>
{results}
</body></html>"""


def _modules_html(selected) -> str:
    out = []
    for key in rage.ALL_MODULES:
        ck = "checked" if (not selected or key in selected) else ""
        label = html.escape(MODULE_LABELS.get(key, key))
        out.append(f"<label><input type='checkbox' name='m' value='{key}' {ck}> {label}</label>")
    return "".join(out)


def render_page(target="", modules=None, time_based=False, delay="0.3",
                authorized=False, results="", active_auth=False, oob="",
                cookie="", login_url="", login_data="",
                headless=False, sqlmap=False, nuclei=False, thorough=False):
    return PAGE.format(
        target=html.escape(target, quote=True),
        modules_html=_modules_html(modules),
        time_based="checked" if time_based else "",
        active_auth="checked" if active_auth else "",
        headless="checked" if headless else "",
        sqlmap="checked" if sqlmap else "",
        nuclei="checked" if nuclei else "",
        thorough="checked" if thorough else "",
        oob=html.escape(oob, quote=True),
        cookie=html.escape(cookie, quote=True),
        login_url=html.escape(login_url, quote=True),
        login_data=html.escape(login_data, quote=True),
        delay=html.escape(delay, quote=True),
        authorized="checked" if authorized else "",
        results=results,
    )


def _clean_html(report) -> str:
    clean = getattr(report, "checks_clean", [])
    if not clean:
        return ""
    items = "".join(f"<li>{html.escape(rage.CLEAN_DESCRIPTIONS.get(n, n))}</li>" for n in clean)
    return ("<h3>Checks that ran and found nothing</h3>"
            "<p style='color:#6b7280'>Not proof the issue is absent — an unauthenticated "
            "black-box scan can miss real bugs.</p><ul>" + items + "</ul>")


def render_results(report) -> str:
    findings = report.sorted()
    head = f"<h2>Results — {html.escape(report.target)}</h2>"
    if not findings:
        return head + "<p>No findings reported.</p>" + _clean_html(report)
    rows = []
    for f in findings:
        color = SEV_COLORS.get(f.severity, "#4b5563")
        owasp = f"{f.owasp} {rage.OWASP_2026.get(f.owasp, '')}" if f.owasp else ""
        ev = f"<br><code>{html.escape(f.evidence.strip()[:160])}</code>" if f.evidence else ""
        loc = f"<br><code>{html.escape(f.location)}</code>" if f.location else ""
        rows.append(
            f"<tr><td><span class='sev' style='background:{color}'>{f.severity.upper()}</span></td>"
            f"<td class='owasp'>{html.escape(owasp)}</td>"
            f"<td><strong>{html.escape(f.title)}</strong><br>{html.escape(f.detail)}{loc}{ev}</td></tr>"
        )
    return (head + f"<p>{len(findings)} finding(s).</p>"
            "<table><thead><tr><th>Severity</th><th>OWASP</th><th>Detail</th></tr></thead>"
            "<tbody>" + "".join(rows) + "</tbody></table>" + _clean_html(report))


def run_scan(target, modules, time_based, delay, active_auth=False, oob=None,
             cookie=None, login_url=None, login_data=None,
             headless=False, sqlmap=False, nuclei=False, thorough=False) -> str:
    args = argparse.Namespace(
        target=target, modules=modules or ["all"], authorized=True,
        time_based=time_based, active_auth=active_auth, oob=oob,
        cookie=cookie, header=[], login_url=login_url, login_data=login_data,
        headless=headless, sqlmap=sqlmap, nuclei=nuclei,
        tls_audit=thorough, openapi=thorough, openapi_spec=None, thorough=thorough,
        max_pages=25, max_requests=6000, delay=delay,
        timeout=12.0, port_timeout=2.0, insecure=False, json=None,
    )
    return render_results(rage.run(args))


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, body: str, status: int = 200):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(render_page())
        else:
            self._send("<h1>404</h1>", 404)

    def do_POST(self):
        if self.path != "/scan":
            self._send("<h1>404</h1>", 404)
            return
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
        target = (form.get("target", [""])[0]).strip()
        modules = form.get("m", [])
        time_based = "time_based" in form
        active_auth = "active_auth" in form
        oob = (form.get("oob", [""])[0]).strip() or None
        cookie = (form.get("cookie", [""])[0]).strip() or None
        login_url = (form.get("login_url", [""])[0]).strip() or None
        login_data = (form.get("login_data", [""])[0]).strip() or None
        headless = "headless" in form
        sqlmap = "sqlmap" in form
        nuclei = "nuclei" in form
        thorough = "thorough" in form
        authorized = "authorized" in form
        try:
            delay = max(0.0, float(form.get("delay", ["0.3"])[0]))
        except ValueError:
            delay = 0.3

        def page(results):
            return render_page(target, modules, time_based, str(delay), authorized, results,
                               active_auth, oob or "", cookie or "", login_url or "", login_data or "",
                               headless, sqlmap, nuclei, thorough)

        if not authorized or not target:
            self._send(page("<p class='warn'>Confirm authorization and enter a target.</p>"))
            return
        try:
            results = run_scan(target, modules, time_based, delay, active_auth, oob,
                               cookie, login_url, login_data, headless, sqlmap, nuclei, thorough)
        except Exception as e:
            results = f"<p class='warn'>Scan error: {html.escape(str(e))}</p>"
        self._send(page(results))

    def log_message(self, *args):
        pass


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="rage-web", description="Local web UI for rage scanner.")
    p.add_argument("--host", default="127.0.0.1",
                   help="Bind address (default 127.0.0.1 / localhost-only).")
    p.add_argument("--port", type=int, default=8787, help="Port (default 8787).")
    args = p.parse_args(argv)

    with socketserver.ThreadingTCPServer((args.host, args.port), Handler) as httpd:
        url = f"http://{args.host}:{args.port}"
        print(f"rage web UI running at {url}  (Ctrl+C to stop)")
        if args.host not in ("127.0.0.1", "localhost", "::1"):
            print("WARNING: bound to a non-loopback address — the UI is reachable from your network.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
