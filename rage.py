#!/usr/bin/env python3
"""
rage — a web-security recon agent for AUTHORIZED testing, mapped to OWASP Top 10 (2026).

Scans a single target you are allowed to test (your dev/beta/staging host, a system you
own, or a host explicitly in scope). Detection, not exploitation. Stdlib only (Python 3.9+).

Modules (OWASP tag in brackets):
  headers [A02]      security headers
  misconfig [A02/A10] directory listing, verbose errors
  files [A02]        backup files, API docs, robots/sitemap, GraphQL introspection
  secrets [A02]      API keys / tokens / private keys / sensitive comments in source
  ports [A02]        risky open ports
  tls [A04]          TLS version, legacy-protocol downgrade, cert expiry, cleartext
  ciphers [A04]      weak cipher-suite support
  mixed [A04]        mixed content, sensitive data in URL
  cors [A01]         cross-origin resource sharing misconfiguration
  methods [A01]      risky HTTP methods / TRACE (XST)
  redirect [A01]     open redirect
  ssrf [A01]         SSRF candidate params (+ optional --oob confirmation, cloud metadata)
  traversal [A01]    path traversal / local file inclusion
  sqli [A05]         SQL injection (error / boolean / optional time-based)
  xss [A05]          reflected XSS (params + forms)
  ssti [A05]         server-side template injection
  cmdi [A05]         OS command injection (requires --time-based)
  crlf [A05]         CRLF / response-splitting and Host-header injection
  injerr [A05]       NoSQL / LDAP / XPath / XML injection via backend errors
  csrf [A01]         forms missing an anti-CSRF token
  jwt [A07]          JWT alg=none / weak-algorithm tokens
  auth [A01/A07]     session-token entropy, password-over-HTTP, unauth sensitive paths
  authactive [A07]   login rate-limiting + username enumeration (opt-in, --active-auth)
  fingerprint [A03]  technology fingerprint + subdomain-takeover signatures
  integrity [A03/A08] missing Subresource Integrity, outdated JS libraries

Not remotely testable (reported as manual-review notes): A06 Insecure Design,
A09 Logging/Alerting, IDOR/BOLA and privilege escalation, business logic,
file-upload abuse, password-reset/MFA/session-fixation logic.

USE ONLY ON SYSTEMS YOU OWN OR ARE EXPLICITLY AUTHORIZED TO TEST.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import dataclasses
import datetime
import html.parser
import http.cookiejar
import json
import math
import random
import re
import socket
import ssl
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable

try:
    import rage_tools
except Exception:
    rage_tools = None

__version__ = "0.1.0"

# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

OWASP_2026 = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}


@dataclass
class Finding:
    module: str
    severity: str
    title: str
    detail: str
    location: str = ""
    evidence: str = ""
    owasp: str = ""

    def as_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["owasp_name"] = OWASP_2026.get(self.owasp, "")
        return d


@dataclass
class Report:
    target: str
    started: float = field(default_factory=time.time)
    findings: list[Finding] = field(default_factory=list)
    checks_clean: list[str] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (SEV_ORDER.get(f.severity, 9), f.owasp, f.module))


# --------------------------------------------------------------------------- #
# HTTP client (stdlib)
# --------------------------------------------------------------------------- #


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: str
    url: str
    elapsed: float


class Http:
    def __init__(self, timeout: float = 12.0, delay: float = 0.3,
                 user_agent: str = f"rage/{__version__} (authorized-testing)",
                 verify_tls: bool = True, max_requests: int = 6000,
                 extra_headers: dict[str, str] | None = None):
        self.timeout = timeout
        self.delay = delay
        self.ua = user_agent
        self.count = 0
        self.max_requests = max_requests
        self.extra_headers = dict(extra_headers or {})
        self.jar = http.cookiejar.CookieJar()
        self._ctx = ssl.create_default_context()
        if not verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def login(self, login_url: str, login_data: str) -> int:
        """POST credentials to establish a session. Returns cookie count captured."""
        body = login_data.encode() if isinstance(login_data, str) else login_data
        self.request(login_url, method="POST", data=body,
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        return len(self.jar)

    def request(self, url: str, method: str = "GET", data: bytes | None = None,
                headers: dict[str, str] | None = None,
                allow_redirects: bool = True) -> HttpResponse | None:
        if self.count >= self.max_requests:
            raise RuntimeError(f"request cap reached ({self.max_requests}); aborting to stay polite")
        self.count += 1
        time.sleep(self.delay)
        hdrs = {"User-Agent": self.ua, "Accept": "*/*"}
        hdrs.update(self.extra_headers)
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        handlers = [urllib.request.HTTPSHandler(context=self._ctx),
                    urllib.request.HTTPCookieProcessor(self.jar)]
        if not allow_redirects:
            handlers.append(_NoRedirect())
        opener = urllib.request.build_opener(*handlers)
        start = time.time()
        try:
            resp = opener.open(req, timeout=self.timeout)
            raw = resp.read(2_000_000)
            return HttpResponse(resp.status, {k.lower(): v for k, v in resp.headers.items()},
                                raw.decode("utf-8", errors="replace"), resp.geturl(), time.time() - start)
        except urllib.error.HTTPError as e:
            raw = e.read(2_000_000) if hasattr(e, "read") else b""
            return HttpResponse(e.code, {k.lower(): v for k, v in (e.headers or {}).items()},
                                raw.decode("utf-8", errors="replace"), url, time.time() - start)
        except (urllib.error.URLError, ssl.SSLError, socket.timeout, ConnectionError, OSError):
            return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


# --------------------------------------------------------------------------- #
# HTML parsing: links + forms + scripts
# --------------------------------------------------------------------------- #


@dataclass
class Form:
    action: str
    method: str
    inputs: dict[str, str]
    has_password: bool = False


@dataclass
class Script:
    src: str
    has_integrity: bool


@dataclass
class Page:
    url: str
    body: str
    headers: dict[str, str]


class _PageParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.forms: list[Form] = []
        self.scripts: list[Script] = []
        self._cur: Form | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.append(Script(a["src"], "integrity" in a))
        elif tag == "form":
            self._cur = Form(a.get("action", ""), (a.get("method") or "get").lower(), {})
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            if (a.get("type") or "").lower() == "password":
                self._cur.has_password = True
            if a.get("name"):
                self._cur.inputs[a["name"]] = a.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def parse_html(base_url: str, body: str):
    p = _PageParser()
    try:
        p.feed(body)
    except Exception:
        pass
    links = [urllib.parse.urljoin(base_url, h) for h in p.links]
    for f in p.forms:
        f.action = urllib.parse.urljoin(base_url, f.action) if f.action else base_url
    for s in p.scripts:
        s.src = urllib.parse.urljoin(base_url, s.src)
    return links, p.forms, p.scripts


# --------------------------------------------------------------------------- #
# Crawler (same-host, bounded)
# --------------------------------------------------------------------------- #


def same_host(a: str, b: str) -> bool:
    return urllib.parse.urlparse(a).netloc == urllib.parse.urlparse(b).netloc


def crawl(http: Http, start_url: str, max_pages: int = 25):
    """BFS same-host crawl -> (param_urls, forms, scripts, pages)."""
    seen: set[str] = set()
    queue = [start_url]
    param_urls: list[str] = []
    forms: list[Form] = []
    scripts: list[Script] = []
    pages: list[Page] = []
    n = 0
    while queue and n < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        resp = http.request(url)
        if not resp or "html" not in resp.headers.get("content-type", ""):
            continue
        n += 1
        pages.append(Page(resp.url, resp.body, resp.headers))
        if urllib.parse.urlparse(url).query:
            param_urls.append(url)
        links, pforms, pscripts = parse_html(resp.url, resp.body)
        forms.extend(pforms)
        scripts.extend(pscripts)
        for link in links:
            link, _ = urllib.parse.urldefrag(link)
            if link.startswith(("http://", "https://")) and same_host(link, start_url) and link not in seen:
                queue.append(link)
    uniq: dict[tuple, str] = {}
    for u in param_urls:
        pr = urllib.parse.urlparse(u)
        uniq.setdefault((pr.path, tuple(sorted(urllib.parse.parse_qs(pr.query)))), u)
    seen_src: dict[str, Script] = {}
    for s in scripts:
        seen_src.setdefault(s.src, s)
    return list(uniq.values()), forms, list(seen_src.values()), pages


def _mutate_query(url: str, param: str, value: str) -> str:
    pr = urllib.parse.urlparse(url)
    q = dict(urllib.parse.parse_qsl(pr.query, keep_blank_values=True))
    q[param] = value
    return urllib.parse.urlunparse(pr._replace(query=urllib.parse.urlencode(q)))


def _params_of(url: str) -> list[str]:
    return list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query))


def _rand(n: int = 10) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


# =========================================================================== #
# A02 — headers / misconfiguration / files / secrets / ports
# =========================================================================== #

SECURITY_HEADERS = {
    "strict-transport-security": ("medium", "HSTS missing — connections can be downgraded to HTTP (MITM).", "A04"),
    "content-security-policy": ("medium", "No CSP — reduces defense-in-depth against XSS/injection.", "A02"),
    "x-content-type-options": ("medium", "Missing 'nosniff' — browser may MIME-sniff responses.", "A02"),
    "x-frame-options": ("medium", "Missing — page may be framed (clickjacking). CSP frame-ancestors also OK.", "A02"),
    "referrer-policy": ("medium", "Missing — referrer may leak to third parties.", "A02"),
    "permissions-policy": ("medium", "Missing — browser features not restricted.", "A02"),
}


def module_headers(http: Http, report: Report, base_url: str) -> None:
    resp = http.request(base_url)
    if not resp:
        report.add(Finding("headers", "info", "Target unreachable for header check", "", base_url))
        return
    h = resp.headers
    for name, (sev, msg, owasp) in SECURITY_HEADERS.items():
        if name == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", ""):
            continue
        if name not in h:
            report.add(Finding("headers", sev, f"Missing header: {name}", msg, base_url, owasp=owasp))
    for leaky in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if h.get(leaky):
            report.add(Finding("headers", "low", f"Version disclosure: {leaky}",
                               f"Header reveals stack details: {h[leaky]!r}", base_url, h[leaky], "A02"))
    for cookie in h.get("set-cookie", "").split("\n"):
        if not cookie:
            continue
        low = cookie.lower()
        name = cookie.split("=", 1)[0].strip()
        issues = [a for a in ("Secure", "HttpOnly", "SameSite") if a.lower() not in low]
        if issues:
            report.add(Finding("headers", "medium", f"Weak cookie flags: {name}",
                               "Missing attribute(s): " + ", ".join(issues), base_url, cookie[:120], "A02"))


STACK_SIGS = re.compile(
    r"traceback \(most recent call last\)|java\.lang\.[a-z]|at System\.|werkzeug|stack trace:|"
    r"<b>(warning|fatal error|notice)</b>|ora-\d{5}|syntaxerror|org\.springframework|"
    r"undefined index|on line \d+ in", re.IGNORECASE)


def module_misconfig(http: Http, report: Report, base_url: str, param_urls: list[str]) -> None:
    resp = http.request(base_url)
    if resp and re.search(r"<title>\s*index of /|<h1>\s*index of /", resp.body, re.IGNORECASE):
        report.add(Finding("misconfig", "medium", "Directory listing enabled",
                           "Server returned an auto-generated directory index.", base_url, owasp="A02"))
    for url in param_urls[:5]:
        params = _params_of(url)
        if not params:
            continue
        r = http.request(_mutate_query(url, params[0], "rage'\")(]}%00"))
        if r and STACK_SIGS.search(r.body):
            m = STACK_SIGS.search(r.body)
            report.add(Finding("misconfig", "medium", "Verbose error / stack-trace disclosure",
                               "Malformed input returned internal error details.",
                               f"{url} [param={params[0]}]", r.body[max(0, m.start() - 30):m.end() + 60], "A10"))
            break


DISCOVERY_PATHS = {
    "/robots.txt": ("info", "robots.txt exposed (enumerate disallowed paths)", "A02"),
    "/sitemap.xml": ("info", "sitemap.xml exposed", "A02"),
    "/swagger.json": ("medium", "Swagger/OpenAPI spec exposed", "A02"),
    "/openapi.json": ("medium", "OpenAPI spec exposed", "A02"),
    "/v2/api-docs": ("medium", "Swagger API docs exposed", "A02"),
    "/swagger-ui.html": ("medium", "Swagger UI exposed", "A02"),
    "/.DS_Store": ("medium", "macOS .DS_Store exposed (leaks filenames)", "A02"),
    "/web.config": ("high", "web.config exposed (server config/secrets)", "A02"),
    "/.htaccess": ("medium", ".htaccess exposed", "A02"),
    "/.svn/entries": ("high", "Subversion metadata exposed", "A02"),
    "/crossdomain.xml": ("low", "crossdomain.xml present (review allow-access-from)", "A01"),
    "/backup.zip": ("high", "Backup archive exposed", "A02"),
    "/backup.tar.gz": ("high", "Backup archive exposed", "A02"),
    "/db.sql": ("critical", "Database dump exposed", "A02"),
    "/dump.sql": ("critical", "Database dump exposed", "A02"),
}
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql"]


def module_files(http: Http, report: Report, base_url: str) -> None:
    pr = urllib.parse.urlparse(base_url)
    root = urllib.parse.urlunparse(pr._replace(path="", query="", fragment=""))
    # 404 fingerprint to suppress soft-404s
    soft = http.request(root + "/rage-404-" + _rand(), allow_redirects=False)
    soft_len = len(soft.body) if soft else -1
    for path, (sev, msg, owasp) in DISCOVERY_PATHS.items():
        r = http.request(root + path, allow_redirects=False)
        if r and r.status == 200 and r.body and len(r.body) != soft_len:
            report.add(Finding("files", sev, msg, f"Accessible at {path}", root + path, owasp=owasp))
    for gp in GRAPHQL_PATHS:
        q = json.dumps({"query": "{__schema{queryType{name}}}"}).encode()
        r = http.request(root + gp, method="POST", data=q,
                         headers={"Content-Type": "application/json"})
        if r and "__schema" in r.body and "queryType" in r.body:
            report.add(Finding("files", "medium", "GraphQL introspection enabled",
                               "Schema is queryable via introspection — aids attackers mapping the API.",
                               root + gp, owasp="A02"))
            break


SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "high", "AWS access key ID"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "high", "Google API key"),
    (re.compile(r"ghp_[0-9A-Za-z]{36}"), "high", "GitHub personal access token"),
    (re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "high", "Slack token"),
    (re.compile(r"sk_live_[0-9A-Za-z]{16,}"), "high", "Stripe live secret key"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "critical", "Private key"),
    # NOTE: JWTs are intentionally NOT treated as secrets here — they are commonly
    # public (e.g. short-lived signed media URLs). module_jwt inspects them instead.
]
COMMENT_SECRET = re.compile(r"<!--[^>]*?(password|passwd|secret|api[_-]?key|todo|fixme|backdoor)[^>]*?-->",
                            re.IGNORECASE)


def module_secrets(http: Http, report: Report, pages: list[Page], scripts: list[Script], base_url: str) -> None:
    host = urllib.parse.urlparse(base_url).netloc
    corpus: list[tuple[str, str]] = [(p.url, p.body) for p in pages]
    if not corpus:
        r = http.request(base_url)
        if r:
            corpus.append((base_url, r.body))
    for s in scripts[:15]:
        if urllib.parse.urlparse(s.src).netloc in ("", host):
            r = http.request(s.src)
            if r:
                corpus.append((s.src, r.body))
    for loc, body in corpus:
        for rx, sev, label in SECRET_PATTERNS:
            m = rx.search(body)
            if m:
                report.add(Finding("secrets", sev, f"Exposed secret in source: {label}",
                                   "Credential-like string found in client-delivered content.",
                                   loc, m.group(0)[:20] + "...", "A02"))
        cm = COMMENT_SECRET.search(body)
        if cm:
            report.add(Finding("secrets", "low", "Sensitive HTML comment",
                               "Comment may leak internal info.", loc, cm.group(0)[:120], "A02"))


RISKY_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet (cleartext)", 25: "SMTP", 53: "DNS", 110: "POP3",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}
DB_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017, 2049}


def _check_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def module_ports(report: Report, host: str, ports: Iterable[int], timeout: float = 2.0) -> None:
    ports = list(ports)
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        results = dict(zip(ports, ex.map(lambda p: _check_port(host, p, timeout), ports)))
    for port, is_open in results.items():
        if not is_open:
            continue
        svc = RISKY_PORTS.get(port, "unknown")
        sev = "high" if port in DB_PORTS else ("medium" if port in (23, 3389, 5900, 445) else "low")
        report.add(Finding("ports", sev, f"Open port {port}/tcp ({svc})",
                           "Exposed service reachable from the scanner's network.", f"{host}:{port}", owasp="A02"))


# =========================================================================== #
# A04 — TLS / ciphers / mixed content
# =========================================================================== #


def module_tls(report: Report, base_url: str, timeout: float = 6.0) -> None:
    pr = urllib.parse.urlparse(base_url)
    if pr.scheme != "https":
        report.add(Finding("tls", "high", "No TLS (site served over HTTP)",
                           "Traffic, credentials and session tokens transit in cleartext.", base_url, owasp="A04"))
        return
    host, port = pr.hostname, pr.port or 443
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as ss:
                cert, version = ss.getpeercert(), ss.version()
    except Exception as e:
        report.add(Finding("tls", "info", "TLS handshake failed", str(e), base_url, owasp="A04"))
        return
    if version in ("SSLv3", "TLSv1", "TLSv1.1"):
        report.add(Finding("tls", "high", f"Weak TLS protocol negotiated: {version}",
                           "Deprecated protocol; require TLS 1.2+.", base_url, owasp="A04"))
    na = cert.get("notAfter") if cert else None
    if na:
        try:
            days = (datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z") - datetime.datetime.utcnow()).days
            if days < 0:
                report.add(Finding("tls", "critical", "TLS certificate expired", f"Expired {abs(days)}d ago.", base_url, owasp="A04"))
            elif days < 15:
                report.add(Finding("tls", "high", "TLS certificate expiring very soon", f"Expires in {days}d.", base_url, owasp="A04"))
            elif days < 30:
                report.add(Finding("tls", "medium", "TLS certificate expiring soon", f"Expires in {days}d.", base_url, owasp="A04"))
        except ValueError:
            pass
    for ver, name in ((ssl.TLSVersion.TLSv1_1, "TLS 1.1"), (ssl.TLSVersion.TLSv1, "TLS 1.0")):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ver
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    report.add(Finding("tls", "high", f"Legacy protocol supported: {name}",
                                       "Server accepts a deprecated TLS version (downgrade risk).", base_url, owasp="A04"))
                    break
        except Exception:
            pass


# Genuinely weak/broken cipher tokens. Modern suites must NOT match: TLS 1.3 names
# (TLS_AES_*_GCM_*, TLS_CHACHA20_POLY1305_*) and strong 1.2 AEAD suites
# (ECDHE-*-AES*-GCM-*) contain none of these — only legacy RC4/DES/3DES/MD5/NULL/
# EXPORT/RC2 do. Keeping this as a named, importable helper lets a regression test
# pin the exact behaviour (a TLS 1.3 handshake must never be flagged "weak").
WEAK_CIPHER_RE = re.compile(r"RC4|3DES|DES-CBC|_DES_|MD5|NULL|EXPORT|RC2", re.IGNORECASE)


def _is_weak_cipher(name: str) -> bool:
    return bool(name) and bool(WEAK_CIPHER_RE.search(name))


def module_ciphers(report: Report, base_url: str, timeout: float = 6.0) -> None:
    pr = urllib.parse.urlparse(base_url)
    if pr.scheme != "https":
        return
    host, port = pr.hostname, pr.port or 443
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # set_ciphers() only governs TLS <=1.2; cap the probe there so a modern
        # server cannot silently fall back to a (strong) TLS 1.3 suite and look "weak".
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("RC4:3DES:DES:MD5:aNULL:eNULL:EXPORT")
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                name = ss.cipher()[0]
        # Only report if the negotiated suite is genuinely weak (defense in depth).
        if _is_weak_cipher(name):
            report.add(Finding("ciphers", "high", "Weak cipher suite supported",
                               f"Server negotiated a weak cipher: {name}.", base_url, name, "A04"))
    except Exception:
        pass  # weak ciphers refused — good


# A URL parameter whose NAME looks like it carries a credential/secret. Placing such
# a value in a query string leaks it to logs/history/referrers.
SENSITIVE_URL_PARAM_RE = re.compile(r"pass(word|wd)?|token|secret|api[_-]?key|session", re.IGNORECASE)
# Signed-media/static-asset URLs legitimately carry access tokens in the query
# string (CDN/media signatures), so they must NOT be flagged as "secrets in URL".
# Named + importable so a regression test can pin the exemption.
STATIC_ASSET_RE = re.compile(r"\.(?:png|jpe?g|gif|svg|ico|webp|bmp|css|js|mjs|woff2?|ttf|eot|map)(?:$|\?)",
                             re.IGNORECASE)


def _is_static_asset(url: str) -> bool:
    return bool(STATIC_ASSET_RE.search(url))


def module_mixed(report: Report, pages: list[Page], param_urls: list[str], base_url: str) -> None:
    if urllib.parse.urlparse(base_url).scheme == "https":
        rx = re.compile(r"(?:src|href)\s*=\s*[\"']http://[^\"']+", re.IGNORECASE)
        for p in pages:
            m = rx.search(p.body)
            if m:
                report.add(Finding("mixed", "medium", "Mixed content (HTTP resource on HTTPS page)",
                                   "Insecure sub-resource loaded over HTTP.", p.url, m.group(0)[:120], "A04"))
                break
    for url in param_urls:
        if _is_static_asset(url):
            continue
        for param in _params_of(url):
            if SENSITIVE_URL_PARAM_RE.search(param):
                report.add(Finding("mixed", "medium", "Sensitive data in URL parameter",
                                   f"Parameter {param!r} may place secrets in URLs/logs/history.",
                                   url, owasp="A04"))
                break


# =========================================================================== #
# A01 — CORS / methods / redirect / SSRF / traversal / CSRF
# =========================================================================== #

CORS_ORIGIN = "https://rage-cors-probe.example"


def module_cors(http: Http, report: Report, base_url: str) -> None:
    resp = http.request(base_url, headers={"Origin": CORS_ORIGIN})
    if not resp:
        return
    acao = resp.headers.get("access-control-allow-origin", "")
    acc = (resp.headers.get("access-control-allow-credentials", "") or "").lower() == "true"
    if acao == CORS_ORIGIN and acc:
        report.add(Finding("cors", "high", "CORS reflects arbitrary origin with credentials",
                           "ACAO echoes the request Origin and Allow-Credentials is true.", base_url, acao, "A01"))
    elif acao == CORS_ORIGIN:
        report.add(Finding("cors", "medium", "CORS reflects arbitrary origin",
                           "Server echoes any Origin in ACAO.", base_url, acao, "A01"))
    elif acao == "*" and acc:
        report.add(Finding("cors", "medium", "CORS wildcard with credentials",
                           "Wildcard ACAO with credentials is invalid/unsafe.", base_url, owasp="A01"))


def module_methods(http: Http, report: Report, base_url: str) -> None:
    resp = http.request(base_url, method="OPTIONS")
    allow = (resp.headers.get("allow", "") or resp.headers.get("access-control-allow-methods", "")) if resp else ""
    risky = [m for m in ("PUT", "DELETE", "PATCH", "CONNECT", "TRACE") if m in allow.upper()]
    if risky:
        report.add(Finding("methods", "medium", f"Risky HTTP methods advertised: {', '.join(risky)}",
                           f"OPTIONS Allow: {allow!r}", base_url, owasp="A01"))
    tr = http.request(base_url, method="TRACE")
    if tr and tr.status == 200 and "TRACE" in tr.body.upper()[:200]:
        report.add(Finding("methods", "medium", "HTTP TRACE enabled (XST)",
                           "TRACE echoes the request — aids Cross-Site Tracing.", base_url, owasp="A01"))


REDIRECT_PARAMS = {"url", "redirect", "redirect_url", "redirecturl", "next", "return", "returnurl",
                   "return_url", "dest", "destination", "continue", "goto", "u", "r"}
OPENREDIR_MARKER = "https://rage-openredirect.example/"


def module_redirect(http: Http, report: Report, param_urls: list[str]) -> None:
    for url in param_urls:
        for param in _params_of(url):
            if param.lower() not in REDIRECT_PARAMS:
                continue
            r = http.request(_mutate_query(url, param, OPENREDIR_MARKER), allow_redirects=False)
            if r and r.status in (301, 302, 303, 307, 308) and OPENREDIR_MARKER.rstrip("/") in r.headers.get("location", ""):
                report.add(Finding("redirect", "high", "Open redirect",
                                   f"Parameter {param!r} redirects to an attacker URL.",
                                   f"{url} [param={param}]", "Location: " + r.headers.get("location", ""), "A01"))


# Fetch-oriented params only. Redirect-style names (next/redirect/return/continue/goto)
# are open-redirect candidates, handled by module_redirect — not SSRF.
SSRF_PARAMS = {"url", "uri", "link", "src", "source", "callback", "webhook", "image", "img",
               "fetch", "load", "domain", "host", "site", "feed", "proxy", "file", "document"}
METADATA_URL = "http://169.254.169.254/latest/meta-data/"
METADATA_SIG = re.compile(r"ami-id|instance-id|iam/|hostname\b", re.IGNORECASE)


def module_ssrf(http: Http, report: Report, param_urls: list[str], oob: str | None) -> None:
    for url in param_urls:
        for param in _params_of(url):
            if param.lower() not in SSRF_PARAMS:
                continue
            loc = f"{url} [param={param}]"
            # Cloud metadata reflection (confirms server-side fetch)
            r = http.request(_mutate_query(url, param, METADATA_URL))
            if r and METADATA_SIG.search(r.body):
                report.add(Finding("ssrf", "critical", "SSRF to cloud metadata endpoint",
                                   "Server fetched 169.254.169.254 and reflected instance metadata.", loc, owasp="A01"))
                continue
            if oob:
                http.request(_mutate_query(url, param, oob))
                report.add(Finding("ssrf", "info", "SSRF OOB probe sent",
                                   f"Sent {oob} via {param!r}; check your collaborator for a callback.", loc, owasp="A01"))
            else:
                report.add(Finding("ssrf", "low", "SSRF candidate parameter",
                                   f"Parameter {param!r} takes a URL/host — confirm with an out-of-band probe (--oob).",
                                   loc, owasp="A01"))


TRAVERSAL_PAYLOADS = ["../../../../../../etc/passwd", "....//....//....//....//etc/passwd",
                      "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd",
                      "..\\..\\..\\..\\..\\windows\\win.ini", "C:\\windows\\win.ini"]
TRAVERSAL_SIGS = re.compile(r"root:.*?:0:0:|daemon:x:|\[extensions\]|for 16-bit app support", re.IGNORECASE)


def module_traversal(http: Http, report: Report, param_urls: list[str]) -> None:
    for url in param_urls:
        for param in _params_of(url):
            for payload in TRAVERSAL_PAYLOADS:
                r = http.request(_mutate_query(url, param, payload))
                if r and TRAVERSAL_SIGS.search(r.body):
                    report.add(Finding("traversal", "high", "Path traversal / local file inclusion",
                                       f"Payload {payload!r} returned OS file contents.",
                                       f"{url} [param={param}]", TRAVERSAL_SIGS.search(r.body).group(0)[:60], "A01"))
                    break


CSRF_TOKEN = re.compile(r"csrf|xsrf|_token|authenticity|nonce|__requestverification", re.IGNORECASE)


def module_csrf(report: Report, forms: list[Form]) -> None:
    for form in forms:
        if form.method != "post" or not form.inputs:
            continue
        if not any(CSRF_TOKEN.search(name) for name in form.inputs):
            report.add(Finding("csrf", "medium", "Form without anti-CSRF token",
                               "State-changing POST form has no detectable CSRF token.", form.action, owasp="A01"))


# =========================================================================== #
# A05 — SQLi / XSS / SSTI / cmdi / CRLF / NoSQL-LDAP-XPath
# =========================================================================== #

SQL_ERR_RE = re.compile(
    r"you have an error in your sql syntax|warning: mysql|mysqli?_|unclosed quotation mark|"
    r"quoted string not properly terminated|pg_query\(\)|org\.postgresql\.util\.psqlexception|"
    r"sqlite3?\.operationalerror|ora-\d{5}|microsoft ole db provider for sql server|"
    r"odbc sql server driver|system\.data\.sqlclient\.sqlexception|sqlstate\[", re.IGNORECASE)
SQLI_PROBES = ["'", "\"", "')", "';"]


def _similar(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    la, lb = len(a), len(b)
    return min(la, lb) / max(la, lb) if max(la, lb) else 1.0


def module_sqli(http: Http, report: Report, param_urls: list[str], time_based: bool) -> None:
    for url in param_urls:
        base = http.request(url)
        baseline = base.body if base else ""
        for param in _params_of(url):
            loc = f"{url} [param={param}]"
            hit = False
            for probe in SQLI_PROBES:
                r = http.request(_mutate_query(url, param, probe))
                if r and SQL_ERR_RE.search(r.body):
                    m = SQL_ERR_RE.search(r.body)
                    report.add(Finding("sqli", "high", "SQL error triggered by injection probe",
                                       f"Payload {probe!r} elicited a database error.", loc,
                                       r.body[max(0, m.start() - 40):m.end() + 40], "A05"))
                    hit = True
                    break
            if hit:
                continue
            rt = http.request(_mutate_query(url, param, "1 OR 1=1-- -"))
            rf = http.request(_mutate_query(url, param, "1 AND 1=2-- -"))
            if rt and rf and _similar(rt.body, rf.body) < 0.95 and _similar(rt.body, baseline) > 0.9:
                report.add(Finding("sqli", "high", "Boolean-based SQLi (likely)",
                                   "TRUE vs FALSE conditions differ materially; confirm manually.", loc, owasp="A05"))
                continue
            if time_based:
                r = http.request(_mutate_query(url, param, "1' AND SLEEP(5)-- -"))
                if r and r.elapsed >= 4.5:
                    report.add(Finding("sqli", "high", "Time-based SQLi (likely)",
                                       f"SLEEP(5) delayed response to {r.elapsed:.1f}s.", loc, owasp="A05"))


XSS_MARKER = "xSs9z1Qk"
XSS_PAYLOAD = f"<{XSS_MARKER}>\"'"


def _is_html(r) -> bool:
    """A reflected marker is only XSS if the response is rendered as HTML.
    JSON APIs that echo input (e.g. FastAPI 422 validation errors) are NOT XSS."""
    return bool(r) and "html" in (r.headers.get("content-type", "") or "").lower()


def module_xss(http: Http, report: Report, param_urls: list[str], forms: list[Form]) -> None:
    for url in param_urls:
        for param in _params_of(url):
            r = http.request(_mutate_query(url, param, XSS_PAYLOAD))
            if _is_html(r) and f"<{XSS_MARKER}>" in r.body:
                report.add(Finding("xss", "high", "Reflected XSS (unescaped marker)",
                                   f"Payload reflected unencoded for param {param!r}.",
                                   f"{url} [param={param}]", XSS_PAYLOAD, "A05"))
            elif _is_html(r) and XSS_MARKER in r.body:
                report.add(Finding("xss", "medium", "Input reflected (encoded) — review context",
                                   f"Marker reflected for param {param!r}; brackets encoded.",
                                   f"{url} [param={param}]", owasp="A05"))
    for form in forms:
        if not form.inputs:
            continue
        data = {name: XSS_PAYLOAD for name in form.inputs}
        enc = urllib.parse.urlencode(data).encode()
        if form.method == "post":
            r = http.request(form.action, method="POST", data=enc,
                             headers={"Content-Type": "application/x-www-form-urlencoded"})
        else:
            sep = "&" if urllib.parse.urlparse(form.action).query else "?"
            r = http.request(form.action + sep + urllib.parse.urlencode(data))
        if _is_html(r) and f"<{XSS_MARKER}>" in r.body:
            report.add(Finding("xss", "high", "Reflected XSS via form",
                               "Form input reflected without encoding.", form.action, XSS_PAYLOAD, "A05"))


SSTI_PAYLOAD = "rage{{7*7}}${7*7}#{7*7}"


def module_ssti(http: Http, report: Report, param_urls: list[str]) -> None:
    for url in param_urls:
        for param in _params_of(url):
            r = http.request(_mutate_query(url, param, SSTI_PAYLOAD))
            if r and "rage49" in r.body and "{{7*7}}" not in r.body:
                report.add(Finding("ssti", "high", "Server-Side Template Injection (likely)",
                                   "Template expression evaluated (7*7 -> 49); confirm manually.",
                                   f"{url} [param={param}]", "rage49", "A05"))


CMDI_PAYLOADS = ["; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)", "& ping -n 6 127.0.0.1"]


def module_cmdi(http: Http, report: Report, param_urls: list[str], time_based: bool) -> None:
    if not time_based:
        report.add(Finding("cmdi", "info", "Command-injection check skipped",
                           "Blind command injection needs the time-based probe; re-run with --time-based.", "", owasp="A05"))
        return
    for url in param_urls:
        for param in _params_of(url):
            base = http.request(_mutate_query(url, param, "1"))
            for payload in CMDI_PAYLOADS:
                r = http.request(_mutate_query(url, param, "1" + payload))
                if r and base and r.elapsed >= 4.5 and base.elapsed < 3:
                    report.add(Finding("cmdi", "high", "Command injection (likely)",
                                       f"Payload {payload!r} delayed response to {r.elapsed:.1f}s.",
                                       f"{url} [param={param}]", owasp="A05"))
                    break


def module_crlf(http: Http, report: Report, param_urls: list[str], base_url: str) -> None:
    for url in param_urls:
        for param in _params_of(url):
            r = http.request(_mutate_query(url, param, "rage%0d%0aRage-Injected: rage"))
            if r and "rage-injected" in r.headers:
                report.add(Finding("crlf", "high", "CRLF / HTTP response-header injection",
                                   f"Injected header via param {param!r}.", f"{url} [param={param}]", owasp="A05"))
    evil = "rage-hostinj.example"
    r = http.request(base_url, headers={"X-Forwarded-Host": evil})
    if r and (evil in r.body or evil in r.headers.get("location", "")):
        report.add(Finding("crlf", "medium", "Host-header injection / reflection",
                           "X-Forwarded-Host reflected into response/redirect.", base_url, evil, "A05"))


INJERR_RE = re.compile(
    r"mongoerror|bson|unexpected token|couchdb|"                     # NoSQL
    r"ldap: error code|javax\.naming\.directory|invalid dn syntax|"  # LDAP
    r"xpatexception|xpath|simplexmlelement|"                         # XPath/XML
    r"xmlparseentityref|failed to load external entity", re.IGNORECASE)
INJERR_PROBES = ["'", "\"", "*)(&", "' || '1'=='1", "${7*7}", ")]}"]


def module_injerr(http: Http, report: Report, param_urls: list[str]) -> None:
    for url in param_urls:
        for param in _params_of(url):
            for probe in INJERR_PROBES:
                r = http.request(_mutate_query(url, param, probe))
                if r and INJERR_RE.search(r.body):
                    m = INJERR_RE.search(r.body)
                    report.add(Finding("injerr", "medium", "Backend error (NoSQL/LDAP/XPath/XML injection)",
                                       f"Payload {probe!r} elicited a backend parser error.",
                                       f"{url} [param={param}]", m.group(0)[:60], "A05"))
                    break


# =========================================================================== #
# A07 — JWT / auth / active auth
# =========================================================================== #

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")


def module_jwt(http: Http, report: Report, pages: list[Page], base_url: str) -> None:
    corpus = [(p.url, p.body) for p in pages] or []
    base = http.request(base_url)
    if base:
        corpus.append((base_url, base.body))
        corpus.append((base_url, base.headers.get("set-cookie", "")))
    seen = set()
    hs_algs: set[str] = set()
    hs_count = 0
    hs_loc = ""
    for loc, text in corpus:
        for tok in JWT_RE.findall(text):
            if tok in seen:
                continue
            seen.add(tok)
            try:
                seg = tok.split(".")[0]
                hdr = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
            except Exception:
                continue
            alg = str(hdr.get("alg", "")).lower()
            if alg == "none":
                report.add(Finding("jwt", "high", "JWT with alg=none",
                                   "Token header allows unsigned tokens — forgeable.", loc, tok[:25] + "...", "A07"))
            elif alg.startswith("hs"):
                hs_count += 1
                hs_algs.add(alg)
                hs_loc = hs_loc or loc
    # One aggregated note rather than one per token (media/signed URLs produce many).
    if hs_count:
        report.add(Finding("jwt", "low", "JWT(s) use a symmetric algorithm (HS*)",
                           f"{hs_count} token(s) use {'/'.join(sorted(hs_algs))} — informational; "
                           "ensure the signing secret is long and random.", hs_loc, owasp="A07"))


# Paths worth probing unauthenticated. Each entry is (path, severity, signature).
# A bare "HTTP 200 with a body" is NOT evidence of a vulnerability: many of these
# paths legitimately return a login page, an SPA shell, or (for public well-known
# URIs like security.txt) exactly the content they are meant to serve. So for
# data-exposure paths we require the body to match a content signature before
# reporting; paths with no reliable signature (admin consoles) are reported low
# and left for manual verification. Anything under /.well-known/ is intentionally
# public (RFC 8615) and is never flagged here.
SENSITIVE_PATHS: list[tuple[str, str, "re.Pattern[str] | None"]] = [
    ("/.env",          "critical", re.compile(r"(?m)^\s*[A-Z0-9_]{2,}\s*=")),
    ("/.git/config",   "critical", re.compile(r"\[core\]|repositoryformatversion|\[remote ")),
    ("/actuator",      "high",     re.compile(r'"_links"\s*:')),
    ("/actuator/env",  "critical", re.compile(r'"(activeProfiles|propertySources)"')),
    ("/phpinfo.php",   "high",     re.compile(r"phpinfo\(\)|PHP Version")),
    ("/server-status", "high",     re.compile(r"Apache (Server )?Status|Server uptime")),
    ("/config.json",   "high",     re.compile(r'"(password|secret|api[_-]?key|token|client[_-]?secret)"', re.I)),
    ("/api/users",     "high",     re.compile(r'"(email|username|password|users)"', re.I)),
    ("/admin",         "low",      None),
    ("/admin/",        "low",      None),
    ("/dashboard",     "low",      None),
    ("/debug",         "low",      None),
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def module_auth(http: Http, report: Report, base_url: str, forms: list[Form]) -> None:
    pr = urllib.parse.urlparse(base_url)
    resp = http.request(base_url)
    if resp:
        for cookie in resp.headers.get("set-cookie", "").split("\n"):
            if "=" not in cookie:
                continue
            name, val = cookie.split("=", 1)
            val = val.split(";", 1)[0]
            if re.search(r"sess|sid|token|auth", name, re.IGNORECASE) and len(val) >= 8:
                e = _entropy(val)
                if e < 3.0 or len(val) < 16:
                    report.add(Finding("auth", "medium", f"Low-entropy session token: {name.strip()}",
                                       f"Length {len(val)}, entropy {e:.1f} bits/char — may be guessable.", base_url, owasp="A07"))
    for form in forms:
        if form.has_password and urllib.parse.urlparse(form.action).scheme == "http":
            report.add(Finding("auth", "high", "Password form posts over HTTP",
                               "Credentials would be sent in cleartext.", form.action, owasp="A07"))
    for path, severity, signature in SENSITIVE_PATHS:
        if "/.well-known/" in path:  # intentionally public (RFC 8615); never a finding
            continue
        tgt = urllib.parse.urlunparse(pr._replace(path=path, query="", fragment=""))
        r = http.request(tgt, allow_redirects=False)
        if not (r and r.status == 200 and r.body):
            continue
        if signature is not None:
            m = signature.search(r.body)
            if not m:
                continue  # 200, but the body is not actually sensitive content
            report.add(Finding("auth", severity,
                               f"Sensitive path exposed without auth: {path}",
                               "HTTP 200 returned a body matching a sensitive-data signature.",
                               tgt, evidence=m.group(0)[:80], owasp="A01"))
        else:
            # No reliable content signature (e.g. an admin console). A 200 only
            # proves the path is reachable, not that access control failed — such
            # paths commonly return a login page or SPA shell. Report low and let
            # the operator verify.
            report.add(Finding("auth", severity,
                               f"Admin/management path reachable without auth: {path}",
                               "HTTP 200 (reachable). Verify manually: often returns a login "
                               "page or SPA shell rather than privileged content.", tgt, owasp="A01"))


def module_authactive(http: Http, report: Report, forms: list[Form], active_auth: bool) -> None:
    login = next((f for f in forms if f.has_password), None)
    if not active_auth:
        report.add(Finding("authactive", "info", "Active auth checks skipped",
                           "Rate-limit/enumeration tests are opt-in; re-run with --active-auth "
                           "(uses random usernames, may generate login noise).", "", owasp="A07"))
        return
    if not login:
        report.add(Finding("authactive", "info", "No login form found for active auth checks", "", owasp="A07"))
        return
    userfield = next((n for n in login.inputs if re.search(r"user|email|login|name", n, re.IGNORECASE)), None)
    passfield = next((n for n in login.inputs if "pass" in n.lower()), None)
    if not userfield or not passfield:
        return
    throttled = False
    for _ in range(6):
        data = dict(login.inputs)
        data[userfield] = "rage_" + _rand()
        data[passfield] = _rand(12)
        r = http.request(login.action, method="POST", data=urllib.parse.urlencode(data).encode(),
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
        if r and (r.status == 429 or re.search(r"too many|rate limit|locked|captcha", r.body, re.IGNORECASE)):
            throttled = True
            break
    if not throttled:
        report.add(Finding("authactive", "low", "No login throttling observed (heuristic)",
                           "6 random-username POSTs saw no 429/lockout. Unreliable against multi-step or "
                           "SPA/flow-API logins, where these POSTs may not be real auth attempts — confirm manually.",
                           login.action, owasp="A07"))
    # Username enumeration (heuristic): common vs random
    a = dict(login.inputs); a[userfield] = "admin"; a[passfield] = _rand(12)
    b = dict(login.inputs); b[userfield] = "rage_" + _rand(); b[passfield] = _rand(12)
    ra = http.request(login.action, method="POST", data=urllib.parse.urlencode(a).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
    rb = http.request(login.action, method="POST", data=urllib.parse.urlencode(b).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
    if ra and rb and (ra.status != rb.status or _similar(ra.body, rb.body) < 0.9):
        report.add(Finding("authactive", "low", "Possible username enumeration",
                           "Login responses differ for a common vs random username; confirm manually.",
                           login.action, owasp="A07"))


# =========================================================================== #
# A03 / A08 — fingerprint / integrity
# =========================================================================== #

TAKEOVER_SIGS = re.compile(
    r"there isn't a github pages site here|nosuchbucket|no such app|herokucdn|"
    r"the specified bucket does not exist|fastly error: unknown domain|"
    r"do not have access to the domain", re.IGNORECASE)
TECH_COOKIES = {"phpsessid": "PHP", "jsessionid": "Java/JSP", "asp.net_sessionid": "ASP.NET",
                "laravel_session": "Laravel", "ci_session": "CodeIgniter", "_rails": "Rails"}


def module_fingerprint(http: Http, report: Report, base_url: str, pages: list[Page]) -> None:
    resp = http.request(base_url)
    if not resp:
        return
    tech = set()
    sv = resp.headers.get("server", "")
    xp = resp.headers.get("x-powered-by", "")
    if sv:
        tech.add(sv)
    if xp:
        tech.add(xp)
    for ck, label in TECH_COOKIES.items():
        if ck in resp.headers.get("set-cookie", "").lower():
            tech.add(label)
    body = resp.body
    mg = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.IGNORECASE)
    if mg:
        tech.add(mg.group(1))
    if "/wp-content/" in body or "/wp-includes/" in body:
        tech.add("WordPress")
    if tech:
        report.add(Finding("fingerprint", "info", "Technology fingerprint",
                           "Detected: " + ", ".join(sorted(tech)), base_url, owasp="A03"))
    if re.search(r"php/[1-5]\.|apache/1\.|apache/2\.0|nginx/0\.|openssl/0\.", sv + xp, re.IGNORECASE):
        report.add(Finding("fingerprint", "medium", "End-of-life / outdated server software",
                           f"Version string suggests EOL software: {sv or xp!r}.", base_url, owasp="A03"))
    for p in ([Page(base_url, body, resp.headers)] + pages):
        if TAKEOVER_SIGS.search(p.body):
            report.add(Finding("fingerprint", "high", "Possible subdomain takeover",
                               "Page shows an unclaimed-service fingerprint (dangling DNS).",
                               p.url, TAKEOVER_SIGS.search(p.body).group(0)[:60], "A03"))
            break


VULN_LIBS = [
    (re.compile(r"jquery[-.]?(\d+)\.(\d+)\.(\d+)", re.IGNORECASE), (3, 5, 0), "jQuery < 3.5.0 (XSS CVEs)"),
    (re.compile(r"angular[-.]?(\d+)\.(\d+)\.(\d+)", re.IGNORECASE), (1, 8, 0), "AngularJS < 1.8 (EOL)"),
    (re.compile(r"bootstrap[-.]?(\d+)\.(\d+)\.(\d+)", re.IGNORECASE), (4, 3, 1), "Bootstrap < 4.3.1 (XSS CVEs)"),
]


def module_integrity(report: Report, scripts: list[Script], base_url: str) -> None:
    host = urllib.parse.urlparse(base_url).netloc
    external: set[str] = set()
    for s in scripts:
        sh = urllib.parse.urlparse(s.src).netloc
        if sh and sh != host:
            external.add(sh)
            if not s.has_integrity:
                report.add(Finding("integrity", "medium", "External script without Subresource Integrity",
                                   "Third-party script loaded without an integrity hash.", s.src, owasp="A08"))
        for rx, minv, label in VULN_LIBS:
            m = rx.search(s.src)
            if m and tuple(int(x) for x in m.groups()) < minv:
                report.add(Finding("integrity", "medium", f"Outdated JS library: {label}",
                                   f"Detected {'.'.join(m.groups())}.", s.src, owasp="A03"))
    if external:
        report.add(Finding("integrity", "info", "Third-party script sources (supply-chain surface)",
                           "Review/pin these origins: " + ", ".join(sorted(external)), base_url, owasp="A03"))


# =========================================================================== #
# Manual-review coverage notes
# =========================================================================== #

MANUAL_NOTES = [
    ("A01", "IDOR/BOLA, privilege escalation and function-level authz need authenticated multi-account testing."),
    ("A03", "Deep supply-chain/SBOM and build-pipeline review needs repo/CI access — run SCA and verify provenance."),
    ("A05", "File-upload abuse and stored/second-order injection need authenticated testing of upload & persistence."),
    ("A06", "Insecure design needs threat modeling and architecture review — not detectable by black-box scanning."),
    ("A07", "Password-reset, MFA and session-fixation logic need authenticated/manual testing."),
    ("A08", "CI/CD artifact signing and update integrity need pipeline access to verify."),
    ("A09", "Logging and alerting coverage can only be assessed with backend/SIEM access."),
    ("A06", "Business-logic flaws (race conditions, price/coupon/workflow abuse) require manual testing."),
]


def module_manual_notes(report: Report) -> None:
    for owasp, note in MANUAL_NOTES:
        report.add(Finding("coverage", "info", f"{owasp} requires manual review", note, owasp=owasp))


# =========================================================================== #
# Optional external-tool modules (via rage_tools)
# =========================================================================== #

def _nuclei_sev(s: str) -> str:
    return s if s in ("critical", "high", "medium", "low", "info") else "info"


def module_nuclei(report: Report, base_url: str) -> None:
    if not rage_tools or not rage_tools.tool_path("nuclei"):
        report.add(Finding("nuclei", "info", "nuclei not installed",
                           "Install nuclei (projectdiscovery.io/nuclei) on PATH and re-run with --nuclei.", base_url))
        return
    for item in rage_tools.run_nuclei(base_url):
        report.add(Finding("nuclei", _nuclei_sev(item["severity"]), item["name"],
                           f"nuclei template: {item['template']}", item["matched"]))


def module_sqlmap(report: Report, param_urls: list[str], cookie: str | None) -> None:
    if not rage_tools or not rage_tools.tool_path("sqlmap"):
        report.add(Finding("sqlmap", "info", "sqlmap not installed",
                           "Install sqlmap (sqlmap.org) on PATH and re-run with --sqlmap.", "", owasp="A05"))
        return
    if not param_urls:
        report.add(Finding("sqlmap", "info", "sqlmap: no parameterized URLs to test", "", owasp="A05"))
        return
    for v in rage_tools.run_sqlmap(param_urls[:5], cookie=cookie):
        report.add(Finding("sqlmap", "high", "SQL injection confirmed by sqlmap",
                           v["detail"], v["url"], owasp="A05"))


def module_tlsaudit(report: Report, base_url: str) -> None:
    engine = rage_tools.tls_audit_available() if rage_tools else None
    if not engine:
        report.add(Finding("tlsaudit", "info", "TLS-audit engine not installed",
                           "Install sslyze (pip install sslyze) or testssl.sh for trustworthy "
                           "cipher/protocol testing (the built-in 'ciphers' check is limited by "
                           "the scanner's own OpenSSL).", base_url, owasp="A04"))
        return
    pr = urllib.parse.urlparse(base_url)
    if pr.scheme != "https":
        report.add(Finding("tlsaudit", "info", "TLS audit skipped (target is not HTTPS)", "", base_url, owasp="A04"))
        return
    for f in rage_tools.run_tls_audit(pr.hostname, pr.port or 443):
        report.add(Finding("tlsaudit", f["severity"], f["title"], f["detail"],
                           base_url, f.get("evidence", ""), "A04"))


# =========================================================================== #
# A05 — OpenAPI/Swagger-driven API endpoint fuzzing
# =========================================================================== #
#
# Crawling only sees HTML links/forms, so API-first apps (FastAPI, etc.) look
# "clean" because nothing got tested. If the app publishes an OpenAPI/Swagger
# spec, this module reads it, enumerates the documented endpoints + parameters,
# and runs injection probes against them. NOTE: for write methods (POST/PUT/
# PATCH) this sends real requests that can create/modify data — intended for
# authorized/idle test environments. DELETE is never exercised.

OPENAPI_PATHS = ["/openapi.json", "/api/openapi.json", "/v3/api-docs", "/swagger.json",
                 "/swagger/v1/swagger.json", "/api-docs", "/openapi"]
_OAPI_SAMPLE = "1"
_OAPI_ERR = "rage'\")(]};--"
_OAPI_TRAVERSAL = "../../../../../../etc/passwd"


def _oapi_snip(body: str, rx) -> str:
    m = rx.search(body)
    return body[max(0, m.start() - 30):m.end() + 40] if m else ""


def _oapi_resolve_ref(spec: dict, node, _depth: int = 0):
    while isinstance(node, dict) and "$ref" in node and _depth < 10:
        ref = node["$ref"]
        _depth += 1
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return {}
        cur = spec
        for part in ref[2:].split("/"):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return {}
        node = cur
    return node if isinstance(node, dict) else {}


def _oapi_string_fields(spec: dict, schema, _depth: int = 0) -> list[str]:
    schema = _oapi_resolve_ref(spec, schema or {})
    if _depth > 4 or not isinstance(schema, dict):
        return []
    props = schema.get("properties") or {}
    out = []
    for name, sub in props.items():
        sub = _oapi_resolve_ref(spec, sub)
        if sub.get("type") in (None, "string"):
            out.append(name)
    return out


def _oapi_load(http: Http, base_url: str, spec_url: str | None):
    candidates = [spec_url] if spec_url else [urllib.parse.urljoin(base_url, p) for p in OPENAPI_PATHS]
    for u in candidates:
        if not u:
            continue
        r = http.request(u)
        if r and r.status == 200 and r.body.lstrip().startswith("{"):
            try:
                data = json.loads(r.body)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and ("openapi" in data or "swagger" in data) and data.get("paths"):
                return data, u
    return None, None


def _oapi_base(spec: dict, base_url: str) -> str:
    pr = urllib.parse.urlparse(base_url)
    root = f"{pr.scheme}://{pr.netloc}"
    servers = spec.get("servers") or []
    if isinstance(servers, list) and servers:
        su = (servers[0] or {}).get("url", "")
        if su.startswith("http"):
            return su.rstrip("/")
        if su.startswith("/"):
            return root + su.rstrip("/")
    if spec.get("basePath"):
        return root + str(spec["basePath"]).rstrip("/")
    return root


def _oapi_endpoints(spec: dict, base_url: str, cap: int = 80) -> list[dict]:
    base = _oapi_base(spec, base_url)
    out: list[dict] = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch") or not isinstance(op, dict):
                continue
            concrete = re.sub(r"\{[^}]+\}", _OAPI_SAMPLE, path)
            url = base + (concrete if concrete.startswith("/") else "/" + concrete)
            query = [_oapi_resolve_ref(spec, p).get("name") for p in (op.get("parameters") or [])
                     if _oapi_resolve_ref(spec, p).get("in") == "query" and _oapi_resolve_ref(spec, p).get("name")]
            rb = _oapi_resolve_ref(spec, op.get("requestBody") or {})
            schema = ((rb.get("content") or {}).get("application/json") or {}).get("schema")
            body = _oapi_string_fields(spec, schema) if schema else []
            out.append({"method": method.upper(), "url": url, "path": path, "query": query, "body": body})
            if len(out) >= cap:
                return out
    return out


def _oapi_request(http: Http, e: dict, params: dict | None = None, body: dict | None = None):
    url = e["url"]
    if params:
        sep = "&" if urllib.parse.urlparse(url).query else "?"
        url = url + sep + urllib.parse.urlencode(params)
    data = headers = None
    if body is not None:
        data = json.dumps(body).encode()
        headers = {"Content-Type": "application/json"}
    return http.request(url, method=e["method"], data=data, headers=headers, allow_redirects=False)


def _oapi_probe(http: Http, report: Report, e: dict, where: str, loc: str,
                mk, time_based: bool) -> None:
    """mk(payload) -> (params, body) builder for either a query param or a body field."""
    r = _oapi_request(http, e, *mk(_OAPI_ERR))
    if r and SQL_ERR_RE.search(r.body):
        report.add(Finding("openapi", "high", f"SQL error via API {where}",
                           "Injection probe elicited a database error.", loc, _oapi_snip(r.body, SQL_ERR_RE), "A05"))
        return
    if r and INJERR_RE.search(r.body):
        report.add(Finding("openapi", "medium", f"Backend parser error via API {where}",
                           "NoSQL/LDAP/XPath/XML error elicited.", loc, _oapi_snip(r.body, INJERR_RE), "A05"))
    r = _oapi_request(http, e, *mk(XSS_PAYLOAD))
    if f"<{XSS_MARKER}>" in (r.body if r else "") and _is_html(r):
        report.add(Finding("openapi", "high", f"Reflected XSS via API {where}",
                           "Payload reflected unencoded (confirm rendering sink).", loc, XSS_PAYLOAD, "A05"))
    r = _oapi_request(http, e, *mk(SSTI_PAYLOAD))
    if r and "rage49" in r.body and "{{7*7}}" not in r.body:
        report.add(Finding("openapi", "high", f"Server-Side Template Injection via API {where}",
                           "Template expression evaluated (7*7 -> 49).", loc, "rage49", "A05"))
    r = _oapi_request(http, e, *mk(_OAPI_TRAVERSAL))
    if r and TRAVERSAL_SIGS.search(r.body):
        report.add(Finding("openapi", "high", f"Path traversal via API {where}",
                           "OS file contents returned.", loc, _oapi_snip(r.body, TRAVERSAL_SIGS), "A05"))
    if time_based:
        r = _oapi_request(http, e, *mk("1' AND SLEEP(5)-- -"))
        if r and r.elapsed >= 4.5:
            report.add(Finding("openapi", "high", f"Time-based SQLi via API {where} (likely)",
                               f"Injected SLEEP(5) delayed response to {r.elapsed:.1f}s.", loc, owasp="A05"))


def module_openapi(http: Http, report: Report, base_url: str,
                   time_based: bool = False, spec_url: str | None = None) -> None:
    spec, url = _oapi_load(http, base_url, spec_url)
    if not spec:
        report.add(Finding("openapi", "info", "No OpenAPI/Swagger spec found",
                           "Tried common spec paths; nothing parseable. Point rage at it with --openapi-spec.",
                           base_url, owasp="A05"))
        return
    eps = _oapi_endpoints(spec, base_url)
    nq = sum(1 for e in eps if e["query"])
    nb = sum(1 for e in eps if e["body"])
    report.add(Finding("openapi", "info", "OpenAPI spec parsed — testing documented endpoints",
                       f"{len(eps)} endpoint(s) from {url} ({nq} with query params, {nb} with a JSON body). "
                       "Write methods (POST/PUT/PATCH) were exercised; DELETE was skipped.", url, owasp="A05"))
    for e in eps:
        for param in e["query"]:
            _oapi_probe(http, report, e, "query param",
                        f"{e['method']} {e['path']} [query={param}]",
                        lambda payload, _p=param: ({_p: payload}, None), time_based)
        if e["body"]:
            for fieldname in e["body"]:
                def _mk(payload, _f=fieldname, _e=e):
                    b = {bf: "rage1" for bf in _e["body"]}
                    b[_f] = payload
                    return (None, b)
                _oapi_probe(http, report, e, "JSON body field",
                            f"{e['method']} {e['path']} [body={fieldname}]", _mk, time_based)


# =========================================================================== #
# Orchestration + CLI
# =========================================================================== #

ALL_MODULES = ["headers", "misconfig", "files", "secrets", "ports", "tls", "ciphers", "mixed",
               "cors", "methods", "redirect", "ssrf", "traversal", "sqli", "xss", "ssti", "cmdi",
               "crlf", "injerr", "csrf", "jwt", "auth", "authactive", "fingerprint", "integrity",
               "sqlmap", "nuclei", "tlsaudit", "openapi"]
# "all" runs the built-in checks; sqlmap/nuclei/tlsaudit/openapi are opt-in (heavy/active) via -m or flags.
DEFAULT_ALL = [m for m in ALL_MODULES if m not in ("sqlmap", "nuclei", "tlsaudit", "openapi")]
CRAWL_MODULES = {"misconfig", "secrets", "mixed", "redirect", "ssrf", "traversal", "sqli", "xss",
                 "ssti", "cmdi", "crlf", "injerr", "csrf", "jwt", "auth", "authactive",
                 "fingerprint", "integrity", "sqlmap"}

CLEAN_DESCRIPTIONS = {
    "headers": "headers: all checked security headers are present",
    "misconfig": "misconfig: no directory listing or verbose errors detected",
    "files": "files: no exposed backup/API-doc/VCS files at the paths tested",
    "secrets": "secrets: no credential patterns found in delivered source",
    "ports": "ports: none of the risky ports tested were open",
    "tls": "tls: no TLS/certificate problems detected",
    "ciphers": "ciphers: no weak cipher suite was accepted",
    "mixed": "mixed: no mixed content or secrets-in-URL detected",
    "cors": "cors: no permissive CORS reflection detected",
    "methods": "methods: no risky HTTP methods/TRACE enabled",
    "redirect": "redirect: no open redirect in tested parameters",
    "ssrf": "ssrf: no SSRF confirmed (URL-taking params may still warrant OOB testing)",
    "traversal": "traversal: no path traversal/LFI in tested parameters",
    "sqli": "sqli: no SQL injection detected in tested parameters",
    "xss": "xss: no reflected XSS detected in tested params/forms",
    "ssti": "ssti: no template injection detected in tested parameters",
    "cmdi": "cmdi: no command injection detected in tested parameters",
    "crlf": "crlf: no CRLF/host-header injection detected",
    "injerr": "injerr: no NoSQL/LDAP/XPath/XML backend errors elicited",
    "csrf": "csrf: every POST form carried an anti-CSRF token",
    "jwt": "jwt: no weak/none-alg JWTs observed",
    "auth": "auth: no session/password/exposed-path issues detected",
    "authactive": "authactive: no login rate-limit/enumeration issue detected",
    "fingerprint": "fingerprint: no takeover/EOL-software signatures detected",
    "integrity": "integrity: external scripts use SRI; no outdated libs flagged",
    "sqlmap": "sqlmap: no SQL injection confirmed on tested URLs",
    "nuclei": "nuclei: no template matches",
    "tlsaudit": "tlsaudit: no weak protocols/ciphers found by the TLS engine",
    "openapi": "openapi: no injection found in documented API endpoints (or no spec exposed)",
}


def _select_modules(args: argparse.Namespace) -> tuple[list[str], bool, list[Finding]]:
    """Resolve the active module list from the requested modules plus convenience
    flags. Pure (no I/O) so it can be unit-tested.

    Returns (modules, headless, notes):
      - --thorough turns on every available engine at once (headless crawl +
        sqlmap + nuclei + TLS audit + OpenAPI fuzzing): "lean on the engines" as
        a single switch.
      - When the authoritative TLS engine (--tls-audit / tlsaudit) is active it
        SUPERSEDES rage's limited built-in 'ciphers' heuristic, which is capped by
        the scanner's own OpenSSL. The heuristic is dropped and an info note says so.
    """
    thorough = getattr(args, "thorough", False)
    modules = list(DEFAULT_ALL if "all" in args.modules else args.modules)
    for attr, mod in (("sqlmap", "sqlmap"), ("nuclei", "nuclei"),
                      ("tls_audit", "tlsaudit"), ("openapi", "openapi")):
        if (getattr(args, attr, False) or thorough) and mod not in modules:
            modules.append(mod)
    headless = getattr(args, "headless", False) or thorough
    notes: list[Finding] = []
    if "tlsaudit" in modules and "ciphers" in modules:
        modules.remove("ciphers")
        notes.append(Finding("ciphers", "info",
                             "Built-in cipher check skipped (TLS-audit engine active)",
                             "The external TLS engine supersedes rage's limited built-in cipher "
                             "probe (capped by the scanner's own OpenSSL); trust the 'tlsaudit' "
                             "findings for protocol/cipher issues.", "", owasp="A04"))
    return modules, headless, notes


def run(args: argparse.Namespace) -> Report:
    base_url = args.target
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    host = urllib.parse.urlparse(base_url).hostname
    report = Report(target=base_url)
    extra_headers: dict[str, str] = {}
    for hv in getattr(args, "header", None) or []:
        if ":" in hv:
            k, v = hv.split(":", 1)
            extra_headers[k.strip()] = v.strip()
    if getattr(args, "cookie", None):
        extra_headers["Cookie"] = args.cookie
    http = Http(timeout=args.timeout, delay=args.delay, verify_tls=not args.insecure,
                max_requests=args.max_requests, extra_headers=extra_headers)
    login_url = getattr(args, "login_url", None)
    if login_url:
        n = http.login(login_url, getattr(args, "login_data", "") or "")
        if n:
            report.add(Finding("auth", "info", "Authenticated session established",
                               f"Login POST set {n} cookie(s); scanning as an authenticated user.",
                               login_url, owasp="A07"))
        else:
            report.add(Finding("auth", "info", "Login produced no session cookie",
                               "Check your --login-data field names; scan may be unauthenticated.",
                               login_url, owasp="A07"))
    elif extra_headers.get("Cookie") or any(k.lower() == "authorization" for k in extra_headers):
        report.add(Finding("auth", "info", "Authenticated session (supplied credentials)",
                           "Scanning with the cookie/authorization header you provided.", base_url, owasp="A07"))
    modules, headless, _sel_notes = _select_modules(args)
    for _note in _sel_notes:
        report.add(_note)
    oob = getattr(args, "oob", None)
    active_auth = getattr(args, "active_auth", False)

    param_urls: list[str] = []
    forms: list[Form] = []
    scripts: list[Script] = []
    pages: list[Page] = []
    if CRAWL_MODULES & set(modules):
        if headless and rage_tools and rage_tools.headless_available():
            print(f"[*] Headless crawl (Chromium) {base_url}...", file=sys.stderr)
            try:
                param_urls, forms, scripts, pages = rage_tools.crawl_headless(
                    base_url, max_pages=args.max_pages, extra_headers=http.extra_headers)
            except Exception as e:
                print(f"[!] headless crawl failed ({e}); falling back to stdlib crawl.", file=sys.stderr)
        elif headless:
            report.add(Finding("headless", "info", "Headless crawler unavailable",
                               "Playwright not installed. Run: pip install playwright && playwright install chromium.",
                               base_url))
        if not pages:
            print(f"[*] Crawling {base_url} (max {args.max_pages} pages)...", file=sys.stderr)
            param_urls, forms, scripts, pages = crawl(http, base_url, max_pages=args.max_pages)
        print(f"[*] {len(param_urls)} param URLs, {len(forms)} forms, {len(scripts)} scripts, "
              f"{len(pages)} pages.", file=sys.stderr)

    steps = [
        ("headers", lambda: module_headers(http, report, base_url)),
        ("misconfig", lambda: module_misconfig(http, report, base_url, param_urls)),
        ("files", lambda: module_files(http, report, base_url)),
        ("secrets", lambda: module_secrets(http, report, pages, scripts, base_url)),
        ("ports", lambda: module_ports(report, host, RISKY_PORTS.keys(), timeout=args.port_timeout)),
        ("tls", lambda: module_tls(report, base_url)),
        ("ciphers", lambda: module_ciphers(report, base_url)),
        ("mixed", lambda: module_mixed(report, pages, param_urls, base_url)),
        ("cors", lambda: module_cors(http, report, base_url)),
        ("methods", lambda: module_methods(http, report, base_url)),
        ("redirect", lambda: module_redirect(http, report, param_urls)),
        ("ssrf", lambda: module_ssrf(http, report, param_urls, oob)),
        ("traversal", lambda: module_traversal(http, report, param_urls)),
        ("sqli", lambda: module_sqli(http, report, param_urls, args.time_based)),
        ("xss", lambda: module_xss(http, report, param_urls, forms)),
        ("ssti", lambda: module_ssti(http, report, param_urls)),
        ("cmdi", lambda: module_cmdi(http, report, param_urls, args.time_based)),
        ("crlf", lambda: module_crlf(http, report, param_urls, base_url)),
        ("injerr", lambda: module_injerr(http, report, param_urls)),
        ("csrf", lambda: module_csrf(report, forms)),
        ("jwt", lambda: module_jwt(http, report, pages, base_url)),
        ("auth", lambda: module_auth(http, report, base_url, forms)),
        ("authactive", lambda: module_authactive(http, report, forms, active_auth)),
        ("fingerprint", lambda: module_fingerprint(http, report, base_url, pages)),
        ("integrity", lambda: module_integrity(report, scripts, base_url)),
        ("sqlmap", lambda: module_sqlmap(report, param_urls, getattr(args, "cookie", None))),
        ("nuclei", lambda: module_nuclei(report, base_url)),
        ("tlsaudit", lambda: module_tlsaudit(report, base_url)),
        ("openapi", lambda: module_openapi(http, report, base_url, args.time_based,
                                           getattr(args, "openapi_spec", None))),
    ]
    real = {"critical", "high", "medium", "low"}
    for name, fn in steps:
        if name not in modules:
            continue
        print(f"[*] {name}...", file=sys.stderr)
        before = len(report.findings)
        try:
            fn()
        except Exception as e:
            report.add(Finding(name, "info", f"{name} module error", str(e)))
            continue
        if not any(f.severity in real for f in report.findings[before:]):
            report.checks_clean.append(name)

    module_manual_notes(report)
    print(f"[*] Done. {http.count} HTTP requests sent.", file=sys.stderr)
    return report


def print_text_report(report: Report) -> None:
    findings = report.sorted()
    print("\n" + "=" * 72)
    print(f" rage report — {report.target}")
    print("=" * 72)
    counts = Counter(f.severity for f in findings)
    if findings:
        print(f" {len(findings)} finding(s)   " + "  ".join(f"{s}:{counts[s]}" for s in SEV_ORDER if counts.get(s)) + "\n")
        for f in findings:
            tag = f"{f.owasp} " if f.owasp else ""
            print(f" [{f.severity.upper():8}] {tag}({f.module}) {f.title}")
            if f.location:
                print(f"            location: {f.location}")
            if f.detail:
                print(f"            {f.detail}")
            if f.evidence:
                print(f"            evidence: {f.evidence.strip()[:160]!r}")
            print()
    else:
        print(" No findings.\n")
    if report.checks_clean:
        print(" Checks that ran and found nothing — NOT proof the issue is absent")
        print(" (an unauthenticated black-box scan can miss real bugs):")
        for name in report.checks_clean:
            print(f"   - {CLEAN_DESCRIPTIONS.get(name, name + ': no issue detected')}")
        print()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rage",
        description="Authorized-only web security recon scanner (OWASP Top 10 2026 mapped).",
        epilog="Only scan systems you own or are explicitly authorized to test.")
    p.add_argument("--version", action="version", version=f"rage {__version__}")
    p.add_argument("target", help="Target URL or domain (e.g. https://beta.example.com)")
    p.add_argument("-m", "--modules", nargs="+", default=["all"], choices=ALL_MODULES + ["all"],
                   help="Modules to run (default: all)")
    p.add_argument("--authorized", action="store_true",
                   help="Confirm you are authorized to actively test this target (required).")
    p.add_argument("--time-based", action="store_true",
                   help="Enable time-based SQLi and command-injection probes (bounded SLEEP(5)).")
    p.add_argument("--active-auth", action="store_true",
                   help="Enable login rate-limit & username-enumeration probes (random usernames).")
    p.add_argument("--oob", metavar="URL", help="Out-of-band collaborator URL for SSRF confirmation.")
    p.add_argument("--max-pages", type=int, default=25, help="Crawl page cap (default 25).")
    p.add_argument("--max-requests", type=int, default=6000, help="Hard request cap (default 6000).")
    p.add_argument("--delay", type=float, default=0.3, help="Delay between requests, seconds (default 0.3).")
    p.add_argument("--timeout", type=float, default=12.0, help="HTTP timeout seconds (default 12).")
    p.add_argument("--port-timeout", type=float, default=2.0, help="Port connect timeout (default 2).")
    p.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates.")
    p.add_argument("--headless", action="store_true",
                   help="Crawl with a headless Chromium (Playwright) to cover JS/SPA apps and XHR APIs.")
    p.add_argument("--sqlmap", action="store_true", help="Confirm SQLi with sqlmap (must be on PATH).")
    p.add_argument("--nuclei", action="store_true", help="Run the nuclei template engine (must be on PATH).")
    p.add_argument("--tls-audit", action="store_true", dest="tls_audit",
                   help="Trustworthy TLS/cipher audit via sslyze or testssl.sh (own cipher stack).")
    p.add_argument("--thorough", action="store_true",
                   help="Lean on every available engine at once: headless crawl + sqlmap + nuclei "
                        "+ TLS audit + OpenAPI fuzzing (engines must be installed; see --tool-status).")
    p.add_argument("--openapi", action="store_true",
                   help="Read the target's OpenAPI/Swagger spec and fuzz the documented API endpoints.")
    p.add_argument("--openapi-spec", metavar="URL", dest="openapi_spec",
                   help="Explicit OpenAPI/Swagger JSON URL (else common paths are tried).")
    p.add_argument("--cookie", metavar="STR", help="Cookie header for authenticated scanning, e.g. 'session=abc'.")
    p.add_argument("--header", action="append", metavar="H",
                   help="Extra request header 'Name: Value' (repeatable), e.g. 'Authorization: Bearer ...'.")
    p.add_argument("--login-url", metavar="URL", help="POST credentials here first to establish a session.")
    p.add_argument("--login-data", metavar="DATA", help="URL-encoded login body, e.g. 'user=admin&pass=secret'.")
    p.add_argument("--json", metavar="FILE", help="Write JSON report to FILE.")
    args = p.parse_args(argv)

    if not args.authorized:
        print("ERROR: active scanning requires --authorized.\n"
              "Only pass it for hosts you own or have explicit written permission to test.", file=sys.stderr)
        return 2

    report = run(args)
    print_text_report(report)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"target": report.target, "started": report.started,
                       "findings": [f.as_dict() for f in report.sorted()],
                       "checks_clean": report.checks_clean}, fh, indent=2)
        print(f"[*] JSON written to {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
