#!/usr/bin/env python3
"""
rage_tools — optional heavy integrations for rage.

Everything here degrades gracefully: if a dependency (Playwright) or external
binary (nuclei, sqlmap) is missing, the corresponding feature reports that it is
unavailable with an install hint, and the rest of rage keeps working.

  * headless crawl  — Playwright/Chromium: renders JS, discovers the real DOM and
                      XHR/fetch API endpoints that the stdlib crawler cannot see.
  * nuclei          — runs the nuclei template engine against the target.
  * sqlmap          — confirms SQL injection on discovered parameterized URLs.

USE ONLY ON SYSTEMS YOU OWN OR ARE EXPLICITLY AUTHORIZED TO TEST.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import urllib.parse


# --------------------------------------------------------------------------- #
# Availability helpers
# --------------------------------------------------------------------------- #

def headless_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except Exception:
        return False


def tool_path(name: str) -> str | None:
    """Resolve an external tool by PATH, then the active Python's Scripts dir."""
    found = shutil.which(name)
    if found:
        return found
    candidates = {sysconfig.get_path("scripts"), os.path.join(sys.prefix, "Scripts"),
                  os.path.join(sys.prefix, "bin")}
    for d in filter(None, candidates):
        for ext in ("", ".exe", ".bat", ".cmd"):
            cand = os.path.join(d, name + ext)
            if os.path.isfile(cand):
                return cand
    return None


# --------------------------------------------------------------------------- #
# Headless crawler (Playwright)
# --------------------------------------------------------------------------- #

def crawl_headless(start_url: str, max_pages: int = 25,
                   extra_headers: dict | None = None, timeout_ms: int = 15000):
    """Render pages with Chromium. Returns (param_urls, forms, scripts, pages).

    Also surfaces XHR/fetch endpoints (with query strings) as param URLs so
    injection modules can reach the real API surface of a JS app.
    """
    from playwright.sync_api import sync_playwright
    import rage  # lazy, avoids circular import at module load

    def host(u):
        return urllib.parse.urlparse(u).netloc

    base_host = host(start_url)
    param_urls: list[str] = []
    forms: list[rage.Form] = []
    scripts: list[rage.Script] = []
    pages: list[rage.Page] = []
    api: set[str] = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(ignore_https_errors=True,
                                  extra_http_headers=extra_headers or {})
        page = ctx.new_page()
        page.on("request", lambda r: api.add(r.url))
        seen: set[str] = set()
        queue = [start_url]
        n = 0
        while queue and n < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            try:
                page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            except Exception:
                continue
            n += 1
            content = page.content()
            pages.append(rage.Page(url, content, {}))
            if urllib.parse.urlparse(url).query:
                param_urls.append(url)
            links, pforms, pscripts = rage.parse_html(url, content)
            forms.extend(pforms)
            scripts.extend(pscripts)
            for link in links:
                link, _ = urllib.parse.urldefrag(link)
                if link.startswith(("http://", "https://")) and host(link) == base_host and link not in seen:
                    queue.append(link)
        browser.close()

    # XHR/fetch endpoints with query strings become fuzzable param URLs
    for u in api:
        if host(u) == base_host and urllib.parse.urlparse(u).query:
            param_urls.append(u)

    uniq: dict[tuple, str] = {}
    for u in param_urls:
        pr = urllib.parse.urlparse(u)
        uniq.setdefault((pr.path, tuple(sorted(urllib.parse.parse_qs(pr.query)))), u)
    seen_src: dict[str, rage.Script] = {}
    for s in scripts:
        seen_src.setdefault(s.src, s)
    return list(uniq.values()), forms, list(seen_src.values()), pages


# --------------------------------------------------------------------------- #
# nuclei
# --------------------------------------------------------------------------- #

def run_nuclei(target: str, timeout: int = 300, extra_args: list | None = None) -> list[dict]:
    """Run nuclei and return normalized findings. [] if unavailable or none."""
    exe = tool_path("nuclei")
    if not exe:
        return []
    cmd = [exe, "-u", target, "-jsonl", "-silent", "-duc",
           "-timeout", "10", "-rate-limit", "30"] + (extra_args or [])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return []
    out = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = j.get("info", {})
        out.append({
            "name": info.get("name") or j.get("template-id", "nuclei finding"),
            "severity": (info.get("severity") or "info").lower(),
            "template": j.get("template-id", ""),
            "matched": j.get("matched-at") or j.get("host", ""),
        })
    return out


# --------------------------------------------------------------------------- #
# sqlmap
# --------------------------------------------------------------------------- #

def _testssl_path() -> str | None:
    """Locate testssl.sh via $RAGE_TESTSSL or PATH (not auto-detected elsewhere,
    so a cloned-but-non-functional copy never masquerades as a working engine)."""
    env = os.environ.get("RAGE_TESTSSL")
    if env and os.path.isfile(env):
        return env
    return tool_path("testssl.sh") or tool_path("testssl")


def tls_audit_available() -> str | None:
    """Return the available TLS-audit engine: 'testssl', 'sslyze', or None."""
    if _testssl_path():
        return "testssl"
    try:
        import sslyze  # noqa: F401
        return "sslyze"
    except Exception:
        return None


_WEAK_CIPHER = re.compile(r"RC4|3DES|DES-CBC|_DES_|DES_|NULL|EXPORT|anon|_MD5|RC2", re.IGNORECASE)
_LEGACY_PROTO = {
    "ssl_2_0_cipher_suites": ("SSL 2.0", "critical"),
    "ssl_3_0_cipher_suites": ("SSL 3.0", "high"),
    "tls_1_0_cipher_suites": ("TLS 1.0", "medium"),
    "tls_1_1_cipher_suites": ("TLS 1.1", "medium"),
}
_ALL_PROTO = list(_LEGACY_PROTO) + ["tls_1_2_cipher_suites", "tls_1_3_cipher_suites"]


def run_tls_audit(host: str, port: int = 443, timeout: int = 180) -> list[dict]:
    """Audit TLS with an engine that carries its own cipher stack. [] if unavailable."""
    engine = tls_audit_available()
    if engine == "testssl":
        return _run_testssl(host, port, timeout)
    if engine == "sslyze":
        return _run_sslyze(host, port, timeout)
    return []


def _accepted(node: dict) -> list:
    return ((node or {}).get("result") or {}).get("accepted_cipher_suites") or []


def _run_sslyze(host: str, port: int, timeout: int) -> list[dict]:
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        cmd = [sys.executable, "-m", "sslyze", "--json_out", path, f"{host}:{port}"]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError):
            return []
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return []
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    results = data.get("server_scan_results") or []
    if not results:
        return []
    res = results[0].get("scan_result") or {}
    out: list[dict] = []

    for key, (label, sev) in _LEGACY_PROTO.items():
        if _accepted(res.get(key)):
            out.append({"severity": sev, "title": f"Legacy protocol enabled: {label}",
                        "detail": f"Server accepts {label} connections (deprecated).", "evidence": label})

    weak: set[str] = set()
    for key in _ALL_PROTO:
        for cs in _accepted(res.get(key)):
            name = (cs.get("cipher_suite") or {}).get("name", "")
            if name and _WEAK_CIPHER.search(name):
                weak.add(name)
    if weak:
        out.append({"severity": "high", "title": "Weak cipher suite(s) supported",
                    "detail": "Server accepts weak ciphers.", "evidence": ", ".join(sorted(weak))[:200]})

    hb = (res.get("heartbleed") or {}).get("result") or {}
    if hb.get("is_vulnerable_to_heartbleed"):
        out.append({"severity": "critical", "title": "Heartbleed (CVE-2014-0160)",
                    "detail": "Server is vulnerable to Heartbleed memory disclosure.", "evidence": ""})
    robot = str(((res.get("robot") or {}).get("result") or {}).get("robot_result", ""))
    if "VULNERABLE" in robot.upper():
        out.append({"severity": "high", "title": "ROBOT attack (RSA padding oracle)",
                    "detail": f"Server robot_result: {robot}.", "evidence": robot})
    return out


def _run_testssl(host: str, port: int, timeout: int) -> list[dict]:
    exe = _testssl_path()
    if not exe:
        return []
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        # A .sh needs a bash interpreter when launched from the Windows Python process.
        prefix = ["bash", exe] if (exe.endswith(".sh") and os.name == "nt") else [exe]
        cmd = prefix + ["--jsonfile", path, "--quiet", "--color", "0", f"{host}:{port}"]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError):
            return []
        try:
            with open(path, encoding="utf-8") as fh:
                items = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return []
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    out = []
    for it in items if isinstance(items, list) else []:
        sev = sev_map.get(str(it.get("severity", "")).upper())
        if sev:
            out.append({"severity": sev, "title": it.get("id", "testssl finding"),
                        "detail": str(it.get("finding", "")), "evidence": str(it.get("id", ""))})
    return out


def run_sqlmap(param_urls: list[str], per_url_timeout: int = 180,
               cookie: str | None = None) -> list[dict]:
    """Run sqlmap on each URL (low level/risk, batch). Returns confirmed points."""
    exe = tool_path("sqlmap")
    if not exe:
        return []
    found = []
    for url in param_urls:
        cmd = [exe, "-u", url, "--batch", "--level", "1", "--risk", "1",
               "--technique", "BEUST", "--flush-session", "--disable-coloring"]
        if cookie:
            cmd += ["--cookie", cookie]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=per_url_timeout)
        except (subprocess.TimeoutExpired, OSError):
            continue
        txt = proc.stdout
        if "is vulnerable" in txt or "sqlmap identified the following injection point" in txt or \
                ("Parameter:" in txt and "Type:" in txt):
            detail = ""
            for key in ("Parameter:", "Type:", "Title:", "back-end DBMS"):
                for ln in txt.splitlines():
                    if key in ln:
                        detail += ln.strip() + "; "
                        break
            found.append({"url": url, "detail": detail[:300] or "sqlmap reported injection"})
    return found
