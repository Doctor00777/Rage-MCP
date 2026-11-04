#!/usr/bin/env python3
"""
rage_mcp — expose rage as an MCP server so an AI agent (Claude Desktop, Cursor,
or any MCP client) can orchestrate the scanner's checks and tool integrations.

This is the "AI-driven" shape: the LLM decides what to run; rage provides the
tools and does the work. Same safety model as the CLI — the `scan` tool refuses
unless authorized=true, scans one target, and never mass-targets or auto-exploits.

Run it directly, or wire it into an MCP client:

    py rage_mcp.py            # starts a stdio MCP server

Claude Desktop (claude_desktop_config.json):
    {
      "mcpServers": {
        "rage": { "command": "py",
                  "args": ["C:/Users/mahat/PentestGPT/websec_scanner/rage_mcp.py"] }
      }
    }

Requires the MCP SDK:  pip install "mcp<2"
USE ONLY ON SYSTEMS YOU OWN OR ARE EXPLICITLY AUTHORIZED TO TEST.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter

import rage
import rage_tools

try:
    from mcp.server.fastmcp import FastMCP
except Exception:  # pragma: no cover - import guard
    sys.stderr.write('The "mcp" package is required. Install it with:  pip install "mcp<2"\n')
    raise SystemExit(1)

mcp = FastMCP("rage")


# --------------------------------------------------------------------------- #
# Plain implementation functions (unit-testable without the MCP runtime)
# --------------------------------------------------------------------------- #

def _list_modules_impl() -> dict:
    return {
        "modules": rage.ALL_MODULES,
        "default_all": rage.DEFAULT_ALL,
        "opt_in": [m for m in rage.ALL_MODULES if m not in rage.DEFAULT_ALL],
        "owasp": rage.OWASP_2026,
        "descriptions": rage.CLEAN_DESCRIPTIONS,
    }


def _tool_status_impl() -> dict:
    return {
        "nuclei": bool(rage_tools.tool_path("nuclei")),
        "sqlmap": bool(rage_tools.tool_path("sqlmap")),
        "tls_audit_engine": rage_tools.tls_audit_available(),
        "headless_browser": rage_tools.headless_available(),
    }


def _scan_impl(target: str, authorized: bool, modules: list[str] | None,
               time_based: bool, active_auth: bool, headless: bool,
               sqlmap: bool, nuclei: bool, tls_audit: bool,
               openapi: bool, openapi_spec: str | None, oob: str | None,
               cookie: str | None, headers: list[str] | None,
               login_url: str | None, login_data: str | None,
               delay: float, max_pages: int) -> dict:
    if not authorized:
        return {"error": "Refused: set authorized=true only for a target you own or "
                         "have explicit written permission to test."}
    args = argparse.Namespace(
        target=target, modules=modules or ["all"], authorized=True,
        time_based=time_based, active_auth=active_auth, oob=oob,
        cookie=cookie, header=headers or [], login_url=login_url, login_data=login_data,
        headless=headless, sqlmap=sqlmap, nuclei=nuclei, tls_audit=tls_audit,
        openapi=openapi, openapi_spec=openapi_spec,
        max_pages=max_pages, max_requests=6000, delay=delay,
        timeout=12.0, port_timeout=2.0, insecure=False, json=None,
    )
    report = rage.run(args)
    findings = [f.as_dict() for f in report.sorted()]
    return {
        "target": report.target,
        "counts": dict(Counter(f["severity"] for f in findings)),
        "findings": findings,
        "checks_clean": report.checks_clean,
        "note": "Heuristic findings (labelled 'likely'/'candidate') need manual confirmation; "
                "a clean result is not proof of security.",
    }


# --------------------------------------------------------------------------- #
# MCP tools
# --------------------------------------------------------------------------- #

@mcp.tool()
def list_modules() -> dict:
    """List rage's scan modules, which run under 'all', which are opt-in
    (sqlmap/nuclei/tlsaudit), and the OWASP Top 10 (2026) mapping."""
    return _list_modules_impl()


@mcp.tool()
def tool_status() -> dict:
    """Report which optional external engines are available on this host
    (nuclei, sqlmap, TLS-audit engine, headless browser)."""
    return _tool_status_impl()


@mcp.tool()
def scan(target: str, authorized: bool = False, modules: list[str] | None = None,
         time_based: bool = False, active_auth: bool = False, headless: bool = False,
         sqlmap: bool = False, nuclei: bool = False, tls_audit: bool = False,
         openapi: bool = False, openapi_spec: str | None = None,
         oob: str | None = None, cookie: str | None = None,
         headers: list[str] | None = None, login_url: str | None = None,
         login_data: str | None = None, delay: float = 0.3, max_pages: int = 25) -> dict:
    """Run an AUTHORIZED web-security scan of a single target; return OWASP-tagged findings.

    Set authorized=true ONLY for a host the user owns or has written permission to test.
    modules: subset from list_modules() (default: all built-in checks). Opt-in heavy engines:
    set sqlmap/nuclei/tls_audit/headless true (and time_based/active_auth for intrusive probes).
    Authenticated scan: pass cookie, headers (["Name: Value", ...]), or login_url + login_data.
    Returns {target, counts, findings[], checks_clean[]}. Heuristic findings need manual review.
    """
    return _scan_impl(target, authorized, modules, time_based, active_auth, headless,
                      sqlmap, nuclei, tls_audit, openapi, openapi_spec, oob, cookie, headers,
                      login_url, login_data, delay, max_pages)


if __name__ == "__main__":
    mcp.run()
