# Rage MCP

**rage** is an authorized-only web-security recon scanner, mapped to the OWASP Top 10 (2026),
with three ways to run it:

- **CLI** — `py rage.py <target> --authorized`
- **Web UI** — `py rage_web.py` → http://127.0.0.1:8787
- **MCP server** — `py rage_mcp.py` lets an AI agent (Claude Desktop, Cursor, Claude Code, any
  MCP client) drive the scanner as tools (`scan`, `list_modules`, `tool_status`).

Detection, not exploitation. Stdlib-only core (Python 3.9+); the heavy engines are optional.

> ⚠️ **Use only on systems you own or are explicitly authorized to test.** Every entry point
> requires an explicit authorization flag. Unauthorized scanning is illegal in most places.

## What it checks (OWASP Top 10 2026)

| OWASP 2026 | Covered by |
|---|---|
| A01 Broken Access Control (+SSRF) | CORS, HTTP methods/TRACE, open redirect, SSRF candidates, path traversal, CSRF, unauth paths |
| A02 Security Misconfiguration | headers, cookie flags, version leak, dir listing, backup/API-doc/GraphQL discovery, secrets, ports |
| A03 Supply Chain | tech/CMS fingerprint, subdomain-takeover signatures, outdated JS libs |
| A04 Cryptographic Failures | TLS version/downgrade, cert expiry, HSTS, weak ciphers, mixed content, sensitive data in URL |
| A05 Injection | SQLi, XSS, SSTI, command injection, CRLF/host-header, NoSQL/LDAP/XPath |
| A06 Insecure Design | reported as manual-review (not black-box testable) |
| A07 Authentication Failures | JWT flaws, token entropy, password-over-HTTP, login rate-limit/enum (opt-in) |
| A08 Data Integrity | missing Subresource Integrity |
| A09 Logging & Alerting | reported as manual-review |
| A10 Exceptional Conditions | verbose error / stack-trace disclosure |

Findings are tagged with their OWASP ID; the report also lists checks that ran and found
nothing (labelled *not proof of absence*) and the categories that need manual review.

## Install

```bash
git clone https://github.com/Doctor00777/Rage-MCP.git
cd Rage-MCP

# The core scanner (rage.py) needs nothing beyond Python 3.9+.
# Optional engines (MCP server, headless crawl, TLS audit):
pip install -r requirements.txt
playwright install chromium       # only if you want the headless (JS/SPA) crawl

# External binaries, optional, must be on PATH: nuclei, sqlmap, testssl.sh
```

## Usage

```bash
py rage.py https://beta.example.com --authorized
py rage.py https://beta.example.com --authorized --headless --nuclei --sqlmap --time-based
py rage.py https://beta.example.com --authorized --cookie "session=..."   # authenticated
py rage.py https://beta.example.com --authorized --json report.json
```

### MCP (AI-driven)

```bash
py rage_mcp.py            # stdio MCP server
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "rage": { "command": "py", "args": ["C:/path/to/Rage-MCP/rage_mcp.py"] }
  }
}
```

Then ask the agent: *"scan https://my-authorized-host with rage."*

## Honest limits

- A clean report is **not** proof of security — it's a strong first pass. Real assurance needs a
  manual pentest plus source/SCA review.
- Heuristic findings (labelled *likely* / *candidate*) must be confirmed manually.
- The full external-tool arsenal (and sslyze/testssl) is Linux-first; run under **WSL/Linux** for
  best coverage.

## License

MIT — see [LICENSE](LICENSE).
