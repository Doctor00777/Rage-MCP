# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] — 2026-11-06

First public release.

### Added
- Stdlib-only core scanner with 29 modules mapped to the OWASP Top 10 (2026).
- Three interfaces: `rage` (CLI), `rage-web` (local web UI), `rage-mcp` (MCP server).
- Optional engines: nuclei, sqlmap, sslyze/testssl.sh, headless Playwright crawl.
- OpenAPI/Swagger endpoint fuzzing (`--openapi`).
- Authenticated scanning (cookie / header / login form).
- `--thorough`: enable every available engine at once; the external TLS engine
  supersedes the limited built-in cipher heuristic.
- Packaging: installable via pip/pipx with console entry points; `--version` flag.
- Test suite (stdlib `unittest`): verifier/regression tests + a local golden corpus
  (vulnerable vs clean app), run in GitHub Actions CI on Python 3.9–3.13.

[Unreleased]: https://github.com/Doctor00777/Rage-MCP/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Doctor00777/Rage-MCP/releases/tag/v0.1.0
