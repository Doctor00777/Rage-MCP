# Contributing to rage

Thanks for your interest! rage is an authorized-only web-security recon scanner.
Contributions are welcome — new checks, better engine integrations, and especially
false-positive fixes.

## Ground rules

- **Authorized testing only.** Never include, commit, or attach scan output, tokens,
  cookies, flags, or traffic captured from a system you do not own or have written
  permission to test. PRs containing third-party data will be closed.
- The **core scanner stays stdlib-only.** Heavy engines (nuclei, sqlmap, sslyze,
  Playwright) are optional and must degrade gracefully when not installed.
- Detection, not exploitation. Modules identify issues; they must not weaponize them.

## Dev setup

```bash
git clone https://github.com/Doctor00777/Rage-MCP
cd Rage-MCP
python -m pip install -e ".[all]"   # or just -e . for the stdlib core
```

## Tests

The suite is stdlib `unittest` — no dependencies, no network (fixtures bind to
loopback):

```bash
python -m unittest discover -s tests -v
```

CI runs this on every push/PR across Python 3.9–3.13.

## Adding or changing a check

1. Keep the module's public signature stable (`rage.run()` wires modules in a list).
2. If you fix a **false positive**, add a regression case in
   `tests/test_false_positive_regressions.py`: the benign input that must *not* fire,
   plus a positive control (the genuine vuln that *must* fire). Prefer pinning the
   shared helper in `tests/test_verifiers.py` when the fix lives in one.
3. New module? Add it to `ALL_MODULES`, give it a `CLEAN_DESCRIPTIONS` entry, map it
   to an OWASP tag, and wire it into `run()`. `tests/test_registry.py` enforces this.
4. For new detections, consider extending the golden corpus in `tests/fixtures.py`.

## Commit / PR style

- Conventional-commit prefixes (`feat:`, `fix:`, `test:`, `docs:`, `chore:`).
- Keep PRs focused; describe what changed and how you verified it.
- Make sure `python -m unittest discover -s tests` is green before opening a PR.
