# rage tests

Zero-dependency regression tests (stdlib `unittest`, same ethos as the scanner).
They run the detection modules against a **network-free fake HTTP client**
(`_helpers.FakeHttp`) with frozen responses, so results are deterministic and no
live target is ever touched.

## Run

```bash
py -m unittest discover -s tests -v
```

(or `python -m unittest discover -s tests -v`). Run from the repo root so
`import rage` resolves. `pytest tests` also works if you have pytest installed.

## What's covered

- **`test_verifiers.py`** — the shared gates several modules rely on:
  `_is_html`, `_is_weak_cipher`, `_is_static_asset`, the SSRF-vs-redirect param
  split, and the secret-pattern set (JWTs excluded, real credentials included).
- **`test_false_positive_regressions.py`** — every false positive we've found and
  fixed, frozen so it stays fixed, each with a positive control proving the real
  vuln is still caught:
  | Regression | Must NOT fire on | Must still fire on |
  |---|---|---|
  | Reflected XSS requires HTML | JSON API echo (FastAPI 422) | unescaped reflection in an HTML page |
  | JWT is not a secret | signed media URL with a JWT | real AWS key / private key |
  | `next=` is redirect, not SSRF | `?next=https://…` | `?url=https://…` |
  | Login-throttle heuristic | — (stays **low** severity) | — |
  | Token in static-asset URL | `/logo.png?token=…` | `/account?token=…` |
- **`test_registry.py`** — module-registry consistency (every module has a clean
  description, opt-in modules stay out of `DEFAULT_ALL`, no duplicates).

## Adding a case

When a new false positive is found and fixed:
1. Add the benign input that must **not** fire.
2. Add a positive control (the genuine vuln that **must** fire).
3. Prefer pinning the shared helper (in `test_verifiers.py`) when the fix lives in
   one — that protects every module that uses it.
