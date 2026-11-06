<!-- Thanks for contributing to rage! -->

## What & why

<!-- What does this change and why? Link any related issue. -->

## Type

- [ ] fix (false positive / bug)
- [ ] feat (new check / flag / integration)
- [ ] docs / chore / test

## Checklist

- [ ] `python -m unittest discover -s tests` passes locally
- [ ] If this fixes a false positive, I added a regression test (benign case + positive control)
- [ ] If this adds a module, it's in `ALL_MODULES`, `CLEAN_DESCRIPTIONS`, `run()`, and OWASP-tagged
- [ ] Core stays stdlib-only; any engine use degrades gracefully when not installed
- [ ] No scan data, tokens, cookies, or traffic from unauthorized systems is included
