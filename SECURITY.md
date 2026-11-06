# Security Policy

## Scope

rage is a security **tool**. This policy covers vulnerabilities in rage itself — for
example, a code path that could harm the user running it, leak local data, or cause
rage to behave unsafely against an unintended target. It does **not** cover findings
that rage reports about some third-party website (those belong to that site's owner).

## Reporting a vulnerability

Please report privately rather than opening a public issue:

- Use GitHub's **"Report a vulnerability"** (Security → Advisories) on
  <https://github.com/Doctor00777/Rage-MCP>, or
- open a minimal issue asking for a private contact channel (no exploit details).

Include: affected version (`rage --version`), platform/Python version, a description,
and minimal reproduction steps. Please do **not** include data captured from systems
you are not authorized to test.

We aim to acknowledge reports within a few days and will credit reporters who wish to
be named once a fix ships.

## Responsible use

rage can send active, intrusive traffic. Use it only on systems you own or are
explicitly authorized to test. Misuse is the user's responsibility — see the LICENSE
disclaimer and the "Responsible use" section of the README.

## Supported versions

This project is pre-1.0; only the latest release receives fixes.
