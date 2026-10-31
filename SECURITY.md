# Security policy

Lantern Zero handles data that can reveal people's finances, including
viewing keys in opt-in scanning mode. We take reports seriously.

## Reporting a vulnerability

Please **do not** open a public issue, pull request, or discussion.

Report privately through GitHub:
**Security → Report a vulnerability** on this repository, which opens a
[private security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).

Include what you can of:

- the component and version or commit affected
- what an attacker could learn or do
- steps or a proof of concept to reproduce it

We will acknowledge the report, keep you updated while we fix it, and credit
you in the advisory unless you ask us not to.

## Especially in scope

- Any way for a viewing key, or data derived from it, to reach disk, logs,
  backups, or anyone other than the scanner holding the lease
- A key lease that outlives its expiry, an opt-out, or the end of a paid period
- Anything that lets the server, a relay, a push gateway, or Apple/Google tell
  default-mode users apart or link pings to payments
- Weaknesses in the Oblivious HTTP setup that expose a client's IP address to
  the server
- Account tokens leaking through URLs, logs, or relays

## Supported versions

The project is pre-alpha. Only the latest commit on `main` receives fixes.
