# Security Policy

## Reporting a vulnerability

If you discover a security issue in promptshield, please report it privately first, before filing a public issue.

- **Email**: [open a private security advisory](https://github.com/dokienlam/promptshield/security/advisories/new)
- We aim to acknowledge reports within **72 hours** and ship a fix or mitigation within **14 days** for high-severity issues.

## In scope

- Bypasses of detection rules (a payload that should be blocked but isn't)
- Crashes, hangs, or memory issues triggered by malformed input
- Data leakage between requests
- Any vulnerability that lets an attacker tamper with logged audit data

## Out of scope

- Detection rules can always be evaded by a determined attacker — promptshield is defense-in-depth, not a complete solution. Submit suggestions for stronger rules as regular pull requests, not security reports.
- Issues in dependencies that are already publicly disclosed.

## Disclosure

We follow coordinated disclosure. After a fix is shipped, the reporter is credited in the release notes (unless they prefer to remain anonymous).
