# Security Policy

## Supported Versions

Security fixes are provided for the latest branch used for integration and release:

- `main`: fully supported
- `dev`: supported for pre-release fixes
- older release branches: best effort, no guaranteed SLA

## Reporting a Vulnerability

Do not open public issues for unpatched vulnerabilities.

Report privately using one of the following:

- GitHub Security Advisory (preferred): repository `Security` tab

Include:

- affected version/commit
- impact and attack scenario
- reproduction steps (minimal PoC)
- proposed mitigation (if available)

## Response Targets

- Initial triage: within 3 business days
- Severity assessment and plan: within 7 business days
- Patch target:
  - critical/high: as soon as possible, typically within 14 days
  - medium/low: next scheduled security release

## Disclosure

- Coordinated disclosure is expected.
- Public details are shared after patch availability.
- Credit is provided unless the reporter requests anonymity.

## Security Baseline

- TLS client operations in origin-recon paths must keep certificate verification enabled.
- Benchmark and helper tooling must not disable TLS verification unless explicitly marked as test-only.
