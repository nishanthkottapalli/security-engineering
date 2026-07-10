# Security Policy

## Overview

The Security Capabilities Lab demonstrates secure software engineering,
detection engineering, vulnerability management, cloud security and
secure SDLC practices.

Security is treated as a first-class engineering concern.

## Reporting a Security Issue

If you believe you have discovered a security vulnerability in this
repository, please open a private security advisory or contact the
maintainers directly.

Please include:

- affected component
- reproduction steps
- expected behaviour
- observed behaviour
- proof of concept (if applicable)
- affected version
- mitigation suggestions

We aim to:

- acknowledge reports promptly
- validate findings
- determine impact
- develop a remediation plan
- publish fixes where appropriate

---

## Supported Versions

| Version | Supported |
|----------|-----------|
| 1.x | Yes |

---

## Security Tooling

This repository continuously validates security using:

- pip-audit
- Bandit
- Trivy
- Gitleaks
- Ruff
- Mypy
- GitHub Actions
- SBOM generation
- Docker image scanning

---

## Vulnerability Management

Dependencies are reviewed continuously.

Critical and High vulnerabilities block CI unless a documented,
temporary exception exists.

---

## Temporary Security Exceptions

Occasionally an upstream dependency cannot be upgraded because another
supported framework has not yet released a compatible version.

In those situations:

- compensating controls are implemented
- the exception is documented
- the exception is reviewed regularly
- the exception is removed immediately once a supported upgrade path
  becomes available

The current exception register is maintained in:

**[SECURITY_EXCEPTIONS.md](SECURITY_EXCEPTIONS.md)**

---

## Responsible Disclosure

Please do not disclose vulnerabilities publicly before maintainers have
had a reasonable opportunity to investigate and remediate the issue.
