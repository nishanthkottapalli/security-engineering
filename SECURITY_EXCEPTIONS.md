# Security Exceptions Register

This document records temporary security exceptions where an upstream
dependency cannot currently be upgraded without violating supported
dependency constraints.

The goal is **not** to permanently suppress vulnerabilities.

Each exception must include:

- affected dependency
- advisory IDs
- reason
- compensating controls
- review trigger
- removal criteria

---

# Exception Status

| ID | Package | Status | Review Trigger |
|----|----------|---------|----------------|
| TEMP-2026-001 | Starlette | Active | Every FastAPI release |

---

# TEMP-2026-001

## Package

Starlette

## Installed Version

0.50.0

## Advisory IDs

- PYSEC-2026-161
- PYSEC-2026-248
- PYSEC-2026-249
- CVE-2026-48817
- CVE-2026-48818

---

## Background

Current dependency chain:

```
FastAPI 0.128.2
└── Starlette >=0.40.0,<0.51.0
```

The current FastAPI release does not permit installation of the
Starlette versions identified by the Python Advisory Database as
containing the published fixes.

Updating Starlette independently would violate FastAPI's supported
dependency constraints and could introduce runtime incompatibilities.

---

## Compensating Controls

The application implements the following controls:

- TrustedHostMiddleware
- Host header validation at the reverse proxy
- Nginx reverse proxy
- Explicit HTTP routing
- Restricted request body size
- Multipart upload limits
- Structured audit logging
- CI dependency monitoring
- Continuous SBOM generation

The Windows-specific StaticFiles issue is not applicable because:

- production deployments do not use Windows
- static assets are served by nginx

---

## Residual Risk

Low

Current deployment architecture mitigates the practical exploitation
paths described in the advisories.

---

## Review Trigger

Review immediately when:

- FastAPI publishes a release supporting newer Starlette versions
- Python Advisory Database changes the fixed version
- Starlette publishes additional security releases

---

## Removal Criteria

Remove this exception when:

- FastAPI supports a patched Starlette release
- the dependency can be upgraded without violating supported
  compatibility constraints
- CI passes without the temporary exception

---

## Owner

Nishanth Konsultancy

---

## Last Reviewed

2026-07-11
