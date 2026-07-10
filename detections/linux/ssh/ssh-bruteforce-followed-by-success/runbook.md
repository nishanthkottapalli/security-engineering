# Analyst runbook

## Triage

1. Confirm the failure count, successful event, username, source IP and hostname.
2. Check whether the source is approved, expected and geographically plausible.
3. Determine whether the account is privileged and whether MFA or a bastion was expected.
4. Review activity after the login: `sudo`, new keys, persistence, downloads and lateral movement.

## Containment

- Disable or rotate the affected credential where compromise is plausible.
- Isolate the host or restrict the source through approved network controls.
- Preserve authentication, process, shell-history, network and cloud evidence.

## Recovery

- Remove unauthorised keys, sessions, users and persistence.
- Patch the exposed service and enforce key-based authentication/MFA where appropriate.
- Re-enable access only after credential and host integrity checks.

## Closure evidence

Record the alert ID, timestamps, analyst conclusion, containment actions,
credential rotation evidence, affected assets and any tuning decision with expiry.
