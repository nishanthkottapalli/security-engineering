# Threat model

## Assets

- user identities and password verifiers
- access tokens
- uploaded evidence
- audit events
- database integrity
- availability of the API and worker

## Trust boundaries

1. external client to Nginx
2. Nginx to FastAPI
3. FastAPI/worker to PostgreSQL
4. FastAPI/worker to the upload volume
5. operator to Docker host and environment configuration

## STRIDE summary

| Threat | Example | Implemented mitigation | Residual work for production |
| --- | --- | --- | --- |
| Spoofing | stolen credential or token | Argon2, signed short-lived JWT, disabled-user check | SSO/MFA, token revocation, key rotation |
| Tampering | overwrite another upload | random server-side name, `O_EXCL`, owner checks | immutable object storage, integrity monitoring |
| Repudiation | deny login or file action | database + JSONL audit events, request IDs | central append-only logging and retention |
| Information disclosure | enumerate another user's upload | object-level ownership and 404 response | tenant-scoped encryption and DLP |
| Denial of service | oversized upload/request flood | gateway rate limit, body limit, app size limit | distributed rate limiting, quotas, autoscaling |
| Elevation of privilege | user calls admin API | explicit admin dependency and integration test | enterprise IdP claims governance |

## Important limitation

The worker's harmless marker check proves queueing and quarantine state changes.
It is not a malware engine. Production ingestion requires an approved scanner,
sandboxing, object-store quarantine, timeouts and decompression controls.
