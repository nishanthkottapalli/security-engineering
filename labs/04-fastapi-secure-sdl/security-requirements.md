# Security requirements

| ID | Requirement | Verification |
| --- | --- | --- |
| AUTH-01 | Passwords use a memory-hard verifier | Argon2 implementation and tests |
| AUTH-02 | Access tokens expire and require issuer/audience | JWT encode/decode code review |
| AUTHZ-01 | Admin endpoints require the admin role | integration test returns 403 |
| AUTHZ-02 | Users can read only their uploads | owner predicate and 404 behaviour |
| FILE-01 | Upload size is bounded in gateway and application | Nginx + FastAPI limits |
| FILE-02 | Active/binary content is rejected by the lab policy | integration tests |
| FILE-03 | Storage names cannot contain client-controlled paths | UUID name and containment check |
| AUD-01 | Security-relevant actions produce structured events | database and JSONL assertions |
| CONT-01 | API and worker run non-root with dropped capabilities | Compose configuration |
| CONT-02 | Application filesystems are read-only | Compose configuration |
| OPS-01 | Health endpoint supports orchestration | Docker health check and smoke test |
