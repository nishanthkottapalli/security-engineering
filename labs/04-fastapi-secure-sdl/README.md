# Lab 04 — FastAPI secure-SDLC reference service

## Start

```bash
cp .env.example .env
make up
make smoke
```

The gateway is available on `http://localhost:8080`, and direct OpenAPI
documentation is exposed on `http://localhost:8000/docs` in development mode.

## Data flow

```mermaid
sequenceDiagram
    participant Client
    participant Gateway as Nginx
    participant API as FastAPI
    participant DB as PostgreSQL
    participant Volume as Upload volume
    participant Worker

    Client->>Gateway: POST /auth/token
    Gateway->>API: Rate-limited request
    API->>DB: Verify Argon2 credential
    API-->>Client: Short-lived JWT
    Client->>Gateway: POST /uploads + JWT
    Gateway->>API: Request ID and proxy context
    API->>API: Size, declared type and content validation
    API->>Volume: O_EXCL write, mode 0600
    API->>DB: Upload + pending job + audit event
    Worker->>DB: Claim job with row lock
    Worker->>Volume: Read and calculate SHA-256
    Worker->>DB: Clean/quarantined status + audit event
    Client->>API: GET /uploads/{id}
    API-->>Client: Owner-scoped status
```

## Demonstrated controls

- authentication and role-based authorisation
- object-level ownership checks
- input, size and content validation
- safe storage path construction
- asynchronous processing separated from the request
- audit trail for login, identity and upload operations
- container least privilege
- gateway rate limiting and headers
- repeatable integration tests

See `threat-model.md`, `security-requirements.md`, `abuse-cases.md` and
`release-gates.md` for the SDL evidence.
