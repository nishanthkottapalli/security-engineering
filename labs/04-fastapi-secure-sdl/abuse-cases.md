# Abuse cases

- An unauthenticated caller attempts to upload a file.
- A normal user attempts to list or create administrator accounts.
- A user guesses another upload identifier.
- A client declares text while sending executable, archive or active HTML content.
- A client sends a file larger than the configured limit.
- Two requests attempt to create the same storage object.
- A background-processing failure leaves a job permanently marked as running.
- A stolen token remains usable until expiry.
- An operator starts the service with default secrets in a production environment.

The current tests cover the first five classes. Production work should add retry
leases, dead-letter handling, token revocation, secret-manager integration,
central logging and recovery tests.
