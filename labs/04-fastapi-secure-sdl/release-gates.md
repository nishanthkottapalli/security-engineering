# Release gates

A pull request is releasable only when:

1. repository validation and Python tests pass;
2. dependency audit and static analysis complete;
3. Terraform formatting, validation and mock tests pass;
4. container filesystem scanning reports no unaccepted critical/high findings;
5. authentication, RBAC, upload and background-worker smoke tests pass;
6. risk acceptances have an owner, rationale, compensating control and expiry;
7. security-sensitive behavioural changes update the threat model and evidence.
