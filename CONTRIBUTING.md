# Contributing

1. Create a focused branch.
2. Add or update tests for behavioural changes.
3. Run `make validate` and `make test`.
4. Document telemetry assumptions, false positives, limitations, and evidence.
5. Never commit credentials, customer data, internal IP addresses, or live findings.

A capability may be labelled `validated` only when its automated tests and
reproduction instructions pass. `production` is reserved for controls operating
in a maintained production environment.
