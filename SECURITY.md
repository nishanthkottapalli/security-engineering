# Security Policy

## Supported branch

Security fixes are applied to the default branch and the latest tagged release.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that may expose users of this
repository. Report it privately through GitHub's private vulnerability reporting
feature. Include the affected component, reproduction steps, impact, and any
suggested remediation.

## Responsible-use boundary

This repository contains defensive security labs. Run them only against systems
you own or are explicitly authorised to test. The supplied simulations are
bounded to disposable local containers or virtual machines. Do not point them at
third-party systems.

The repository intentionally uses synthetic telemetry and a deliberately small
sample application. It must not be treated as a production security product
without an organisation-specific architecture review, threat model, operational
ownership, monitoring, backups, and formal acceptance testing.
