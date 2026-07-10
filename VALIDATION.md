# Validation record

This record distinguishes checks executed while assembling the repository from
checks that require Docker, VirtualBox, Wazuh, Terraform provider downloads, or
an AWS account.

## Executed successfully

Build environment: Linux x86-64, Python 3.13.5.

- clean editable installation from `pyproject.toml` in a new virtual environment
- dependency consistency check with `pip check`
- repository structure and JSON/YAML/XML validation
- Python byte-code compilation
- Ruff linting and formatting
- strict mypy checking across the `secops_lab` package
- Bandit static analysis of application source
- pytest suite: 8 tests passed
- local SSH detection replay: 6 events processed, 1 expected correlation alert
- local multi-scanner triage replay: 6 records normalised to 4 deduplicated findings
- Terraform HCL and Terraform test-file parsing

## Supplied for execution in the target environment

The build environment did not expose Docker, Vagrant, VirtualBox, or Terraform,
so the following acceptance paths are implemented but were not started here:

```bash
make full-demo
vagrant up --provider=virtualbox
```

GitHub Actions independently executes Compose validation and smoke tests, Wazuh
`wazuh-logtest`, Terraform format/validate/mock tests, dependency auditing,
Bandit, Trivy, Gitleaks, and SBOM generation.

A real `terraform apply` is intentionally excluded from CI. It requires an
approved disposable AWS account, short-lived credentials, plan review, and cost
approval.
