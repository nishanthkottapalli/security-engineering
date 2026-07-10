# AWS foundational security baseline

This Terraform package demonstrates a single-account regional baseline with:

- encrypted, versioned and non-public security-evidence storage
- multi-region CloudTrail with log-file validation and CloudWatch delivery
- GuardDuty and high-severity EventBridge/SNS routing
- Security Hub default standards and controls
- Inspector v2 for EC2, ECR and Lambda
- AWS Config recording and delivery
- ECR enhanced continuous scanning
- IAM account password policy
- optional VPC Flow Logs

## Credential-free execution

```bash
make terraform-fmt
make terraform-validate
make terraform-test
```

`terraform test` uses Terraform's mock provider. It validates module composition
without creating cloud resources or requiring AWS credentials.

## Real AWS execution

1. Use a dedicated lab account inside an AWS Organisation.
2. Authenticate with short-lived credentials through IAM Identity Center or an
   approved role; do not place credentials in files.
3. Copy `terraform.tfvars.example` to `terraform.tfvars` and review every value.
4. Run `make terraform-plan` and inspect the plan.
5. Run `make aws-apply` only after cost, ownership and destruction approval.

Several resources are account/region singletons. Import or adopt existing
CloudTrail, Config, GuardDuty, Security Hub, Inspector and ECR scanning settings
rather than creating duplicates in an established account.

## Deliberate limits

The module does not automate AWS Organisation creation, delegated administrator
configuration, root MFA, break-glass ownership, IAM Identity Center, SCPs,
central log-archive accounts or cross-account aggregation. Those require an
organisation-specific landing-zone design. `force_destroy` exists only for
disposable labs and defaults to `false`.
