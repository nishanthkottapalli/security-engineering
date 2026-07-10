# Lab 03 — AWS foundational security baseline

The lab has two execution paths.

## Safe default

```bash
make terraform-test
```

Terraform's mock AWS provider plans the complete module without AWS credentials
or cloud resources. This is suitable for local development and CI.

## Real account

Use a dedicated sandbox account and short-lived role credentials:

```bash
cp terraform/aws-foundation/terraform.tfvars.example \
   terraform/aws-foundation/terraform.tfvars
make terraform-plan
# Inspect the saved plan.
make aws-apply
```

A real apply can create billable services and may conflict with existing
account-level services. See the Terraform package README before proceeding.
