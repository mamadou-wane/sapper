---
status: Accepted
date: 2026-05-29
tags: [terraform, architecture, state]
---

# ADR-0001: Use S3 with native locking for Terraform remote state

## Context

Terraform tracks the infrastructure it manages in a state file. By default that file lives on the workstation of whoever ran `terraform apply` last, which stops working as soon as the project has more than one operator.

This project will run `plan` and `apply` from GitHub Actions and from developer machines. They can't all hold the real state, and two runs against the same state at once will race and corrupt it. State has to live in shared, durable storage with locking, and it has to exist before the CI/CD work starts.

## Decision

Use an S3 backend for remote state with S3-native locking turned on.

```hcl
terraform {
  required_version = ">= 1.11.0"

  backend "s3" {
    bucket       = "<state-bucket>"
    key          = "<path>/terraform.tfstate"
    region       = "<region>"
    encrypt      = true
    use_lockfile = true
  }
}
```

The state bucket has versioning, server-side encryption, and Block Public Access enabled.

Pin Terraform to >= 1.11.0. Native locking (`use_lockfile`) shipped in 1.10 as an experimental feature. 1.11 is where it stops being experimental and where the DynamoDB locking arguments get marked deprecated. That makes 1.11.0 the right floor: native locking is stable there, and the DynamoDB path is already deprecated.

## Options considered

- Local state (the default). No setup. But it's laptop only, so CI can't read it, nothing locks concurrent runs, and one wiped machine takes the state with it. **Rejected:** a shared project can't run on local state.
- S3 with DynamoDB locking. The long-standing remote setup, and it works on older Terraform. The cost is a second resource: a DynamoDB table to create, secure with IAM, and pay for. Those locking arguments are also deprecated as of 1.11. **Rejected:** more to manage, and it builds on a path Terraform is deprecating.
- S3 with native lockfile locking. **Chosen:** Just the S3 bucket to manage, simpler IAM, and the locking method Terraform now points you to. The cost is a higher minimum Terraform version.

## Consequences

State is shared and durable. CI and laptops read and write the same file. Versioning gives a way back from a bad write, encryption protects state at rest, and Block Public Access keeps the infra metadata out of public view. The backend also has fewer pieces to manage: the bucket holds both the state and the lock, so there's no DynamoDB table to provision and secure.

What we are now committed to:

- Terraform >= 1.11.0 on every laptop and every CI runner. An older version will fail on this backend config.
- IAM that covers the lock object. The lock is the state key with a `.tflock` suffix, and Terraform creates and deletes it on each operation, so grant it the same object permissions as the state key. Miss it and you hit a confusing failure: state reads and writes work, then the run fails the moment it tries to lock.
