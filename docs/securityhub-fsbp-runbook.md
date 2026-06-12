# T5 runbook: Terraform-managed Security Hub + FSBP

## Purpose

T5 enables the second half of the detective layer. AWS Config (T4) records the two lab resource types; Security Hub evaluates security controls against that recorded data, with AWS Foundational Security Best Practices (FSBP) enabled explicitly and Terraform owning the account configuration and the enabled standard.

`aws_securityhub_account` targets Security Hub CSPM (classic), which keeps the project on the ASFF / `Security Hub Findings - Imported` contract the whole runtime path rides on, confirmed in Phase 0 (`SPIKE_NOTES.md` §1).

This sets up the detection work that follows: intentionally misconfigured lab resources producing Security Hub findings.

## What T5 creates

File: `terraform/securityhub.tf`

Resources:

```text
aws_securityhub_account.main
aws_securityhub_standards_subscription.fsbp
```

## Design decisions

### Default standards disabled

```hcl
enable_default_standards = false
```

Security Hub can auto-enable default standards when the hub is created. That behavior is off, so Terraform owns exactly which standards are enabled. FSBP is subscribed explicitly; CIS stays absent unless deliberately added later.

### Consolidated control findings

```hcl
control_finding_generator = "SECURITY_CONTROL"
```

Security Hub uses consolidated security control findings. Later detection and automation logic relies on a control structure set in code rather than an inherited account default.

### New controls auto-enable

```hcl
auto_enable_controls = true
```

New FSBP controls enable themselves as AWS ships them. This sits in deliberate tension with ADR-0002, which pinned the CI scanner so its ruleset changes only by an explicit, reviewable version bump. The asymmetry is the point. The gate blocks code: a ruleset that moves on its own can start or stop failing builds with no diff to review, so its coverage changes only by deliberate change. The detective layer watches for drift: it blocks nothing and mutates nothing, so a control it lacks costs more than a finding that surprises. The default-wider posture is also bounded twice over. The Config recorder records only the two lab resource types, so most new controls evaluate against nothing here, and the EventBridge rule allowlists specific control IDs, so a new control can surface a finding but can never reach the remediation path. Pin what blocks; let what watches widen.

### Config before Security Hub, graph-enforced

```hcl
depends_on = [
  aws_config_configuration_recorder_status.main
]
```

Security Hub evaluates many FSBP controls through AWS Config, and out-of-order enablement leaves controls at "no data." The Terraform graph enforces that the Config recorder is enabled before the hub is created, the same ordering Phase 0 held manually.

## Apply procedure

Run from the repository root:

```bash
terraform -chdir=terraform fmt
terraform -chdir=terraform validate
checkov -d terraform --skip-path terraform/bootstrap
terraform -chdir=terraform plan
```

Expected plan before first apply:

```text
Plan: 2 to add, 0 to change, 0 to destroy.
```

Apply:

```bash
terraform -chdir=terraform apply
```

Expected resources created:

```text
aws_securityhub_account.main
aws_securityhub_standards_subscription.fsbp
```

The hub creates quickly. The FSBP standards subscription can take a few minutes to finish.

## Verification

Verify the hub:

```bash
aws securityhub describe-hub
```

Expected:

```text
HubArn present
AutoEnableControls: true
ControlFindingGenerator: SECURITY_CONTROL
```

Verify enabled standards:

```bash
aws securityhub get-enabled-standards
```

Expected:

```text
Exactly one standards subscription
StandardsArn: arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0
StandardsStatus: READY
CIS absent
```

Verify Terraform is clean:

```bash
terraform -chdir=terraform plan
```

Expected:

```text
No changes. Your infrastructure matches the configuration.
```

## Current verified state

Security Hub is enabled:

```text
HubArn: arn:aws:securityhub:us-east-account-id:hub/default
AutoEnableControls: true
ControlFindingGenerator: SECURITY_CONTROL
```

FSBP is enabled and ready:

```text
StandardsArn: arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0
StandardsStatus: READY
StandardsControlsUpdatable: READY_FOR_UPDATES
```

Terraform plan after apply:

```text
No changes. Your infrastructure matches the configuration.
```

## Git commits

T5 was committed in one checkpoint:

```text
infra: add security hub fsbp
```

## Invariants

- Security Hub is Terraform-managed. No standards are enabled from the console; anything new is defined in Terraform (or imported) so the plan stays clean.
- FSBP is the only enabled standard. CIS is not enabled.
- The Config recorder stays enabled. FSBP controls evaluate against recorded configuration items, so a stopped recorder reads as "no data" rather than as a finding.
- `standards_arn` takes the standard's ARN (`arn:aws:securityhub:us-east-1::standards/...`). The subscription ARN is a different identifier; do not pass it there.

## Next step

T5 readies the environment for detection. Next in the slice: the Makefile (T6), the acceptance runsheet (T7), then the out-of-band break and observation window (T8): make a lab resource noncompliant outside the pipeline, wait for the Security Hub finding, and verify the finding shape the later automation consumes.
