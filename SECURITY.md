# Security policy

sapper is a security lab. Reports about its own code are welcome and get read carefully.

## Scope

In scope: the Terraform in this repo, the CI pipeline, and any application code that lands
with the control loop. Out of scope: AWS service behavior (report that to AWS), and the lab
bucket in `terraform/lab.tf`, which is deliberately minimal because drifting it is the point
of the project.

## Reporting

Use GitHub's private vulnerability reporting: the Security tab, then "Report a vulnerability".
Do not open a public issue for a vulnerability.

Include reproduction steps or captured output, and state whether AI tooling generated the
report. Reports without verifiable evidence are closed.

This is a one-person project. Expect an acknowledgment within 7 days.
