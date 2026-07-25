# Cost

Every number here is an observed measurement from this lab account. None of it is a production
estimate or a pricing guarantee.

## Posture on 2026-07-24

| Measure | Value |
|---|---|
| Month-to-date AWS spend | $0.71 |
| Security Hub CSPM checks, current billing period | 176 |
| Security Hub cost anomaly, flagged | $0.04 |
| Budget threshold | $20/month |

The anomaly detector flagged Security Hub at a large percentage because the expected baseline was a
few cents. Absolute impact: four cents. It is recorded here because an anomaly dismissed without a
written reason is how a real one gets dismissed later.

Security Hub's 30-day free trial has expired on this account. Measurements taken during that
window are not comparable to current billing and are not reused. R1's cost figures come from the
final evidence window, under post-trial pricing.

## Controls

**AWS Budgets** at 85% actual, 100% actual, and 100% forecast. Created 2026-06-07, still
console-managed. Moving it into Terraform needs `terraform import`, since the budget already
exists and a fresh apply would collide with it.

**AWS Cost Anomaly Detection** watches for service-level increases.

**Scoped Config recorder.** The recorder is limited to `AWS::S3::Bucket` and
`AWS::EC2::SecurityGroup`. Config bills per configuration item recorded, which makes recorder scope
the most effective cost control in the project. It is enforced in Terraform rather than by
remembering to check.

**Teardown discipline.** Security Hub, Config, and Lambda logging are torn down when idle. The lab
ships compliant and is broken deliberately, only inside an evidence window.

**Two evidence windows.** Continuous uptime is never required. Window A, during the boundary
spike, needs S3 and IAM only, so the detective stack stays off. Window B runs the full stack once, after the
remediation path is code-complete.

## Limits of these controls

AWS Budgets and Cost Anomaly Detection notify. Neither can stop a charge. Both report after the
fact.

Billing data lags and refreshes a few times a day, so a same-day reading misses the current hour.
A post-teardown cost check taken immediately reads stale data, which is why the teardown reading
happens at T+48h.

Cost Explorer's API bills per request.

These are lab measurements at lab volume. They say nothing about what this architecture costs at
production scale.

## What teardown actually claims

The phrase "teardown verified to zero residue" does not appear in this project. `make destroy`
returns the detective services and lab resources to zero ongoing cost. Several things survive on
purpose: the Terraform state bucket, the evidence bucket, and the budget. Others survive because
AWS retains them. Security Hub keeps findings for 90 days after the service is disabled, and
auto-created Lambda log groups are not Terraform resources, so they persist until deleted.

The evidence for teardown is a scripted residue sweep plus a T+48h cost reading. An assertion of
zero is not evidence.
