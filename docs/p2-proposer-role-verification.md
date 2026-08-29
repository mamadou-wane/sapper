# Proposer role, verified against the plan's IAM boundary

Read from the live account on 2026-08-28 with `aws iam get-role`, `get-role-policy`,
`list-attached-role-policies`, and `list-role-policies` on `sapper-proposer`, after the last
boundary change of the P2 slice (#32). The account ID is written `<account>` here; the captures
under `evidence/` keep it on purpose, this note does not need to.

What the plan requires of this role (the engineering plan's IAM boundary section, unpublished) is
four explicit denies, an enumerated allow set, no `iam:PassRole`, and nothing else. What the role
holds:

## Shape

- One inline policy, `sapper-proposer`, nine statements. No attached managed policies. No
  permissions boundary (the boundary belongs to `sapper-remediation`, the bounded role).
- Trust: `lambda.amazonaws.com`, plus the operator's Identity Center admin role so the negative
  suite (P5) and the P1.5 probe can assume it. No other principal.

## Allows, five statements

| Statement | Action | Resource | Condition |
|---|---|---|---|
| `ReadLiveStateForTheFreshnessGate` | `s3:GetBucketPublicAccessBlock` | the lab bucket ARN | none |
| `WriteProposalsAndLocks` | `s3:PutObject` | `proposals/*`, `locks/*` on the evidence bucket | `Null s3:if-none-match = false` (the header must be present) |
| `ReadItsOwnLocks` | `s3:GetObject` | `locks/*` on the evidence bucket | none |
| `ListItsOwnPrefixes` | `s3:ListBucket` | the evidence bucket | `StringLike s3:prefix` in `proposals/*`, `locks/*`, `applied/*` |
| `WriteItsOwnLogs` | `logs:CreateLogStream`, `logs:PutLogEvents` | `log-group:/aws/lambda/sapper-proposer:*` | none |

Each maps to one line of the plan's allow set: the Gate 5 live-state read; the create-only writes;
the lock read the generation chain needs on a 412 (ruled 2026-08-26, #25); the prefix-scoped list,
widened by `applied/*` for the chain's reclamation check (ruled 2026-08-28, #27); the function's
own log group and no `logs:CreateLogGroup` (#32). The one allow-set line not present is
`sqs:SendMessage` to the on-failure destination, which P3 creates and grants.

No `s3:GetObject` on `proposals/*`, `approvals/*`, `consumed/*`, `applied/*`, or `rollback/*`: the
proposer cannot read a proposal, an approval, or a remediation record. Existence checks in the
suppressor are prefix-scoped lists on a derived key, which is what the third and fourth grants
are shaped for.

## Denies, four statements

| Statement | Action | Resource |
|---|---|---|
| `DenyTargetMutation` | `s3:PutBucketPublicAccessBlock` | `*` |
| `DenySecurityHubWrites` | `securityhub:BatchUpdateFindings`, `securityhub:BatchImportFindings` | `*` |
| `DenyApprovalForgery` | `s3:PutObject` | `approvals/*` on the evidence bucket |
| `DenyPrivilegeEscalation` | `sts:AssumeRole`, `iam:PassRole` | the `sapper-remediation` role ARN |

These are the plan's four denies, in order: target mutation, Security Hub write, approval write,
role assumption. `iam:PassRole` appears once in the policy, inside the deny, and in no allow.

## What this note is not

A read-back of a policy proves what the policy says, not what AWS does with it. The `AccessDenied`
captures that prove each deny at runtime are P5's (`make verify-boundary`, nine negative tests
with paired positive controls). The P1.5 captures under `evidence/p15/` already prove two of the
proposer's outcomes against live S3: capture 04 (an `approvals/` write refused) and capture 05 (a
`proposals/` write accepted).
