# Production gap

What sapper does not do, and what it would take to run it for real. This file exists so scope
decisions stay visible instead of being implied by absence. Nothing here is a completion
requirement for Release 1.

## Reproducibility

The Terraform backend bucket is hardcoded, and the lab bucket name embeds this account's ID, so
`make deploy` will not run from a clean clone in another account. Closing it means moving the
backend to `-backend-config`, deriving resource names from `data.aws_caller_identity.current` plus
a suffix, and writing a reproduction guide.

Captured evidence under `evidence/` keeps the original account ID and resource names. Those files
are records of what ran. Editing them to look account-neutral would make them tidier and worthless.

## Shift-left gate

Running today: `terraform fmt -check`, offline `terraform validate`, and Checkov pinned to
`3.2.530` under Python 3.12, each step's exit code gating the push. Any failed Checkov check fails
the build.

Not built: secret scanning, Terraform linting, and a severity-aware gate that consolidates several
scanners into one auditable decision artifact. Open-source Checkov cannot filter by severity
without a Prisma Cloud API key, so this project does not claim severity-gated builds.

## Second remediation scenario

Release 1 remediates one control: S3.8, public bucket access. The security-group scenario
(EC2.18 and EC2.19) is designed and deferred. Adding it is a parser path, an IAM policy statement,
and a remediation module. The parser is specced to handle full-ARN resource IDs, which is the form
security groups arrive in; that path and its unit tests land with the proposer (P2). Nothing is
built or tested yet.

Two things to get right when it is built, recorded now so they are not rediscovered the hard way.

In a default VPC, `RevokeSecurityGroupIngress` returns success with the rule still in place when
the specified values do not exactly match the existing rule. It populates `unknownIpPermissionSet`
rather than raising. A naive implementation writes a green "remediated" record for a change that
never happened. Capture `SecurityGroupRuleId` in before-state, revoke by rule ID, assert
`unknownIpPermissionSet` is empty, and re-read state before declaring success.

EC2.18 and EC2.19 do not always imply the same revocation set. Treating them as one action can
apply a subset and leave the group open while the evidence reads clean. The suppressor's action
token has to encode the specific revocation set rather than the control pair.

## Synthetic demo path

A demo-twin EventBridge rule on a custom source (`sapper.demo`) is designed and deferred. It is
needed because `PutEvents` cannot publish events with an `aws.*` source, so a demo cannot drive the
production rule synthetically. The design keeps REAL and DEMO provenance derived from the event
source rather than asserted by the record. Release 1 takes its evidence from a real finding.

## AI advisory (Release 2)

A queue-driven Bedrock worker that reads validated proposal records and produces advisory records
only, off the authorization path, with a pre-registered evaluation set and a safety metric gating
release. Designed. Unbuilt.

Three facts verified against AWS documentation on 2026-07-24, each of which contradicted an earlier
draft of the design:

Invoking a model with a guardrail attached requires `bedrock:ApplyGuardrail` on the guardrail ARN
alongside `bedrock:InvokeModel` on the model. A policy omitting it fails every guarded call.

Content qualified as `grounding_source` is excluded from all other guardrail policy evaluations,
including prompt-attack detection. Passing untrusted text as grounding source and expecting the
injection filter to inspect it inspects nothing. The qualifier list must include `guard_content`
for the other policies to run.

A contextual grounding check needs three components: grounding source, query, and the content to
guard. Without a query the check does not run at all.

Also deferred with it: splitting the evaluation runner into a credential-free replay mode for every
push and a live mode for tagged releases, since a stochastic system cannot gate CI on a single
sample per case.

## Kubernetes platform proof (Release 3)

Deploying the advisory worker to EKS under pod-scoped identity. Designed and unbuilt. Cut unless
the earlier releases finish with room to spare.

The minimum version worth having: EKS Pod Identity association with a dedicated ServiceAccount, the
node IMDS hop limit pinned so a pod cannot reach the node's credentials, `sts:GetCallerIdentity`
from inside the pod returning the workload identity, one captured denial for an action outside the
workload policy, and verified teardown. Pod Identity requires adding a trust-policy statement to
the role, so what stays unchanged is the role's permission policy.

## Operational scope

Out of scope: multi-account and AWS Organizations architecture, chat-based approval routing, broad
auto-remediation, automated approvals, and a large remediation catalog. sapper remediates a narrow
reversible set behind a human decision. Widening that set is a different project with a different
threat model.

## Threat model boundary

This section holds the threat model until P5 proves the boundary at runtime, at which point it
moves to `THREAT_MODEL.md` and documents an enforced bound rather than an intended one.

The separation sapper proves is between the proposer identity and the remediation identity. The
proposer can reason and record. It holds no permission to mutate a target, write an approval, write
to Security Hub, or assume the remediation role, and each of those is an explicit deny backed by a
captured `AccessDenied`.

Two principals sit outside that bound and are trusted:

The deployment role creates both runtime identities, so an attacker holding it does not need to
defeat the separation.

The account administrator can alter the evidence store. The store is tamper-evident against the
runtime roles, which hold no delete, lifecycle, versioning, or bucket-policy permission. It is not
immutable.

That tamper-evidence claim splits by blast radius. The two delete denies apply to every principal
except the admin, which is what makes it hold. The eight bucket-configuration denies
(`s3:PutBucketPolicy`, `s3:DeleteBucketPolicy`, `s3:PutBucketVersioning`,
`s3:PutLifecycleConfiguration`, `s3:PutReplicationConfiguration`, `s3:PutBucketAcl`,
`s3:PutEncryptionConfiguration`, `s3:PutBucketPublicAccessBlock`) are scoped to the four named roles
instead: a uniform deny with no named principals would have made the bucket's own policy permanently
unmodifiable, since the evidence bucket is created once and never recreated. The residual: those
eight denies do not bind a future principal that gains an identity-based allow to reconfigure the
bucket, only the roles named today. Accepted in exchange for a bucket whose policy stays modifiable
by Terraform, the operator, and root.

The proposer and remediator execution roles also trust the operator's admin principal, not only
`lambda.amazonaws.com`. That widening exists so the boundary probes and the negative suite can run:
a negative test can only prove a role is denied by acting as that role, and there is no other
principal available to assume it from a terminal. The consequence: an administrator can chain
through the remediator's execution role into the bounded role and mutate a target with no approval
written. That adds a path to a case already declared out of scope above; the bound this project
proves stays intact, since the approval role still holds no mutating permission and no path to the
bounded role, so the designed path is unchanged. What the widening buys is that every captured
`AccessDenied` in this repo is reproducible by a reader running the same commands against the same
account, rather than requiring a throwaway Lambda deployment per test.

The approval role holds no mutating permission on any target and cannot assume the bounded role.
The bounded role trusts only the remediator function's execution role, so writing an approval
object is the only path to an apply. That is enforced in IAM rather than in CLI code, and P5 proves
it with captured denials for the approval role attempting the fix directly and attempting to assume
the bounded role.

The account administrator sits outside all of it. In this lab the same person holds both the
approval role and an administrative role, and an administrator can mutate a target directly,
rewrite the bounded role's trust policy, or replace the remediator's code. No design closes that
from inside the account. What the design closes is the path the system itself takes: it cannot
apply a change without an approval object, and no principal on that path can both write an approval
and mutate a target. Separating the approver from the administrator is an organizational control,
and it is the first thing a production deployment would add.

Applying a fix is a single point of commitment: writing the approval object triggers the apply,
with no second confirmation. The mitigation is reversibility rather than another gate. The
before-state is captured, hashed, and bound into the approval, and a rollback path restores it and
records the restore as evidence. A second confirmation prompt was considered and rejected: same
person, same session, same information, seconds apart. Two-person approval is the control that
would provide a genuinely independent second look, and it is out of scope for a single-operator
project.



Supply-chain compromise of the scanners is out of scope.
