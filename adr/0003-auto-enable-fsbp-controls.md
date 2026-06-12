# ADR-0003: Auto-enable new FSBP controls inside a pinned standard subscription

Status: Proposed
Date: 2026-06-12

## Context

Security Hub CSPM went live under Terraform this week (T5): `enable_default_standards = false`, the FSBP standard subscribed explicitly, consolidated control findings, and the subscription READY. AWS ships new FSBP controls on its own cadence, and one account-level switch decides whether they arrive enabled or disabled. `auto_enable_controls` governs "whether to automatically enable new controls when they are added to standards that are enabled," and it defaults to true (Terraform Registry, `aws_securityhub_account`, checked 2026-06-12).

Two prior facts shape the call. ADR-0002 pinned the CI scanner to Checkov 3.2.530 so the blocking ruleset changes only by an explicit, reviewable version bump. And the Config recorder is scoped to the two lab resource types, S3 buckets and security groups, and is recording, with object delivery observed 2026-06-12. A third bound exists in the runtime design and lands with the proposer slice: the EventBridge rule is narrowed to FAILED findings on allowlisted control IDs (BLUEPRINT.md).

The posture is live, so the call gets its record now.

## Decision

Keep `auto_enable_controls = true`, set explicitly in code rather than inherited as the provider default. New FSBP controls enable themselves as AWS ships them, inside a standard subscription that Terraform pins. Pin what blocks; let what watches widen.

The asymmetry with ADR-0002 is the point. The CI gate blocks code: a ruleset that moves on its own can start or stop failing builds with no diff to review, so its coverage changes only by deliberate change. The detective layer blocks nothing and mutates nothing, so a control it lacks costs more than a finding that surprises. The widening is bounded twice: the scoped recorder means most new controls evaluate against nothing here, and the EventBridge allowlist means a new control can surface a finding but can never reach the remediation path.

## Options considered

- **Option A (chosen): `auto_enable_controls = true`.** Pros: detection coverage tracks AWS without manual chasing; the two bounds cap the blast radius of any surprise; zero toil for a one-person lab. Cons: the live enabled-control set can exceed what the code names; new controls add checks, findings, and cost without a diff.
- **Option B: `auto_enable_controls = false`, enable each new control explicitly in Terraform.** Pros: the code fully describes the enabled posture; every widening is reviewed; reproducible from the repo alone. Cons: the posture goes stale silently, because nothing fails when AWS ships a control the account never enables, and the staleness is invisible until a missed misconfiguration makes it visible. The failure mode is the quiet one, which is the wrong failure mode for the layer whose whole job is watching.

## Consequences

Better: the detective posture tracks AWS's coverage on AWS's cadence; the runtime contract is unmoved by any widening, because the allowlist, never the detector, decides what the proposer sees; and the scoped recorder caps both the evaluation surface and the Config cost of each new control.

Worse, and now committed to: the repo alone no longer answers "which controls are enabled," the account does, which costs reproducibility-from-code for this one setting. New FAILED findings on lab resources outside the two scenarios are expected console noise, and reviewing newly enabled controls becomes a periodic chore. Cost can creep one check at a time, with the $20/month budget alarm as the backstop. Any control disabled for noise is filed as an explicit `aws_securityhub_standards_control` with its `disabled_reason` (Terraform Registry, checked 2026-06-12), so every exception carries its rationale in code. And widening the runtime allowlist stays a deliberate change with its own record, never a side effect of detection growing.
