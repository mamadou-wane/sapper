# sapper

> Blocks unsafe cloud infrastructure in code, detects the misconfigurations that drift in after deploy, and remediates a narrow, reversible set only after human approval, with evidence for every action.

Cloud incidents are rarely exotic. They are public buckets, open ports, and leaked keys, introduced either by code that should have been blocked or by changes made outside the pipeline. sapper closes both gaps under one principle: *think, but never act blindly*. The pipeline blocks what it can catch, the runtime detects what slips past, and nothing mutates a resource without a human approval bound to the exact change. Every action leaves evidence, including the denied and failed ones.

> The name: a sapper is a combat engineer who clears hazards and breaches obstacles, and knows which ones are too dangerous to touch without care. "Blast radius" is the through-line.

## Status

In active development. Built and verified so far:

- **Phase 0 de-risking, complete.** The live Security Hub contract confirmed (CSPM classic, ASFF), the control IDs observed for both lab scenarios (S3.8, EC2.18/19), finding latency recorded, a finding-triggered EventBridge event captured as a fixture, and a $20/month budget guardrail set before any billing service went live. The record is [`SPIKE_NOTES.md`](./SPIKE_NOTES.md).
- **The Phase 1 Terraform foundation.** Remote state on S3 with native locking configured, a pinned provider, uniform default tags, and a compliant lab bucket, all defined in code. The first deploy, with the detective services and the state-lock demonstration, lands this week.
- **The CI gate.** terraform fmt, offline init/validate, and Checkov on every push, with no AWS credentials or backend access in CI, proven by a deliberate failing push restored to green.

Everything else on this page is the design, sequenced in [`BUILD_PLAN.md`](./BUILD_PLAN.md).

## Demo

_Lands with Phase 1: a short GIF of `make demo` and a two-to-three-minute walkthrough._

## What it does

The shift-left layer catches problems before deploy. Every change to the Terraform runs through Gitleaks (secrets), TFLint (lint), and Checkov (IaC security) in CI, and the findings flow into a single severity-aware gate: high-severity fails the build, low-severity warns, because failing on noise is how teams learn to ignore the gate.

The runtime layer handles what gets past the pipeline, after deploy. For the misconfigurations that bypass it (console changes, drift, resources created elsewhere), Security Hub findings route through EventBridge to a Lambda that detects and proposes a fix, captures before-state, and stops. That Lambda holds no permission to mutate any target resource: no Security Hub write, no approval write, no remediation action; it can only read, and write its own proposal and evidence records. A human approves, and a separate step, running as a bounded least-privilege role, re-checks the resource, applies the reversible fix, and captures after-state. Two scenarios: flip a public S3 bucket private, and revoke an over-permissive security-group rule.

## Architecture

Shift-left (CI). This is the target state; the live gate today is fmt, validate, and Checkov with zero AWS access (see Status):

```
commit  (Gitleaks runs locally via pre-commit for fast feedback)
  └─ GitHub Actions  (OIDC → least-privilege AWS role · Phase 2; CI currently holds no AWS credentials)
       ├─ Gitleaks: secret scanning (server-side, the enforcement gate)
       ├─ TFLint: Terraform linting
       ├─ Checkov: Terraform security scanning
       └─ OPA/Conftest: organization-specific policy-as-code  (planned · v1.1)
            └─ Severity gate → pass / warn / fail  +  committed evidence
```

Runtime (detect and propose, then approve, then remediate):

```
drift  →  Security Hub finding  →  EventBridge  →  Lambda (detect-and-propose)
                       (rule narrowed to FAILED        │  (read + write-evidence only; no Security Hub write,
                        + the allowed control IDs)     │   no approval write, no remediation permission)
                                                       ├─ dedupe: open-proposal suppressor  (app-side;
                                                       │   finding ID + UpdatedAt distinguishes recurrence)
                                                       ├─ capture before-state
                                                       ├─ write dry-run plan + proposal record ──▶ STOP
                                                       └─ on handler failure: retries → SQS DLQ + alarm
                                                                │                      (no silent drops)
                                  human approval  (CLI writes a separate approval record:
                                  human principal only, create-only, immutable once written)
                                                                │
                                      remediation step  (separate invocation; assumes the bounded role)
                                      ├─ verify approval + plan-hash binding
                                      ├─ re-check current state (no TOCTOU)
                                      ├─ apply reversible fix  (bounded role + permissions boundary)
                                      ├─ capture after-state → verify → evidence
                                      └─ optional, off by default: mark finding RESOLVED
                                         (Security Hub auto-resolves on a compliant eval)
```

## The design decisions that matter

A few choices carry this project; full rationale is in [`BLUEPRINT.md`](./BLUEPRINT.md) and the [ADRs](./adr):

- The proposer detects and proposes, and it never remediates. A Lambda can't pause for human approval (stateless, 15-minute cap), so approval becomes a state transition between two invocations: the proposer writes a plan and stops, then a separate approved step acts. The proposer can only read and write its own proposal and evidence records: no Security Hub write, no approval write, no remediation permission. The two remediation actions live only in a separate role the approved step assumes.
- The remediation role's blast radius is bounded, and the bound is demonstrated three times. The role can perform only the two scoped, reversible actions, capped by a permissions boundary, with tag-write denied so its scope can't be widened by a retag. The S3 action is scoped by explicit bucket ARN (S3 bucket-level tag authorization needs per-bucket ABAC, so an ARN scope is the dependable choice); the SG action is scoped to the lab security group(s). Three negative IAM tests (`make verify-boundary`) prove the three boundary claims: the remediation role attempting a forbidden action, the proposer attempting a mutation, and the proposer attempting an approval write. Each captured `AccessDenied` is committed as evidence, which turns the bounds from written claims into demonstrated ones.
- The human gate can't be forged. The proposer writes only a proposal record; the approval record is writable only by the human principal (enforced by bucket policy) and is create-only, made immutable once written by an S3 conditional-write condition in that policy. It is bound to the finding, the resource, and a hash of the dry-run plan, so a compromised proposer can't approve itself and a stale approval can't authorize a different change. Provenance is enforced by policy and verified at apply time by the binding.
- Failures leave evidence too. A handler failure exhausts its retries into a dead-letter queue and trips an alarm rather than vanishing, and the evidence store is versioned with deletes denied to the runtime roles, so neither a crash nor a compromised proposer can quietly lose a finding or rewrite history.
- Evidence-first, and adversarial. Every workflow produces an artifact. The guardrails are proven by making them fail on purpose: a planted secret blocked, insecure Terraform rejected. A clean pass proves nothing on its own. One blind spot the scanners miss is documented honestly, and at least one Security Hub finding runs the full path end-to-end, from the production source to committed evidence.

## Results

_Populated from measured runs as phases land. The safe-failure row is the project's one documented engineering improvement: a baseline captured before hardening, re-measured after, against a failure-mode set pre-registered in [`EVIDENCE.md`](./EVIDENCE.md)._

| Measure | Value |
|---|---|
| Security Hub controls monitored | _TBD_ |
| CI gate outcomes (blocked / warned) | _TBD_ |
| Mean time to remediate, lab (excl. approval pause) | _TBD_ |
| Safe-failure coverage (baseline to after) | _TBD_ |

## Run it

The target workflow; targets land with their phases (see [`BUILD_PLAN.md`](./BUILD_PLAN.md)).

```bash
make setup       # prerequisites + remote-state backend
make deploy      # stand up the lab + the detect-and-propose pipeline
                 # (incl. Security Hub / Config under Terraform, the DLQ, and alarms)

# Simulate drift: make a lab bucket public out-of-band. The detect-and-propose
# Lambda captures before-state, writes a dry-run plan + proposal record, and
# STOPS. It holds no permission to mutate the resource.
#
# Review the plan, then approve as your human principal via the approval CLI
# (cli/approve.py): it writes the human-only, create-only approval record;
# the proposer can't.

make remediate        # assumes the bounded role, re-validates state, applies the
                      # reversible fix, captures after-state, and verifies
make verify-boundary  # run the three negative IAM tests; capture the denials as evidence
make destroy          # tear down lab resources AND disable the detective services
```

**Prerequisites:** an AWS account with SSO and Terraform; the GitHub OIDC role arrives with Phase 2.
**Cost:** runs on AWS Free Tier where possible; Security Hub and Config bill continuously while enabled, so `make destroy` turns them off. See [`COST.md`](./COST.md).

> `make demo` runs that whole flow, detect → propose → approve → remediate → verify, against a representative event for speed, so a reviewer sees a finding gated and remediated in one command. Security Hub findings can take minutes to hours to appear, and a synthetic event can't impersonate the production source (`PutEvents` cannot publish events with an `aws.*` source; AWS reserves that prefix). So the demo enters through a demo-only twin EventBridge rule on a custom source (`sapper.demo`), carrying the identical payload to the identical handler. Every evidence record is labeled REAL or DEMO, the measured finding latency is documented, and at least one finding from the production source is banked end-to-end as evidence that the path works. Reviewers who won't stand up their own account can follow the recording and the committed evidence artifacts.

## Threat model and limitations

This is a single-account lab, well short of a production system. It runs in a dedicated lab account: the account ID and bucket names are visible in code and evidence by design. They are identifiers rather than credentials, and treating them as such is part of the model. The runtime layer exists because prevention is never complete: resources drift via clickops, emergencies, and out-of-band changes. The threat model treats four runtime escalation paths as first-class: approval forgery, evidence tampering (a compromised proposer rewriting its own history), scope-widening by retag, and the remediation running as admin instead of the bounded role, each closed by design. One honest scope note: the bounded-blast-radius property is a property of the remediation function's *identity*; the account, operated by an admin SSO identity, is the wider trust boundary. Full model in [`THREAT_MODEL.md`](./THREAT_MODEL.md); the honest distance to production is in [`PRODUCTION_GAP.md`](./PRODUCTION_GAP.md).

## What I'd do next

Policy-as-code (OPA/Conftest) is in the design and sequenced after v1, at the severity-gate seam. Later: Step Functions or SSM Automation `aws:approve` for formal approval, an AWS Config comparison path, a CSPM sliver (a toxic-combination rule), and tightly gated conditional auto-remediation.

## Docs

[`BLUEPRINT.md`](./BLUEPRINT.md) (design) · [`BUILD_PLAN.md`](./BUILD_PLAN.md) (phased delivery) · [`SECURITY_PIPELINE.md`](./SECURITY_PIPELINE.md) · [`REMEDIATION.md`](./REMEDIATION.md) · [`EVIDENCE.md`](./EVIDENCE.md) · [`THREAT_MODEL.md`](./THREAT_MODEL.md) · [`PRODUCTION_GAP.md`](./PRODUCTION_GAP.md) · [`COST.md`](./COST.md) · [`SPIKE_NOTES.md`](./SPIKE_NOTES.md) · [ADRs](./adr)

## About

Built by Mamadou Wane, Marine Corps veteran (combat engineer) and CS student at WGU, graduating December 2026. sapper is the first of two decoupled projects that share one thesis: define the blast radius, prove the system fails safe, and measure whether it does. The second applies the thesis to reliability under controlled fault injection. Two narrow builds taken deep, instead of one sprawling platform; the scope-down is deliberate.

[github.com/mamadou-wane](https://github.com/mamadou-wane) · [mamadouwane.com](https://mamadouwane.com) · [linkedin.com/in/mamadouswane](https://linkedin.com/in/mamadouswane)

