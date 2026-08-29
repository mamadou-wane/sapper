# ADR-0002: Use inline, resource-scoped Checkov suppressions

Status: Accepted
Date: 2026-06-11
Related runbook: `docs/aws-config-runbook.md`

## Context

CI runs Checkov against `terraform/` on every push. After T4 added the AWS Config substrate, the gate failed on controls that are out of scope for the Phase 1 lab: six S3 controls on the Config delivery bucket and the lab target bucket (CKV_AWS_18 access logging, CKV_AWS_21 versioning, CKV_AWS_144 cross-region replication, CKV_AWS_145 KMS encryption, CKV2_AWS_61 lifecycle policy, CKV2_AWS_62 event notifications), and the recorder-scope graph controls CKV2_AWS_45 and CKV2_AWS_48 on the recorder and its status resource.

The flagged resources are out of scope by design. The delivery bucket holds temporary AWS Config output and is force-destroyed at teardown. The target bucket is a minimal detection target holding no durable data. The recorder is scoped to two resource types as the Phase 1 cost guard.

The first fix was a global `skip_check` list in `.github/workflows/ci.yml`. CI went green. The list applies to every resource in the repository, current and future, and the planned evidence bucket (specified in `PLAN.md` §8 as versioned, SSE, Block Public Access) needs several of the controls being skipped. The workflow also ran Checkov through the mutable `bridgecrewio/checkov-action@master` tag, so the rule set could change between runs with no change in the repo. Phase 1 puts more resources behind this gate (the evidence bucket, IAM roles, EventBridge, the Lambda), so the exemption mechanism had to be settled now.

[Citation corrected 2026-08-25: this paragraph cited `BUILD_PLAN.md`, a working plan document that was never committed to this repo and was retired and superseded by `PLAN.md` on 2026-07-24. A reader following the citation finds nothing. The evidence-bucket specification it meant is `PLAN.md` §8, the project's engineering plan, which is not published.]

## Decision

Suppressions are declared inline on the exact Terraform resource they apply to, each with a written reason:

```
#checkov:skip=<CHECK_ID>: <reason>
```

The global `skip_check` list is removed. The workflow installs a pinned Checkov CLI (`pipx install checkov==3.2.530`) in place of the mutable action tag and runs `checkov -d terraform --skip-path terraform/bootstrap`. The single path exclusion covers `terraform/bootstrap`, which creates the remote-state foundation and sits outside the runtime lab guardrail surface.

A suppression is acceptable only when all four hold: it is tied to one specific resource, it carries a written reason, the reason matches the project threat model, and it leaves the scanner active for future resources.

### Addendum, 2026-06-12: the interpreter is part of the pin

A pinned Checkov version is necessary but not enough for a reproducible scan. The same `checkov==3.2.530` gives different results across Python interpreters. Under 3.14 the graph framework fails to load and the scan silently degrades to 26 passed / 0 skipped with no warning; under 3.12 it runs fully, 37 passed / 14 skipped, every suppression honored. CI was correct throughout, because the runner image ships 3.12. The degraded path was the local pre-apply check, where the graph-level controls (the `CKV2_*` checks, which include the recorder-scope suppressions this ADR turns on) were the ones that vanished.

Invariant: local scans run under Python 3.12 to match CI, and parity is confirmed by the summary line matching, not the version string alone. A green result with `Skipped checks: 0` is the tell that the graph framework didn't load, since this repo has standing suppressions; that anomaly is what surfaced the gap, not an error message.

Annotation count: 15 suppressions are filed, 14 consumed. The second `CKV2_AWS_45` on the recorder-status resource is dormant by design and kept deliberately, so the expected steady-state is 14 skipped, and a run reporting 15 or 13 is itself a signal.

## Options considered

- Option A: bring the lab resources into compliance. Pros: no suppressions; clean gate output. Cons: versioning, replication, KMS, access logging, and lifecycle rules on buckets that hold temporary or demonstration data add cost and Terraform surface while protecting nothing; recording all Config resource types breaks the Phase 1 cost guard. Rejected: these controls protect durable data, and these resources hold none.

- Option B: global `skip_check` list in the workflow (tried first). Pros: a one-line change; CI green immediately. Cons: exempts every resource in the repository from the listed checks, with no reason attached anywhere; the evidence bucket would silently inherit waivers for the exact controls it must pass. Rejected after one iteration: the gate could no longer fail on those checks, which is the same as having no gate for them.

- Option C: inline, resource-scoped suppressions with a pinned CLI (chosen). Pros: the gate keeps evaluating everything built after this; each exemption sits in the diff next to the resource it excuses, with its reason, where review can challenge it; scan results are deterministic between runs. Cons: skip comments add noise, and the six S3 lines repeat on both lab buckets; reasons can go stale; new Checkov checks arrive only with a deliberate version bump.

## Consequences

The gate stays active for Phase 1 and beyond. The evidence bucket will be evaluated against versioning, encryption, logging, and lifecycle controls, which matches its build spec (see the 2026-08-25 addendum). Every future exemption is a visible, reasoned diff line judged against the four-condition test.

What gets worse: the lab resources carry suppression comments, duplicated across the two buckets because each exemption must sit on its own resource. Suppressions can rot; if a resource's purpose changes (a bucket starts holding durable data), nothing automated flags the stale skips, so catching that is a code-review job. Pinning trades freshness for determinism: the gate's coverage ages between version bumps, and bumping Checkov is now a deliberate, owned change. The `terraform/bootstrap` exclusion remains a blanket exemption, so that directory must stay limited to the remote-state foundation or it becomes the next blind spot.

We are now committed to: a written reason on every suppression, judged against the four conditions; shipping the evidence bucket compliant rather than suppressed; and treating Checkov version bumps as explicit changes with their own review.

The middle commitment is superseded for the evidence bucket's five ruled skips. See the 2026-08-25 addendum for which controls, and why each one was judged wrong for this bucket rather than merely inconvenient.

### Addendum, 2026-08-25: the evidence bucket ships suppressed on five checks

P1.5 built the evidence bucket (`terraform/boundary/evidence.tf`) and the commitment above did not
survive it. "Shipping the evidence bucket compliant rather than suppressed" assumed that holding
durable data was reason enough to earn every control this ADR's Context section named as blocked on
the disposable lab buckets. It was not examined against what this particular bucket is: a
permanent, append-only evidence store whose tamper-evidence comes from the bucket policy's delete
and reconfiguration denies (`terraform/boundary/bucket-policy.tf`), not from encryption strength,
replication, access logging, or event notifications.

One of the five is worse than merely unnecessary: `CKV2_AWS_61` wants a lifecycle rule, and a
lifecycle rule expires objects. This store exists to keep records forever. A lifecycle rule would
delete the evidence it is built to hold, so compliance and purpose point opposite directions here,
and purpose wins.

The evidence bucket carries five inline suppressions, each resource-scoped with a written reason
and judged against the four-condition test in the Decision section above. That test was cited here
as "Option C's" until 2026-08-25; Option C is the option that was chosen, but the test itself is
stated in Decision, which is where a reader has to go to check the judgement:

- `CKV_AWS_144` (cross-region replication): single-region lab evidence store, out of scope for R1.
- `CKV_AWS_145` (KMS encryption): SSE-S3 is the R1 choice; tamper-evidence rests on the bucket
  policy's delete denies, not on encryption strength, and KMS adds per-request cost with no
  threat-model benefit here.
- `CKV_AWS_18` (access logging): deferred; the CloudTrail S3 data-event selector built in P3 is the
  audit surface for this bucket.
- `CKV2_AWS_62` (event notifications): arrive in P4, when the remediator subscribes to `approvals/`.
- `CKV2_AWS_61` (lifecycle policy): none, on purpose, for the reason above.

Annotation count, re-baselined: 20 suppressions are filed, 19 consumed, the dormant `CKV2_AWS_45`
unchanged from the 2026-06-12 addendum. The expected steady-state is 19 skipped; a run reporting 20
or 18 is now the signal, in place of the 15/13 pair that addendum named. The 15/14 figures were
right for the resources that existed on 2026-06-12. What moved them is the evidence bucket's five
skips, not an error in the earlier count.


### Addendum, 2026-08-28: the proposer function ships suppressed on seven checks

P2 built the proposer Lambda and its log group in `terraform/proposer.tf`. Seven checks are
suppressed inline, each judged against the four-condition test in Decision, and one is met
rather than suppressed:

- `CKV_AWS_50` (X-Ray tracing): out of scope for a single-function lab; the structured line the
  handler writes per finding is the trace.
- `CKV_AWS_116` (dead-letter queue): the failure path is an async on-failure destination, an
  event-invoke config rather than a `dead_letter_config`, and it lands in P3 (`PLAN.md` §9).
- `CKV_AWS_117` (VPC): the function reaches S3 only; the lab has no VPC resources.
- `CKV_AWS_173` (environment-variable KMS key): the environment carries a bucket name, a bucket
  ARN, and two integers.
- `CKV_AWS_272` (code signing): out of scope for a lab deployed from a pinned, locally built tree.
- `CKV_AWS_158` (log-group KMS key): the logs carry finding ids, drop reasons, and the PROVENANCE
  metric line, no secrets.
- `CKV_AWS_338` (one-year log retention): 30 days, ruled 2026-08-28; the stack is torn down
  between evidence windows and the banked evidence lives in the repo.

`CKV_AWS_115` (function-level concurrency limit) is satisfied by `reserved_concurrent_executions`
rather than suppressed, ruled 2026-08-28: a concurrency cap is a real blast-radius control on a rule
that fires per finding, and a suppression would have hidden the absence of one.

Annotation count, re-baselined from the scan: 27 suppressions are filed, 26 consumed, the dormant
`CKV2_AWS_45` unchanged. The expected steady-state is 26 skipped (181 passed, 0 failed on
2026-08-28); a run reporting 27 or 25 is now the signal, in place of the 20/18 pair the 2026-08-25
addendum named.
