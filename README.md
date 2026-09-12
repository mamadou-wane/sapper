# sapper

> A cloud security lab with a CI guardrail, live detection and approval-boundary evidence, and a code-complete proposer. The full human-approved remediation loop remains incomplete.

Misconfigurations can enter through infrastructure code or changes made outside the pipeline.
sapper combines a CI gate with a runtime design for detecting drift, proposing an exact change,
and requiring human approval before a bounded remediation. Release 1 targets the S3.8 public-bucket
scenario; the approval CLI and remediation are not yet implemented.

A sapper is a combat engineer who clears hazards and breaches obstacles, but knows which ones are too dangerous to touch without care.

## Current Status

**Status 2026-09-12: Release 1 (Security Core) is incomplete; development is currently paused.**
The detection foundation and the P1.5 approval-boundary spike have historical live AWS evidence.
The proposer (P2) is code-complete with unit/moto tests and Terraform wiring, but its live
finding-to-PENDING run remains unproven. No resumption date is set.

- De-risked the live Security Hub contract with real findings (S3.8/S3.9 for public buckets, EC2.18/EC2.19 for open security groups).
- Built the detective layer in Terraform (scoped AWS Config recorder + Security Hub with FSBP standard).
- Set up CI/CD in GitHub Actions with pinned Checkov, terraform fmt/validate, and a deliberate failing push to prove the gate works.
- Proved detection in the lab: intentionally created drift, captured real findings, measured latency, and rolled back cleanly with full evidence.
- Proved the approval boundary live (P1.5): a durable Deny-only evidence bucket, four scoped roles, and sixteen acceptance tests banked under `evidence/p15/`, each capture naming the principal that produced it.

**Planned and incomplete:** records/integrity infrastructure, including failure handling, alarms,
and CloudTrail data events (P3); the approval CLI, remediation, and rollback (P4); the full negative
IAM suite (P5); and end-to-end live validation, release evidence, and reproducibility work (P6).

The boundary spike ran against live AWS on 2026-08-25 and the captures are banked. The approver
wrote an approval once and a rewrite of the same key returned `412`. A write without the
conditional header returned `403` from the bucket policy itself, proven by an admin control pair,
since the admin held unconditional `s3:*` and its denial could only come from the bucket. The
proposer's write to the approval prefix was denied while a positive control showed the same
credential succeeding in its own prefix, and `make destroy` removed the detective stack while the
evidence bucket and all four roles survived. Those pairings matter: a denial only proves a
boundary if the same credential succeeds somewhere it should.

Mocked AWS cannot evaluate bucket policies, which is why this proof ran first and ran live.

The proposer landed 2026-08-28 in a series of small PRs (#20 through #33): an ASFF parser that is
the one place raw findings are read, a gate chain that drops with a named reason and makes one
AWS call last, a suppressor whose lock is a chain of create-only generations so a crashed
invocation can be reclaimed without a race, a proposal record the approver later signs, a
PROVENANCE metric emitted through the function's own logs, and Terraform definitions for the
function and its EventBridge target. The [P2 closeout](https://github.com/mamadou-wane/sapper/pull/34)
records 113 passing tests plus formatting, validation, and scanner checks. The proposer role's
2026-08-28 live policy read-back is documented in
[docs/p2-proposer-role-verification.md](./docs/p2-proposer-role-verification.md). It records the
role's permissions at that date.

## Architecture (Release 1)

Two layers, with implementation and evidence at different stages.

**Shift-left (CI) · implemented**

`terraform fmt`, offline `validate`, and pinned Checkov run on pull requests and pushes to `main`.
Any failed Checkov check fails the build. No AWS credentials in CI. Severity-aware gating, secret
scanning, and Terraform linting are future work: open-source Checkov cannot filter by severity without a commercial API
key, so this project does not claim severity-gated builds.

**Runtime (Detect → Propose → Approve → Remediate)**  
Detection was proven in the lab. The detective stack was torn down on 2026-08-25, as recorded in
the [P1.5 teardown proof](./evidence/p15/README.md#teardown-proof-at-1); this README does not claim
an active deployment. Terraform defines the Security Hub finding rule
(`sapper-securityhub-findings`) and its proposer Lambda target. That wiring is implemented;
live delivery to the proposer remains unproven.

The proposer gates findings and writes an immutable PENDING proposal with a dry-run plan and its
hash. The remaining loop is planned: a human approval CLI bound to that hash, and a remediator
that uses the existing bounded role to apply the reversible fix and capture before/after evidence.

P1.5 proved create-only approval writes and refusal of proposer approval forgery against live AWS,
with paired positive controls. The proposer role's explicit denies were subsequently read back
from AWS. The existing captures establish the tested boundaries. The full P5 runtime denial
suite and end-to-end approval/remediation proof remain incomplete.

## Results from the Lab

- [Real S3.8 detection evidence](./evidence/t8-detection/README.md): about 2m20s from completed drift to Security Hub's first observation in the recorded run. This measures detection, not delivery to the proposer or remediation latency.
- CI gate proven with a deliberate failing push restored to green.
- Interpreter-parity check added after discovering pinned Checkov returned fewer checks under Python 3.14.
- Scoped resources + budget alarm set before anything that bills continuously was enabled.

## Run It

Requires Terraform, the AWS CLI with credentials, and Python 3.12 (Checkov's graph framework only
loads under 3.12; see [ADR-0002](./adr/0002-inline-checkov-suppressions.md)).

The remote state backend is hardcoded to a bucket in the author's account, so `make deploy` will
not work from a clean clone yet. What does work from a clean clone:

```bash
make setup-scan   # create the pinned Python 3.12 venv used by the scanner
make fmt          # terraform fmt -check (matches CI)
make validate     # offline terraform validate (no AWS credentials needed)
make scan         # Checkov guardrail scan (parity-locked to CI)
make setup-test   # create the Python 3.12 venv with sapper and its dev dependencies
make test         # pytest, ruff, and mypy (parity-locked to CI)
make package      # build the proposer deployment tree from the pinned set
make help         # every target, and which ones are not built yet
```

With AWS credentials and the backend pointed at your own bucket:

```bash
make plan         # terraform plan (builds the proposer package first)
make deploy       # stand up lab + detective stack + proposer (packages and scans first)
make destroy      # tear down lab + detective services (guarded; never touches state)
```

`make remediate`, `make rollback`, `make verify-boundary`, and `make demo` are honest stubs that
print what they will do. `make help` labels them `[NOT BUILT]`.

## Docs

- [ADRs](./adr)
- [Evidence](./evidence)
- [Cost](./COST.md)
- [Production Gap](./PRODUCTION_GAP.md)
- [Proposer role, verified against the plan](./docs/p2-proposer-role-verification.md)
- [License](./LICENSE) (Apache-2.0)

## About

Built by Mamadou Wane, Marine Corps veteran (combat engineer) and CS student at WGU, graduating December 2026. The lab focuses on bounded permissions, captured evidence, and explicit limits on what each test proves.

[github.com/mamadou-wane](https://github.com/mamadou-wane) · [mamadouwane.com](https://mamadouwane.com) · [linkedin.com/in/mamadouswane](https://linkedin.com/in/mamadouswane)
