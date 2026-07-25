# sapper

> Blocks unsafe cloud infrastructure in code, detects misconfigurations that drift in after deploy, and only remediates a narrow, reversible set after human approval, with evidence for every action.

Public buckets, open security groups, and leaked keys usually come from code that should have been blocked or changes made outside the pipeline. sapper closes both gaps. The CI gate blocks what it can catch upfront. The runtime detects what slips past. Nothing mutates a resource without a human approving the exact change, and every step leaves evidence.

A sapper is a combat engineer who clears hazards and breaches obstacles, but knows which ones are too dangerous to touch without care.

## Current Status

**Release 1 (Security Core) is in active development.** The foundation is built and verified.

- De-risked the live Security Hub contract with real findings (S3.8/S3.9 for public buckets, EC2.18/EC2.19 for open security groups).
- Built the detective layer in Terraform (scoped AWS Config recorder + Security Hub with FSBP standard).
- Set up CI/CD in GitHub Actions with pinned Checkov, terraform fmt/validate, and a deliberate failing push to prove the gate works.
- Proved detection end-to-end: intentionally created drift, captured real findings, measured latency, and rolled back cleanly with full evidence.

Next up is a boundary spike that proves the separation of identity against live AWS, before the
proposer is built on top of it. It banks five captures, each naming the principal that produced it:
the approver writes an approval and succeeds, the approver's second write to the same key returns
`412`, a write without the conditional header returns `403` from the bucket policy, the proposer's
write to the approval prefix returns `403 AccessDenied`, and a positive control shows the proposer
can still write its own prefix. That last one matters: a denial only proves a boundary if the same
credential succeeds somewhere it should.

Mocked AWS cannot evaluate bucket policies, so this proof has to run against live AWS and it comes
first. Then the proposer Lambda, the records and integrity layer, the approval CLI and bounded
remediation role, and the negative IAM suite.

## Releases

sapper is one project delivered as three releases, each shippable on its own.

- **Release 1 – Security Core** (in progress): Detect unsafe changes in CI and after deploy, then remediate only after human approval with full evidence.
- **Release 2 – AI Advisory** (designed): A Bedrock worker that reasons about findings from outside the authorization path. It can advise but cannot act.
- **Release 3 – EKS Platform Proof** (designed): Deploy the advisory worker to Amazon EKS under pod-scoped identity.

## Architecture (Release 1)

Two layers. The first is running today. The second is designed and partly built; this section
marks which is which, because a boundary claim that is not yet enforced is not a boundary.

**Shift-left (CI) · running**  
`terraform fmt`, offline `validate`, and pinned Checkov run on every push. Any failed Checkov check
fails the build. No AWS credentials in CI. Severity-aware gating, secret scanning, and Terraform
linting are future work: open-source Checkov cannot filter by severity without a commercial API
key, so this project does not claim severity-gated builds.

**Runtime (Detect → Propose → Approve → Remediate)**  
Detection is running: Security Hub CSPM emits an ASFF finding, and a Terraform-managed EventBridge
rule (`sapper-securityhub-findings`) matches it. The rule is deliberately target-less until the
proposer lands.

The rest is designed, specified, and not yet built: a proposer Lambda that gates the finding and
writes a PENDING proposal record with a dry-run plan and its hash, a human-only create-only
approval bound to that plan hash, and a separate bounded remediation role that applies the
reversible fix and captures before/after evidence.

The design intent is that the proposer holds no mutating permission and cannot write its own
approval, with each absence backed by an explicit IAM deny and proven at runtime by a captured
`AccessDenied`. That proof does not exist yet. Until it does, this repo claims a design. It does not yet claim an enforced boundary.

## Results from the Lab

- Real S3.8 finding captured through EventBridge and committed as evidence.
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
make help         # every target, and which ones are not built yet
```

With AWS credentials and the backend pointed at your own bucket:

```bash
make deploy       # stand up lab + detective stack (scans first)
make destroy      # tear down lab + detective services (guarded; never touches state)
```

`make remediate`, `make verify-boundary`, and `make demo` are honest stubs that print what they
will do. `make help` labels them `[NOT BUILT]`. They are not silently broken: they are not written.

## Docs

- [ADRs](./adr)
- [Evidence](./evidence)
- [Cost](./COST.md)
- [Production Gap](./PRODUCTION_GAP.md)
- [Building this with an AI agent](./AI_WORKFLOW.md)
- [License](./LICENSE) (Apache-2.0)

## About

Built by Mamadou Wane, Marine Corps veteran (combat engineer) and CS student at WGU, graduating December 2026. sapper is one flagship delivered as three releases that share one thesis: define the blast radius, prove the system fails safe, and measure whether it does. 

[github.com/mamadou-wane](https://github.com/mamadou-wane) · [mamadouwane.com](https://mamadouwane.com) · [linkedin.com/in/mamadouswane](https://linkedin.com/in/mamadouswane)
