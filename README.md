# sapper

> Blocks unsafe cloud infrastructure in code, detects misconfigurations that drift in after deploy, and only remediates a narrow, reversible set after human approval, with evidence for every action.

Public buckets, open security groups, and leaked keys usually come from code that should have been blocked or changes made outside the pipeline. sapper closes both gaps. The CI gate blocks what it can catch upfront. The runtime detects what slips past. Nothing mutates a resource without a human approving the exact change, and every step leaves evidence.

A sapper is a combat engineer who clears hazards and breaches obstacles, but knows which ones are too dangerous to touch without care.

## Current Status

**Status 2026-08-25:** Release 1 (Security Core) in progress. The detection foundation and the
approval boundary are built and proven against live AWS; next is P2, the proposer.

- De-risked the live Security Hub contract with real findings (S3.8/S3.9 for public buckets, EC2.18/EC2.19 for open security groups).
- Built the detective layer in Terraform (scoped AWS Config recorder + Security Hub with FSBP standard).
- Set up CI/CD in GitHub Actions with pinned Checkov, terraform fmt/validate, and a deliberate failing push to prove the gate works.
- Proved detection end-to-end: intentionally created drift, captured real findings, measured latency, and rolled back cleanly with full evidence.
- Proved the approval boundary live (P1.5): a durable Deny-only evidence bucket, four scoped roles, and sixteen acceptance tests banked under `evidence/p15/`, each capture naming the principal that produced it.

The boundary spike ran against live AWS on 2026-08-25 and the captures are banked. The approver
writes an approval once and a rewrite of the same key returns `412`. A write without the
conditional header returns `403` from the bucket policy itself, proven by an admin control pair,
since an admin holds unconditional `s3:*` and its denial can only come from the bucket. The
proposer's write to the approval prefix is denied while a positive control shows the same
credential succeeding in its own prefix, and `make destroy` removed the detective stack while the
evidence bucket and all four roles survived. Those pairings matter: a denial only proves a
boundary if the same credential succeeds somewhere it should.

Mocked AWS cannot evaluate bucket policies, which is why this proof ran first and ran live. Next:
the proposer Lambda, the records and integrity layer, the approval CLI and bounded remediation
role, and the negative IAM suite.

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
- [License](./LICENSE) (Apache-2.0)

## About

Built by Mamadou Wane, Marine Corps veteran (combat engineer) and CS student at WGU, graduating December 2026. sapper is one flagship that defines the blast radius, proves the system fails safe, and measures whether it does.

[github.com/mamadou-wane](https://github.com/mamadou-wane) · [mamadouwane.com](https://mamadouwane.com) · [linkedin.com/in/mamadouswane](https://linkedin.com/in/mamadouswane)
