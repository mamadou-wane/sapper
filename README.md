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

Next up is the proposer slice (the detect-and-propose Lambda, human approval, bounded remediation role, and negative IAM tests).

## Releases

sapper is one project delivered as three releases, each shippable on its own.

- **Release 1 – Security Core** (in progress): Detect unsafe changes in CI and after deploy, then remediate only after human approval with full evidence.
- **Release 2 – AI Advisory** (designed): A Bedrock worker that reasons about findings from outside the authorization path. It can advise but cannot act.
- **Release 3 – EKS Platform Proof** (designed): Deploy the advisory worker to Amazon EKS under pod-scoped identity.

## Architecture (Release 1)

Two layers:

**Shift-left (CI)**  
`terraform fmt`, validate, and pinned Checkov run on every push. High-severity findings fail the build. No AWS credentials in CI.

**Runtime (Detect → Propose → Approve → Remediate)**  
Security Hub finding → EventBridge → Proposer Lambda (read-only) → writes proposal record → Human approval → Bounded remediation role applies the reversible fix and captures before/after evidence.

The proposer has no mutation permissions. The remediation role is locked down with a permissions boundary and negative IAM tests.

## Results from the Lab

- Real S3.8 finding captured through EventBridge and committed as evidence.
- CI gate proven with a deliberate failing push restored to green.
- Interpreter-parity check added after discovering pinned Checkov returned fewer checks under Python 3.14.
- Scoped resources + budget alarm set before anything that bills continuously was enabled.

## Run It

```bash
make setup     # prerequisites + remote state
make deploy    # stand up lab + detective stack
# Simulate drift (e.g. make a lab bucket public)
make remediate # after human approval
make destroy   # clean teardown
```

## Docs

- [ADRs](./adr)
- [Evidence](./evidence)
- [Threat Model](./THREAT_MODEL.md)
- [Production Gap](./PRODUCTION_GAP.md)
- [Cost](./COST.md)

## About

Built by Mamadou Wane, Marine Corps veteran (combat engineer) and CS student at WGU, graduating December 2026. sapper is one flagship delivered as three releases that share one thesis: define the blast radius, prove the system fails safe, and measure whether it does. 

[github.com/mamadou-wane](https://github.com/mamadou-wane) · [mamadouwane.com](https://mamadouwane.com) · [linkedin.com/in/mamadouswane](https://linkedin.com/in/mamadouswane)
