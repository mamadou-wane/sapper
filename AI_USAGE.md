---
title: AI Usage in This Repository
status: active
reviewed-by-human: true
---

# AI Usage in This Repository

sapper is built with AI coding agents (Claude Code) as working partners. This file is the
complete and only disclosure of that use. There are no attribution markers in git history,
code comments, or documents by design; the working agreement agents operate under is
`AGENTS.md`, published once it stabilizes.

## Policy

- Agents only draft. Every public document was reviewed and revised by me before publication.
- The judgment artifacts are mine: every ADR decision and its consequences, every ruling on
  open plan decisions, the approval-boundary design, and what counts as evidence.
- Nothing merges without my review. I do not ship code or docs I cannot explain line by line.
- Facts about AWS behavior are verified against current vendor documentation before they are
  relied on. A model's recall of an API is treated as a plausible guess.

## Agent Usage

| Area | Typical Use | Human Role |
|---|---|---|
| Plan auditing | Multi-agent adversarial audits with refutation passes (27 agents on consolidated plan; 153 findings survived, 16 refuted) | Weigh findings as evidence, rule on each, re-verify blockers by hand |
| Infrastructure drafting | Terraform modules, IAM policy drafts, Makefile targets | Review, adapt, verify against AWS docs before apply |
| Docs drafting | READMEs, runbooks, ADR drafts, this file | Rewrite in my own words, verify every command and number |
| Research | AWS service behavior, engineering practice, tooling comparisons | Verify against primary sources before relying on it |

Agents were not used for rulings on open decisions, approval-boundary design judgments, what
evidence gets captured and banked, or anything applied to the live AWS account.

## Agent Errors and Corrections

1. Least-privilege argument for not granting `bedrock:ApplyGuardrail` with
   `bedrock:InvokeModel`. Every guarded call would have returned `AccessDeniedException`.
   Caught by adversarial audit with live docs, re-verified manually. Advisory release cut.
2. Design passing untrusted metadata as `grounding_source`, expecting prompt-attack filter
   inspection. Grounding content excluded; planned injection metric measured non-existent
   control. Same catch as above.
3. Boundary test: denied principal receives `412 Precondition Failed`. S3 checks
   authorization before preconditions, principal gets `403`. Caught in second audit; spike
   rewritten as five captures.
4. Claim: event-triggered remediator means "no human can assume bounded role."
   `aws sts get-caller-identity` showed approver was account admin, deny-immune. Claim
   narrowed, dedicated approver role added.
5. Post-audit inventory "do not touch" list silently cancelling four just-accepted
   hardenings. Caught in human review; agent's confident summary needs most auditing.

## Numbers

- Agent-drafted docs reviewed and rewritten: <<N>>
- Agent findings overruled after human verification: <<N>>
- Audit findings refuted pre-work: 16 of 169 (first plan audit)

## Style Standard

Human and agent output held to MIT 6.102 Software Construction bar (safe from bugs, easy to
understand, ready for change) and its code-review checklist, per `AGENTS.md`.
