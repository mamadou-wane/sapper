# Building sapper with an AI agent in the loop

sapper is built with an AI coding agent as a working partner. This file is the record of how that
actually goes, including the times the generated approach was wrong. A log that only records
successes is marketing, and this project's whole premise is that a claim without evidence behind it
is not a claim.

Two rules govern the collaboration and show up in every entry below. Facts about AWS behavior are
verified against current vendor documentation rather than recalled, because a model's memory of an
API is a plausible guess. And when two documents disagree, the conflict gets named and ruled on
rather than silently resolved.

---

## Auditing the engineering plan

**Task.** Stress-test the engineering plan before writing any more code against it.

**Approach.** The plan went through a multi-agent adversarial audit: one pass establishing ground
truth by reading the repository, twelve independent review lenses (AWS detection correctness, IAM,
evidence integrity, Bedrock, distributed-systems idempotency, evaluation methodology, the
claim-to-proof matrix, EKS, delivery risk, cost, internal consistency, and a red team), then a
refutation pass where every finding was attacked by a skeptic with live documentation access. 153
findings survived. 16 were refuted and discarded.

**Approach rejected.** A single-pass review. The refutation stage paid for itself: 16 findings that
read as entirely plausible died on contact with the actual documentation, or with plan text that
already addressed them. Without that stage each would have become a work item.

**What the audit found that mattered most.** Two claims about Amazon Bedrock were wrong in ways
that fail on the first call rather than in production:

Invoking a model with a guardrail attached requires `bedrock:ApplyGuardrail` on the guardrail ARN
in addition to `bedrock:InvokeModel`. The plan had reasoned its way to *not* granting it, as a
least-privilege decision. Every guarded call would have returned `AccessDeniedException`.

Content qualified as `grounding_source` is excluded from all other guardrail policy evaluations,
including prompt-attack detection. The design passed untrusted resource metadata as grounding
source and expected the injection filter to inspect it. The filter would have inspected nothing,
and the planned metric for injection escapes would have been measuring a control that never ran.

Both were re-verified by hand against AWS documentation before anything was changed.

**What review caught in the agent's own work.** After the audit, the agent produced a summary whose
"do not touch" list protected the finding-gate chain as it already existed, while the audit had
accepted four hardenings to that same chain. The framing would have quietly cancelled fixes that
had been agreed a few minutes earlier. Human review caught it.

The agent also wrote two different effort ranges for the same scope, forty lines apart, inside the
section of the plan whose job is honesty. The ruling was to delete every time estimate from the
plan. Estimates on unbuilt work are false precision, and a dependency-ordered sequence carries the
real signal.

**Where the audit was wrong.** It flagged a README sentence about a budget alarm as false, on the
grounds that no budget exists in Terraform. The sentence was a historical claim about lab process,
and the spike notes corroborate it. The claim stayed and the missing Terraform coverage was tracked
separately. Audit findings are evidence to weigh, never verdicts to apply.

It also recommended scrubbing an account ID from every file that contains it. Most of those files
are captured evidence. Rewriting a captured artifact to look account-neutral would falsify a record
of what ran, so the change was scoped to the two Terraform files that are actually code.

---

## Auditing the plan again, after fixing it

**Task.** Re-audit the corrected plan before building from it.

**Approach.** Four independent lenses: internal consistency, technical correctness of the new
design decisions, a red team against the boundary claim, and whether an engineer could build from
the document tomorrow. 72 findings. All four lenses returned the same verdict independently: not
implementable as written.

**Approach rejected.** Going straight to an implementation plan. The document read as finished, and
three of four lenses found blockers inside the single mechanism the plan calls the safety invariant
of the first release.

**What review caught.** Five blockers, four of them introduced by the previous round of fixes.

*The consumption marker was written to a prefix its writer is denied.* The design declared the
approvals prefix writable only by the approver, then had the remediation role write a consumption
marker into that same prefix before every apply. An explicit Deny in a bucket policy overrides any
identity-based Allow, so either every apply would fail, or the remediator held write access to
approvals and could forge one. Four lenses found this independently. Fixed by splitting the
evidence store into four prefixes with three distinct writers.

*A planned live test was physically impossible.* The boundary spike called for the proposer to
overwrite an approval and receive `412 Precondition Failed`. A denied principal receives `403` on
both attempts, because S3 evaluates authorization before conditional-request preconditions. Two of
the three planned captures were the same request. Rewritten as five captures, each naming the
principal that can actually produce it.

*The delete deny guarded the wrong action.* `s3:DeleteObjectVersion` was denied and
`s3:DeleteObject` was not. In a versioned bucket, `DeleteObject` writes a delete marker, after
which the next conditional create succeeds. The deny list defeated nothing.

*Create-only on a unique key provides no deduplication*, because a generated identifier never
collides. The suppressor was an unsynchronised read-then-write, and asynchronous Lambda retries
make duplicates routine. Replaced with an explicit lease object keyed on the incident.

*Three claims were right for the wrong reason.* A provenance gate was described as closing a
forgery hole that AWS already closes at the service level, so its adversarial test would have
passed without proving anything. A stale-finding analysis credited two mechanisms that cannot fire
on the case it described. A deduplication key was justified by an argument that inverts the actual
risk.

*Mocked AWS tests the wrong half.* Recent versions of the mocking library implement conditional
writes but do not evaluate bucket policies. The single-use test would pass in CI while the
enforcement that matters stayed untested. The line between mocked and live coverage was drawn in
the wrong place.

**One consequence of this audit.** The boundary spike moved ahead of the main build. Mocked AWS
cannot evaluate resource-based policies, so the property the whole project rests on can only be
proven against live AWS. It had been scheduled third of four. Proving a boundary before building on
it is worth more than proving it afterward.

---

## Ruling the one decision the audit could not

**Task.** Decide whether IAM should require an approval object to exist before a remediation can
happen.

**The problem.** The red team found that nothing in IAM required it. The approving operator was
also the operator running the apply, and held the only trust path into the bounded role, so the
approval check lived in client-side code that same operator controls. Skipping the tool skipped the
gate. The captured `AccessDenied` evidence was all real, and none of it covered that path.

**Ruling.** The remediator became a Lambda triggered by the object-created event on the approvals
prefix, with its execution role as the only trust principal of the bounded role. Writing the
approval object is now the only path to an apply. The rejected alternative was to keep the command
line tool and reword the claim to match what it supported.

**What review caught, by asking the agent to defend its own recommendation.** The agent had
summarized the change as meaning no human can assume the bounded role. Challenged on whether that
was actually true, a single call to `aws sts get-caller-identity` showed the approver identity was
the account's administrator role. An administrator is denied nothing, so the claim was false, and
the plan had specified an adversarial test that could never pass. A specified test that cannot pass
is more dangerous than a missing one, because it looks like coverage.

Fixed by adding a dedicated approver role holding only create-only write on approvals and read on
proposals, and by narrowing the claim to what the design delivers: the system cannot apply a change
without an approval object, and no principal on that path can both approve and mutate. The account
administrator remains outside the boundary, which is the separation of duties a production
deployment enforces organizationally.

**Second-order consequence, surfaced by the same challenge.** Under the new design the approval
write is a single point of commitment, with no second confirmation before the change lands. A
second prompt was rejected as ceremony: the same person, the same session, the same information,
seconds apart. A cancel window was declined because it adds latency to a remediation whose purpose
is closing an exposure window. First-class rollback was adopted instead, restoring the captured
before-state and recording the restore as evidence. It also closed a gap the audit had already
flagged, that reversibility was claimed throughout with no implementation behind it.

**The lesson worth keeping.** Both defects surfaced from one question: is that actually the right
approach? The agent's own confident summary was the thing that needed auditing, and checking it
took a single command against the live account.
