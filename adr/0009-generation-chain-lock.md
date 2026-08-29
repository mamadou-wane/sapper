# ADR-0009: The lock is a chain of generations

Status: Accepted
Date: 2026-08-28
Related: `PLAN.md` §4 (the project's engineering plan, not published); `evidence/p15/10-proposer-lock.json`

## Context

The proposer suppresses duplicate proposals for one incident (resource ARN and remediation action) with a create-only lock object, `locks/<sha256>.lock`, written with `If-None-Match: *`. P1.5 proved that key against live S3. The PR #23 review found two things the design left open. The claim, which that design called a "lease", had no duration anywhere. And a lock object is one-shot: create-only plus the evidence bucket's delete denies make the key permanent, so once its claim expired nothing guarded the incident again, and Lambda's two async retries alone would put up to three PENDING proposals on the second drift of the same bucket.

Treating an expired claim as "proceed" reopens the unsynchronised list-then-create race the design exists to close. The decision path is read-only, the proposal write that follows lands on a fresh ULID, and N concurrent invocations that all read "expired" write N proposals.

## Decision

The lock stays the serialization primitive and gains monotonic generations. Generation 0 keeps the P1.5-banked key. Generation n >= 1 is `locks/<sha256>/<nnnnnn>.lock`, six digits, zero-padded, failing closed at 999,999. Reclaiming an incident is a create-only write of the next generation: the chain listing is the compare, the write is the swap, and a stale compare fails the swap with a 412. Nothing is overwritten or deleted.

The lock body is `{proposal_id, provenance, created_at}`, the shape the P1.5 probe wrote, where `created_at` is the claim's creation time. A claim lives for `CLAIM_TTL = lambda_timeout + M`, with `M > 1 s` and the sum at most 30 s: a liveness window, not the 72-hour proposal expiry. Once it expires, proposal state decides. An expired, applied, or absent proposal permits the next generation; an open one suppresses.

## Options considered

- Scan the proposal prefix on 412 and decide from the latest proposal's state. Rejected: the decision path stays read-only and the write that follows is create-only on a unique ULID, so concurrent invocations that all decide "proceed" all succeed. There is no serialization point.
- Reclaim the lock with an `If-Match` overwrite. Serialized, and vendor-verified to work on S3. Rejected: the evidence bucket's `DenyNonConditionalObjectCreation` refuses it, so it needs a carve-out in the one bucket policy P1.5 exists to prove, downgrades the "create-only is enforced by the bucket" proof row, and forces a second evidence run.
- A generation chain. Chosen: create-only is the serializer, the bucket policy does not change, and the banked generation 0 key and capture stay valid.

## Consequences

- Reclamation costs one listing, one read, and up to two existence lists per attempt. The proposer's `ListBucket` grant widens by the `applied/` prefix, which lets it enumerate every applied marker, not only the one key it derives.
- Correctness rests on `M`. A reader that rules a live claim expired writes a duplicate, because the owner's proposal write cannot fail. Clock skew between Lambda invocations has to stay far below `M`. Stated in `PLAN.md` §4, not solved.
- The generation width cannot widen in place. An incident that reaches the cap needs an administrator, and the on-failure alarm is what reports it.
- A remediator that dies between `consumed/` and `applied/` leaves the incident suppressed for up to 72 hours (`PRODUCTION_GAP.md`, "Consumed without applied").
- The seventh key template has no live capture until the first REAL run writes generation 1.
