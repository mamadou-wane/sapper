# T8: detection evidence (S3.8, public bucket)

This records an out-of-band break of a lab bucket and the real Security Hub finding it produced. It confirms two things the runtime layer depends on: that the detective stack (Config + Security Hub/FSBP, T4/T5) detects a public-bucket drift, and that the finding carries the exact shape the proposer keys on.

- Provenance: REAL. A real bucket-level change produced a real Security Hub finding, not a synthetic `sapper.demo` event.
- Account: 116137268889
- Region: us-east-1
- Resource: `arn:aws:s3:::sapper-lab-public-116137268889`

## The break

The bucket was empty before drift, and its baseline bucket-level Block Public Access was all true. The break set all four bucket-level BPA flags to false, out of band, to simulate a misconfiguration that bypasses the pipeline.

| BPA flag | Baseline | After break |
|---|---|---|
| BlockPublicAcls | true | false |
| IgnorePublicAcls | true | false |
| BlockPublicPolicy | true | false |
| RestrictPublicBuckets | true | false |

| Marker | Local (EDT) | UTC |
|---|---|---|
| Drift started | 2026-06-13 16:04:42 | 2026-06-13T20:04:42Z |
| Break completed | 2026-06-13 16:10:03 | 2026-06-13T20:10:03Z |

The latency clock starts at break completed (`20:10:03Z`), the moment the bucket was fully noncompliant. The five minutes before that are the manual editing window and are not detection latency.

## The finding

The observed ASFF fields from the live Security Hub finding:

| Field | Value |
|---|---|
| Compliance.SecurityControlId | S3.8 |
| Compliance.Status | FAILED |
| RecordState | ACTIVE |
| Resource | `arn:aws:s3:::sapper-lab-public-116137268889` |
| FirstObservedAt | 2026-06-13T20:12:23.144Z |
| UpdatedAt | 2026-06-13T20:12:55.120Z |

## Measured detection latency

| Interval | From | To | Elapsed |
|---|---|---|---|
| Break to first observation | 2026-06-13T20:10:03Z | 2026-06-13T20:12:23.144Z | about 2m20s |
| Break to current revision | 2026-06-13T20:10:03Z | 2026-06-13T20:12:55.120Z | about 2m52s |

`FirstObservedAt` is when Security Hub first recorded the noncompliant state, so break to first observation (about 2m20s) is the detection latency. `UpdatedAt` is the finding's current revision, 32 seconds later.

## What this confirms

The finding generator is set to `SECURITY_CONTROL` (consolidated control findings, per T5), and the finding populates `Compliance.SecurityControlId = S3.8`. That field is the proposer's primary gate input. The three fields captured here, `SecurityControlId = S3.8`, `Compliance.Status = FAILED`, and `RecordState = ACTIVE`, are the proposer's gate inputs before it acts. The resource ARN is in lab scope (`sapper-lab-*`), which the proposer's resource-ID parsing requires.

EventBridge delivery of this finding to the proposer is out of T8 scope; the proposer is not built yet (Phase 1 runtime). T8 proves the detection signal exists and has the right shape.

## Note on the earlier finding

An older S3.8 finding on this bucket from 2026-06-07 (Phase 0) is retained as recurrence and dedupe evidence, not as the primary T8 detection artifact. The proposer's dedupe keys on finding ID plus `UpdatedAt`, so a recurrence of the same control on the same resource is exactly the case that suppressor has to handle.

