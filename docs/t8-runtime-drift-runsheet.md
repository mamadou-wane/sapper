# T8 runtime drift runsheet: S3.8 public bucket

The acceptance procedure for the S3.8 runtime drift experiment. It breaks a lab bucket out of band, confirms Security Hub detects it with the right finding shape, measures detection latency, and watches the finding across a 48-hour window before rolling back. Run it top to bottom and capture the evidence each step names.

- Account: <account-id>
- Region: us-east-1
- Resource: `arn:aws:s3:::sapper-lab-public-<account-id>`
- Control: S3.8 (S3 general purpose buckets should block public access)

Fill `<account-id>` with the real account number before running, or `export ACCT=<account-id>` and substitute. Every command below carries it, in the bucket name and the finding-filter ARNs. A wrong ARN makes the server-side filter return empty, which looks identical to "the finding has not appeared yet," and you will wait on nothing.

## Scope

What this experiment proves:

- The detective stack (AWS Config plus Security Hub with FSBP, T4/T5) detects a public-bucket drift introduced outside the pipeline.
- Security Hub emits the S3.8 finding in the shape the runtime layer consumes: `Compliance.SecurityControlId = S3.8`, `Compliance.Status = FAILED`, `RecordState = ACTIVE`, under the `SECURITY_CONTROL` finding generator.
- The detection latency from break completed to the finding's `FirstObservedAt`.
- The finding persists while the resource stays noncompliant across a 48-hour window.

What this experiment does not prove yet:

- It does not prove EventBridge delivers the finding to the proposer. The EventBridge rule and the proposer Lambda are not exercised here, and the proposer is not built.
- It does not prove remediation. The bounded remediation role, the approval binding, and the fix are not built.
- It does not exercise the human-approval or evidence-write path.

This is detection-only acceptance. It ends at a confirmed, shaped Security Hub finding.

## Pre-check: bucket empty

```bash
aws s3 ls s3://sapper-lab-public-<account-id> --recursive
```

Normal result: no output. The bucket must be empty so the experiment has no object-level variables and rollback is clean. If anything is listed, stop and resolve that first.

## Baseline BPA capture

```bash
aws s3api get-public-access-block \
  --bucket sapper-lab-public-<account-id> \
  | tee t8-bpa-baseline.json
```

Expected: all four flags true.

```json
{
  "PublicAccessBlockConfiguration": {
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }
}
```

## Pre-break Security Hub evaluation check

Before breaking anything, confirm S3.8 is already evaluating this bucket. The clean signal is an existing S3.8 finding sitting at `PASSED` against the compliant baseline.

```bash
aws securityhub get-findings \
  --region us-east-1 \
  --filters '{"ResourceId":[{"Value":"arn:aws:s3:::sapper-lab-public-<account-id>","Comparison":"EQUALS"}]}' \
  | jq -r '.Findings[]
      | select(.Compliance.SecurityControlId=="S3.8")
      | "\(.Compliance.Status) \(.RecordState) \(.Workflow.Status) updated=\(.UpdatedAt)"'
```

Expected: an S3.8 entry present, ideally `PASSED ACTIVE`, confirming the control actively evaluates this bucket. If nothing returns, Security Hub has not evaluated S3.8 against the bucket yet; wait until it does before breaking. Skipping this conflates enablement lag with detection latency, and the §3 latency refresh then records the wrong quantity.

## Timestamp capture

Capture the drift-start markers before you touch the console. Break-completed is captured at the save step below and is t=0 for the latency measurement; drift-start records when the manual change began, so the editing window stays on the record too.

```bash
date '+LOCAL %Y-%m-%d %H:%M:%S %Z' | tee t8-drift-start.txt
date -u +%Y-%m-%dT%H:%M:%SZ | tee -a t8-drift-start.txt
```

## Manual console break only

Make the change in the S3 console, not the CLI and not Terraform. The point of the experiment is out-of-band clickops drift, so the break has to come from outside the pipeline.

1. S3 console, bucket `sapper-lab-public-<account-id>`, Permissions tab.
2. Edit Block Public Access (bucket settings).
3. Uncheck all four settings.
4. Save, and confirm the typed acknowledgment the console requires.

At the instant the save completes, capture break-completed in UTC. This is t=0 for the latency clock, not the moment you began editing.

```bash
date -u +%Y-%m-%dT%H:%M:%SZ | tee t8-break-completed.txt
```

## Post-break BPA capture

```bash
aws s3api get-public-access-block \
  --bucket sapper-lab-public-<account-id> \
  | tee t8-bpa-broken.json
```

Expected: all four flags false. This confirms the resource is now noncompliant.

## Security Hub query and raw JSON evidence capture

Pull the active finding for this resource and save the raw response as evidence. The query filters server-side on the resource ARN and `RecordState` (both stable filter attributes) and selects S3.8 in jq.

```bash
aws securityhub get-findings \
  --region us-east-1 \
  --filters '{"ResourceId":[{"Value":"arn:aws:s3:::sapper-lab-public-<account-id>","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' \
  | tee t8-s3.8-finding-raw.json
```

The finding can take a few minutes to appear. If the query returns no S3.8 finding, wait and re-run; do not shorten the wait by assuming it failed.

Extract the fields that matter:

```bash
jq '[.Findings[]
  | select(.Compliance.SecurityControlId == "S3.8")
  | {SecurityControlId: .Compliance.SecurityControlId,
     Status: .Compliance.Status,
     RecordState,
     WorkflowStatus: .Workflow.Status,
     Resource: .Resources[0].Id,
     FirstObservedAt,
     UpdatedAt}]' t8-s3.8-finding-raw.json
```

Expected: one S3.8 entry with `Status = FAILED`, `RecordState = ACTIVE`, `WorkflowStatus = NEW`, and the resource ARN above.

`WorkflowStatus` is recorded to confirm it sits at NEW and is therefore correctly excluded from the handler gates (SPIKE_NOTES §7), not used for dedupe. The open-proposal suppressor is the dedupe source of truth; workflow status is explicitly not it. Seeing it reset to NEW on the PASSED-to-FAILED transition is the corroboration that excluding it from the gates was right.

## Fixture parity

When proposer fixtures exist, compare the raw Security Hub finding shape against the proposer fixture. The fields that must remain stable are:

- `Compliance.SecurityControlId`
- `Compliance.Status`
- `RecordState`
- `Resources[0].Id`

At the time of this T8 runsheet, `fixtures/sample-finding-event.json` is not present yet, so fixture parity is a future proposer acceptance check, not a blocker for T8 detection acceptance.

## Latency calculation

Detection latency is break completed to the finding's `FirstObservedAt`.

Before computing, confirm the raw finding actually carries `FirstObservedAt` and that it differs from `UpdatedAt`. If the field is absent or just echoes `UpdatedAt`, the number measures the wrong thing, so eyeball the raw JSON and pick the timestamp that marks first detection. The snippet below raises if no S3.8 finding carries `FirstObservedAt`, which is the signal to go look rather than trust a silent result.

```bash
python3 - <<'PY'
from datetime import datetime, timezone
with open("t8-break-completed.txt") as f:
    break_completed_raw = f.read().strip()
import json
with open("t8-s3.8-finding-raw.json") as f:
    data = json.load(f)
first_observed_raw = next(
    finding["FirstObservedAt"]
    for finding in data["Findings"]
    if finding.get("Compliance", {}).get("SecurityControlId") == "S3.8"
)
def parse_aws_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
break_completed = parse_aws_time(break_completed_raw)
first_observed = parse_aws_time(first_observed_raw)
latency = first_observed - break_completed
print(f"break completed:  {break_completed_raw}")
print(f"first observed:   {first_observed_raw}")
print(f"latency seconds:  {latency.total_seconds():.3f}")
PY
```

This uses Python's standard library so it works on macOS and Linux without requiring GNU `date`. `FirstObservedAt` may include sub-second precision. Record the result. `UpdatedAt` is the finding's later revision timestamp and is not the detection latency.

## Observation window checks

Re-run the query at each interval and save a timestamped copy. The window confirms the finding stays ACTIVE while the resource stays noncompliant, and shows the re-evaluation cadence through `UpdatedAt`.

```bash
# at +12h, +24h, +36h, +48h
ts=$(date -u +%Y%m%dT%H%M%SZ)
aws securityhub get-findings \
  --region us-east-1 \
  --filters '{"ResourceId":[{"Value":"arn:aws:s3:::sapper-lab-public-<account-id>","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' \
  | tee "t8-window-$ts.json" \
  | jq -r '.Findings[]
      | select(.Compliance.SecurityControlId=="S3.8")
      | "\(.Compliance.Status) \(.RecordState) updated=\(.UpdatedAt)"'
```

Expected at each check: `FAILED ACTIVE` with `UpdatedAt` advancing as Security Hub re-evaluates. If the finding leaves ACTIVE or FAILED at any check, record which check and the values; that is a result, not a failure of the run.

**Warning: do not remediate during the observation window.** Leave the bucket broken until all four window checks are done. Do not re-enable Block Public Access, do not run any remediation target, and do not let anything else fix the bucket. The window measures finding persistence on a continuously noncompliant resource, and an early fix destroys the measurement. Remediation is not built, so this is a discipline rule for manual action, not a tooling guard.

## Rollback

Only after the +48h check, restore the baseline.

```bash
aws s3api put-public-access-block \
  --bucket sapper-lab-public-<account-id> \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

Confirm the restore:

```bash
aws s3api get-public-access-block --bucket sapper-lab-public-<account-id>
```

Expected: all four flags true, matching `t8-bpa-baseline.json`. If this bucket's BPA is declared in Terraform, `terraform -chdir=terraform apply` reconciles the drift to the same state.

Confirm the finding clears. On its next evaluation Security Hub should move the S3.8 finding to `Compliance.Status = PASSED` and archive it; the exact timing depends on the re-evaluation cadence, so re-run the query until it reflects the compliant state rather than assuming a fixed delay.

## Acceptance criteria

- [ ] Bucket confirmed empty before the break (`t8-bpa-baseline.json` preceded by a clean `s3 ls`).
- [ ] Baseline BPA captured: all four flags true.
- [ ] S3.8 confirmed evaluating the bucket before the break (PASSED finding present, or enablement confirmed).
- [ ] Break performed in the S3 console only, no CLI or Terraform.
- [ ] Break-completed timestamp captured in UTC (`t8-break-completed.txt`).
- [ ] Post-break BPA captured: all four flags false.
- [ ] S3.8 finding retrieved with `Status = FAILED`, `RecordState = ACTIVE`, `WorkflowStatus = NEW`, on the correct resource ARN.
- [ ] Raw finding JSON saved (`t8-s3.8-finding-raw.json`).
- [ ] Raw finding includes the proposer gate fields: `Compliance.SecurityControlId`, `Compliance.Status`, `RecordState`, and `Resources[0].Id`.
- [ ] Fixture parity deferred until `fixtures/sample-finding-event.json` exists.
- [ ] Detection latency computed from break completed to `FirstObservedAt` and recorded.
- [ ] Finding still `FAILED ACTIVE` at +12h, +24h, +36h, +48h, or the deviation recorded with its check time.
- [ ] No remediation or manual fix occurred during the window.
- [ ] Rollback restored BPA to all four true, and the finding cleared on re-evaluation.
