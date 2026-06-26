# P1 fixture provenance

provenance: REAL

Fixture:
- `fixtures/sample-finding-event.json`

Capture:
- source: EventBridge -> Lambda throwaway logger -> CloudWatch Logs
- EventBridge rule: `sapper-securityhub-findings`
- event pattern: `fixtures/event-pattern-securityhub-finding.json`
- captured_at: 2026-06-26T01:22:30Z
- processed_at: 2026-06-26T01:22:26.953Z
- control_id: S3.8
- compliance_status: FAILED
- workflow_status: NEW
- finding_id: arn:aws:securityhub:us-east-1:116137268889:security-control/S3.8/finding/d9e45e0f-a518-4110-88ea-66821b2c7bd9
- resource_id: arn:aws:s3:::sapper-lab-public-116137268889

Break / fix timeline:
- broken_at: 2026-06-26T01:04:45Z
- fixed_at: 2026-06-26T01:12:11Z
- rebroken_at: not separately captured in shell output; S3.8 re-failed at 2026-06-26T01:22:15.937Z

Redaction:
- `detail.findings[0].Resources[0].Details.AwsS3Bucket.OwnerId` redacted to `REDACTED_OWNER_ID`
- gate-relevant fields left unchanged

Validation:
- AT-3 envelope shape: OK
- AT-4 `aws events test-event-pattern`: true
