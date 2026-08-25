resource "aws_s3_bucket" "evidence" {
  #checkov:skip=CKV_AWS_144: single-region lab evidence store; cross-region replication is out of scope for R1
  #checkov:skip=CKV_AWS_145: SSE-S3 is the R1 choice; the tamper-evidence claim rests on the delete denies in the bucket policy, not on encryption, and KMS adds per-request cost without a threat-model benefit here
  #checkov:skip=CKV_AWS_18: access logging deferred; the CloudTrail S3 data-event selector built in P3 is the audit surface for this bucket
  #checkov:skip=CKV2_AWS_62: event notifications arrive in P4, when the remediator subscribes to approvals/
  #checkov:skip=CKV2_AWS_61: no lifecycle rule on purpose; evidence is permanent (PLAN.md §8) and the bucket policy denies the runtime roles s3:PutLifecycleConfiguration. An expiration rule would delete the records this store exists to keep

  bucket = local.evidence_bucket

  # No force_destroy, deliberately. This is the one bucket in the project that
  # must survive every teardown (PLAN.md §8). force_destroy is exactly how an
  # accidental destroy run in the wrong directory would empty it.
}

# Versioning is created in the same apply as the bucket and before any object is
# written. Objects written to a bucket before versioning is enabled stay
# unversioned forever, and the delete-marker reasoning in the bucket policy
# assumes every object in this store has versions.
resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
