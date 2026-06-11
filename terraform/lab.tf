resource "aws_s3_bucket" "lab" {
  #checkov:skip=CKV_AWS_18: lab target bucket is intentionally minimal; access logging is out of scope for Phase 1 drift demonstration
  #checkov:skip=CKV_AWS_21: lab target bucket stores no durable evidence; versioning is out of scope for Phase 1 drift demonstration
  #checkov:skip=CKV_AWS_144: single-region lab target bucket; cross-region replication is out of scope
  #checkov:skip=CKV_AWS_145: lab target bucket does not store sensitive data; KMS is out of scope for Phase 1 drift demonstration
  #checkov:skip=CKV2_AWS_61: lifecycle policy is out of scope for empty lab target bucket
  #checkov:skip=CKV2_AWS_62: event notifications are out of scope for Phase 1 lab target bucket

  bucket = "sapper-lab-public-116137268889"
}

resource "aws_s3_bucket_public_access_block" "lab" {
  bucket = aws_s3_bucket.lab.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
