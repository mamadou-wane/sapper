output "evidence_bucket" {
  description = "Name of the durable evidence bucket. Permanent."
  value       = aws_s3_bucket.evidence.bucket
}

output "role_arns" {
  description = "The four boundary identities, for the operator and later slices (P5). scripts/boundary-probe.sh consumes evidence_bucket, not this."
  value = {
    proposer    = aws_iam_role.proposer.arn
    remediator  = aws_iam_role.remediator.arn
    remediation = aws_iam_role.remediation.arn
    approver    = aws_iam_role.approver.arn
  }
}

output "admin_role_arn" {
  description = "The resolved Identity Center admin role. Exempted from the delete deny."
  value       = local.admin_role_arn
}
