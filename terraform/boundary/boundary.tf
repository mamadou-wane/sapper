# ---------------------------------------------------------------------------
# The remediation permissions boundary
#
# A boundary is a CEILING on everything the role can do, so it has to include
# the role's own evidence writes and not only the fix. PLAN.md §7's earlier
# wording ("caps its maximum permissions to the single S3.8 fix") would have
# blocked the role from writing the record proving it applied the fix.
#
# Verified: a bucket policy granting to a ROLE ARN stays limited by this
# boundary. A grant to an assumed-role SESSION ARN would skip boundary
# evaluation entirely, which is one more reason no sts:: value appears in
# bucket-policy.tf.
#
# Amendments owed to later slices, each named rather than predicted:
#   P4: logs:CreateLogStream and logs:PutLogEvents on the remediator function's
#       own log group, once that log group exists.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "remediation_boundary" {
  statement {
    sid    = "CeilingApplyTheFix"
    effect = "Allow"
    actions = [
      "s3:PutBucketPublicAccessBlock",
      "s3:GetBucketPublicAccessBlock",
    ]
    resources = local.lab_bucket_arns
  }

  statement {
    sid    = "CeilingReadTheDecision"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
    ]
    resources = [
      "${aws_s3_bucket.evidence.arn}/proposals/*",
      "${aws_s3_bucket.evidence.arn}/approvals/*",
    ]
  }

  statement {
    sid     = "CeilingWriteItsOwnEvidence"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.evidence.arn}/consumed/*",
      "${aws_s3_bucket.evidence.arn}/applied/*",
      "${aws_s3_bucket.evidence.arn}/rollback/*",
    ]
  }

  statement {
    sid       = "CeilingList"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.evidence.arn]
  }
}

resource "aws_iam_policy" "remediation_boundary" {
  name        = "sapper-remediation-boundary"
  description = "Ceiling for sapper-remediation. PLAN.md §7. Owes a logs:* amendment when P4 creates the remediator log group."
  policy      = data.aws_iam_policy_document.remediation_boundary.json
}
