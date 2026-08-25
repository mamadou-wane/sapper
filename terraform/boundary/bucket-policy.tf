locals {
  # One writer per prefix (D9). This map is the entire access model of the
  # evidence store, and the Deny statements below are generated from it, so the
  # policy and the table in PLAN.md §5 cannot drift apart.
  #
  # title() on these single-word keys yields alphanumeric Sids. A future
  # multi-word prefix (for example audit-log) would carry its separator into
  # the Sid, which S3 rejects. Add a replace() in the sid expression before
  # introducing such a key.
  prefix_writers = {
    proposals = aws_iam_role.proposer.arn
    locks     = aws_iam_role.proposer.arn
    approvals = aws_iam_role.approver.arn
    consumed  = aws_iam_role.remediation.arn
    applied   = aws_iam_role.remediation.arn
    rollback  = aws_iam_role.remediation.arn
  }
}

data "aws_iam_policy_document" "evidence" {

  # -- 1. One writer per prefix ---------------------------------------------
  #
  # aws:PrincipalArn carries the ROLE ARN and never the assumed-role session
  # ARN. AWS documents this explicitly: "Do not specify the assumed role session
  # ARN as a value for this condition key." Listing the sts:: form as well would
  # be dead code, because a negated operator evaluates its values as a NOR and
  # an unmatchable pattern is inert. It is omitted anyway: a reviewer who
  # concluded the session form was doing the work is one edit from listing only
  # it, which would fire this Deny on every request and lock the bucket out.
  dynamic "statement" {
    for_each = local.prefix_writers
    iterator = pw

    content {
      sid       = "OnlyOneWriterFor${title(pw.key)}"
      effect    = "Deny"
      actions   = ["s3:PutObject"]
      resources = ["${aws_s3_bucket.evidence.arn}/${pw.key}/*"]

      principals {
        type        = "AWS"
        identifiers = ["*"]
      }

      condition {
        test     = "ArnNotLike"
        variable = "aws:PrincipalArn"
        values   = [pw.value]
      }
    }
  }

  # -- 2. Create-only, enforced by the bucket --------------------------------
  #
  # Bucket-wide on purpose, so scratch/ is covered and AT-16 can prove the
  # bucket rather than the caller is what refuses a headerless write.
  #
  # Both conditions AND together. s3:PutObject is also the action that
  # authorizes CreateMultipartUpload, UploadPart, and UploadPartCopy, none of
  # which can carry an If-None-Match header. A Deny keyed only on the header's
  # absence would refuse multipart uploads at initiation, which presents as a
  # size-dependent bug rather than a policy bug.
  statement {
    sid       = "DenyNonConditionalObjectCreation"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Null"
      variable = "s3:if-none-match"
      values   = ["true"]
    }

    condition {
      test     = "Bool"
      variable = "s3:ObjectCreationOperation"
      values   = ["true"]
    }
  }

  # -- 3. No deletes -----------------------------------------------------------
  #
  # On a versioning-enabled bucket, If-None-Match: * succeeds when the current
  # version is a delete marker. AWS documents it verbatim: "if there's no
  # current object version with the same name, or if the current object version
  # is a delete marker, the write operation succeeds." So DeleteObject followed
  # by a conditional PutObject returns 200 and create-only is defeated.
  # DeleteObject is the action that writes the marker; denying DeleteObjectVersion
  # alone leaves the hole wide open.
  #
  # The admin exemption matches PLAN.md §8 exactly: tamper-evident against the
  # runtime roles, alterable by an administrator, which is the declared
  # out-of-scope privileged-access case. It is not "immutable".
  statement {
    sid    = "DenyDeletes"
    effect = "Deny"
    actions = [
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
    ]
    resources = ["${aws_s3_bucket.evidence.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = [local.admin_role_arn]
    }
  }

  # -- 4. Runtime roles cannot reconfigure the bucket --------------------------
  #
  # Scoped to the four named roles, never Principal "*" (D8). A wildcard Deny on
  # s3:PutBucketPolicy would make this policy unmodifiable by Terraform, by the
  # operator, and by root, on the one bucket in this project that is created
  # once and never recreated. A lifecycle expiration, a versioning suspend, or a
  # policy rewrite each bypasses a deny-delete, so they belong to the same bound.
  #
  # Ruled at the R4 gate, 2026-08-25: an ACL grant, an encryption rewrite, or a
  # public-access-block change on this bucket belongs to the same bound as a
  # policy rewrite. s3:PutEncryptionConfiguration and s3:PutBucketPublicAccessBlock
  # also govern their delete counterparts (DeleteBucketEncryption and
  # DeletePublicAccessBlock), so the deny closes those paths too.
  #
  # The replication action is s3:PutReplicationConfiguration, not the API
  # operation name PutBucketReplication. The first apply carried the operation
  # name and S3 rejected the policy as MalformedPolicy (2026-08-25). The action
  # also governs DeleteBucketReplication, so both replication paths stay closed.
  statement {
    sid    = "RuntimeRolesCannotReconfigure"
    effect = "Deny"
    actions = [
      "s3:PutBucketPolicy",
      "s3:DeleteBucketPolicy",
      "s3:PutBucketVersioning",
      "s3:PutLifecycleConfiguration",
      "s3:PutReplicationConfiguration",
      "s3:PutBucketAcl",
      "s3:PutEncryptionConfiguration",
      "s3:PutBucketPublicAccessBlock",
    ]
    resources = [aws_s3_bucket.evidence.arn]

    principals {
      type = "AWS"
      identifiers = [
        aws_iam_role.proposer.arn,
        aws_iam_role.remediator.arn,
        aws_iam_role.remediation.arn,
        aws_iam_role.approver.arn,
      ]
    }
  }

  # -- 5. TLS only -------------------------------------------------------------
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = data.aws_iam_policy_document.evidence.json

  # Public access block lands first. If this policy were ever judged to grant
  # public access, block_public_policy rejects the PutBucketPolicy call, and a
  # loud failure here is the outcome we want.
  depends_on = [aws_s3_bucket_public_access_block.evidence]
}
