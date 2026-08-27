# ---------------------------------------------------------------------------
# sapper-proposer
#
# The four explicit denies of PLAN.md §7. An omitted permission and a denied
# permission look identical at runtime only while nothing else grants the
# action. The explicit deny is what keeps the bound provable against a future
# policy addition, and what P5 tests.
#
# Deferred, each owned by the slice that creates the resource:
#   P2: logs:CreateLogStream, logs:PutLogEvents on its own log group
#   P3: sqs:SendMessage to sapper-proposer-failures
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "proposer" {
  statement {
    sid       = "ReadLiveStateForTheFreshnessGate"
    effect    = "Allow"
    actions   = ["s3:GetBucketPublicAccessBlock"]
    resources = local.lab_bucket_arns
  }

  statement {
    sid     = "WriteProposalsAndLocks"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.evidence.arn}/proposals/*",
      "${aws_s3_bucket.evidence.arn}/locks/*",
    ]

    # Requires the header to be PRESENT. This is belt to the bucket policy's
    # braces: the bucket is what enforces create-only for every principal, and
    # this keeps the role's own grant honest about what it is for.
    #
    # Side effect: every identity grant carrying this Null s3:if-none-match
    # condition makes multipart upload impossible for that role, because
    # UploadPart cannot send the header. Deliberate, and fine for small JSON
    # records; the bucket policy's s3:ObjectCreationOperation carve-out exists
    # for principals with unconditioned grants, such as the operator.
    condition {
      test     = "Null"
      variable = "s3:if-none-match"
      values   = ["false"]
    }
  }

  # §4's 412 path decides lease expiry by reading the lock object's body; S3
  # lifecycle cannot decide it, because deletion is asynchronous and an expired
  # object still reads. The first build granted the write and the list but no
  # read, so that path could never run. Ruled R-A, 2026-08-26: read the locks
  # prefix and nothing else. proposals/* and approvals/* stay unreadable.
  statement {
    sid       = "ReadItsOwnLocks"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/locks/*"]
  }

  # Scoped to the proposer's own write set. PLAN.md §7 said "prefix-scoped"
  # without naming the prefixes, so the first build shipped this grant unscoped
  # and the proposer could list every key in the store, including approvals/.
  # Ruled at R10, 2026-08-25: scope it, and enumerate the prefixes in §7.
  #
  # This change post-dates the banked probe run. No capture is invalidated: the
  # probe never calls ListBucket.
  statement {
    sid       = "ListItsOwnPrefixes"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.evidence.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["proposals/*", "locks/*"]
    }
  }

  statement {
    sid       = "DenyTargetMutation"
    effect    = "Deny"
    actions   = ["s3:PutBucketPublicAccessBlock"]
    resources = ["*"]
  }

  statement {
    sid    = "DenySecurityHubWrites"
    effect = "Deny"
    actions = [
      "securityhub:BatchUpdateFindings",
      "securityhub:BatchImportFindings",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "DenyApprovalForgery"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/approvals/*"]
  }

  statement {
    sid    = "DenyPrivilegeEscalation"
    effect = "Deny"
    actions = [
      "sts:AssumeRole",
      "iam:PassRole",
    ]
    resources = [aws_iam_role.remediation.arn]
  }
}

resource "aws_iam_role_policy" "proposer" {
  name   = "sapper-proposer"
  role   = aws_iam_role.proposer.id
  policy = data.aws_iam_policy_document.proposer.json
}

# ---------------------------------------------------------------------------
# sapper-remediator (the execution role, not the bounded role)
#
# Its entire purpose is assuming the bounded role. The two denies are a
# deliberate strengthening beyond §7, which enumerates denies for the proposer
# only: they make "the remediator reaches a target only through the bounded
# role" an enforced statement rather than an absence.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "remediator" {
  statement {
    sid       = "AssumeTheBoundedRole"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.remediation.arn]
  }

  statement {
    sid       = "DenyDirectTargetMutation"
    effect    = "Deny"
    actions   = ["s3:PutBucketPublicAccessBlock"]
    resources = ["*"]
  }

  statement {
    sid       = "DenyApprovalForgery"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/approvals/*"]
  }
}

resource "aws_iam_role_policy" "remediator" {
  name   = "sapper-remediator"
  role   = aws_iam_role.remediator.id
  policy = data.aws_iam_policy_document.remediator.json
}

# ---------------------------------------------------------------------------
# sapper-remediation (the bounded role)
#
# The grant. The permissions boundary in boundary.tf is the ceiling; both are
# required, and effective permissions are their intersection.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "remediation" {
  statement {
    sid    = "ApplyTheFix"
    effect = "Allow"
    actions = [
      "s3:PutBucketPublicAccessBlock",
      "s3:GetBucketPublicAccessBlock",
    ]
    resources = local.lab_bucket_arns
  }

  statement {
    sid     = "ReadTheDecision"
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = [
      "${aws_s3_bucket.evidence.arn}/proposals/*",
      "${aws_s3_bucket.evidence.arn}/approvals/*",
    ]
  }

  statement {
    sid     = "WriteItsOwnEvidence"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.evidence.arn}/consumed/*",
      "${aws_s3_bucket.evidence.arn}/applied/*",
      "${aws_s3_bucket.evidence.arn}/rollback/*",
    ]

    condition {
      test     = "Null"
      variable = "s3:if-none-match"
      values   = ["false"]
    }
  }

  statement {
    sid       = "ListEvidence"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.evidence.arn]
  }
}

resource "aws_iam_role_policy" "remediation" {
  name   = "sapper-remediation"
  role   = aws_iam_role.remediation.id
  policy = data.aws_iam_policy_document.remediation.json
}

# ---------------------------------------------------------------------------
# sapper-approver
#
# PLAN.md §5 lists four grants and says "Nothing else." The count was three
# until 2026-08-25, when s3:GetObjectVersion was added: approvals pin
# proposal_version_id on a versioned bucket, and s3:GetObject alone cannot read
# a specific version. §5 says nothing about denies.
#
# The two denies below are a deliberate strengthening past that list: P5 tests
# approver target mutation and approver sts:AssumeRole on the bounded role, and
# an implicit deny would satisfy both tests today while silently weakening if
# this role ever gains a broader grant.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "approver" {
  statement {
    sid       = "WriteApprovalsCreateOnly"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/approvals/*"]

    condition {
      test     = "Null"
      variable = "s3:if-none-match"
      values   = ["false"]
    }
  }

  statement {
    sid       = "ReadProposals"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.evidence.arn}/proposals/*"]
  }

  statement {
    sid       = "ListProposalsOnly"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.evidence.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["proposals/*"]
    }
  }

  statement {
    sid       = "DenyTargetMutation"
    effect    = "Deny"
    actions   = ["s3:PutBucketPublicAccessBlock"]
    resources = ["*"]
  }

  statement {
    sid       = "DenyPathToTheBoundedRole"
    effect    = "Deny"
    actions   = ["sts:AssumeRole", "iam:PassRole"]
    resources = [aws_iam_role.remediation.arn]
  }
}

resource "aws_iam_role_policy" "approver" {
  name   = "sapper-approver"
  role   = aws_iam_role.approver.id
  policy = data.aws_iam_policy_document.approver.json
}
