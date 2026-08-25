# ---------------------------------------------------------------------------
# Runtime execution roles
#
# Both trust lambda.amazonaws.com for their eventual runtime use, and also the
# operator's admin principal (D7). A negative test can only prove a role is
# denied by acting as that role, so P1.5's proposer probes and six of P5's eight
# tests assume these roles from the operator's terminal.
#
# The consequence, disclosed in PRODUCTION_GAP.md rather than left implied: an
# admin can chain admin -> sapper-remediator -> sapper-remediation and mutate a
# target with no approval written. PLAN.md §5 already places the account
# administrator outside the bound, so this adds a path to a case already
# declared out of scope. What it buys is that every captured AccessDenied in
# this repo is reproducible by a reader with the same account.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "runtime_trust" {
  statement {
    sid     = "LambdaRuntime"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }

  statement {
    sid     = "OperatorRunsTheNegativeSuite"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [local.admin_role_arn]
    }
  }
}

resource "aws_iam_role" "proposer" {
  name               = "sapper-proposer"
  description        = "Reads findings and live state, writes proposals and locks. Holds no path to a target mutation or an approval."
  assume_role_policy = data.aws_iam_policy_document.runtime_trust.json
}

resource "aws_iam_role" "remediator" {
  name               = "sapper-remediator"
  description        = "Execution role of the remediator function (P4). Its only privilege is assuming the bounded role."
  assume_role_policy = data.aws_iam_policy_document.runtime_trust.json
}

# ---------------------------------------------------------------------------
# The bounded remediation role
#
# Its sole trust principal is the remediator's execution role (PLAN.md §7,
# D4-b). Not the account root, not a human, and specifically not
# sapper-approver. That is what makes writing an approval object the only way to
# cause an apply, rather than merely the customary way.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "remediation_trust" {
  statement {
    sid     = "OnlyTheRemediatorFunction"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.remediator.arn]
    }
  }
}

resource "aws_iam_role" "remediation" {
  name        = "sapper-remediation"
  description = "The bounded role. Mutates exactly one allowlisted bucket through one API, and writes its own evidence."

  assume_role_policy = data.aws_iam_policy_document.remediation_trust.json

  # Attached at creation, in the same apply that creates the role. A bounded
  # role that exists unbounded for even one apply is a window.
  permissions_boundary = aws_iam_policy.remediation_boundary.arn
}

# ---------------------------------------------------------------------------
# The approver
#
# A dedicated role rather than the admin session. PLAN.md §5: the only Identity
# Center permission set on this account is AdministratorAccess, and an admin is
# denied nothing, which would make every approver-side denial in P5 untestable
# and the D4-b claim false.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "approver_trust" {
  statement {
    sid     = "OperatorAssumesApprover"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [local.admin_role_arn]
    }
  }
}

resource "aws_iam_role" "approver" {
  name               = "sapper-approver"
  description        = "Writes approvals and reads proposals. Holds no mutating permission and no path to the bounded role."
  assume_role_policy = data.aws_iam_policy_document.approver_trust.json
}
