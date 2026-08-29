data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {}

# The Identity Center permission-set role carries a generated suffix that changes
# if the permission set is deleted and re-provisioned, so it is resolved rather
# than typed.
#
# Three things here carry the design:
#   1. name_regex is filtered client-side with Go's MatchString, which is
#      UNANCHORED. Without ^...$ this would also match a hypothetical
#      AWSReservedSSO_AdministratorAccessReadOnly_... role.
#   2. one() on an empty set returns null rather than erroring, which would put a
#      null principal in the approver's trust policy. The postcondition fails the
#      plan instead.
#   3. No region argument. aws_iam_roles is region-disabled in provider v6.
#
# Failure mode: if the permission set is re-provisioned, assuming sapper-approver
# starts returning AccessDenied. Recovery is one `make boundary-apply`.
data "aws_iam_roles" "sso_admin" {
  name_regex  = "^AWSReservedSSO_AdministratorAccess_[0-9a-zA-Z]+$"
  path_prefix = "/aws-reserved/sso.amazonaws.com/"

  lifecycle {
    postcondition {
      condition     = length(self.arns) == 1
      error_message = "Expected exactly one AdministratorAccess Identity Center role, found ${length(self.arns)}. Zero usually means the path_prefix is wrong; more than one means the regex needs narrowing."
    }
  }
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  # The operator's admin principal. Trusted by the threat model, and the only
  # principal that can assume sapper-approver.
  admin_role_arn = one(data.aws_iam_roles.sso_admin.arns)

  # Permanent. PLAN.md §8: created once, never recreated. Generated from the
  # caller's account so a clone in another account produces its own unique name.
  evidence_bucket = "sapper-evidence-${local.account_id}"

  # The lab target lives in the main stack (terraform/lab.tf), which is torn down
  # between evidence windows. Constructing the ARN from the same naming rule
  # avoids a cross-module state dependency on a stack that may not exist.
  lab_bucket_arns = [
    "arn:${local.partition}:s3:::sapper-lab-public-${local.account_id}",
  ]

  # The proposer function's log group, created by the main stack alongside the
  # function (PLAN.md §12) under Lambda's fixed naming rule, so the ARN is
  # constructed here for the same reason the lab bucket ARN is.
  proposer_log_group_arn = "arn:${local.partition}:logs:${data.aws_region.current.region}:${local.account_id}:log-group:/aws/lambda/sapper-proposer"
}
