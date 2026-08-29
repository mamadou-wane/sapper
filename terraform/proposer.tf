# ---------------------------------------------------------------------------
# The proposer function (PLAN.md §3, §4, §12; ruled 2026-08-26 and 2026-08-28).
#
# The durable role and the evidence bucket come from the boundary module and
# are looked up by name rather than through its remote state, so this stack,
# torn down between evidence windows, has no state dependency on the one that
# is not. The rule in eventbridge.tf existed target-less; this file connects it.
# ---------------------------------------------------------------------------

data "aws_iam_role" "proposer" {
  name = "sapper-proposer"
}

data "aws_s3_bucket" "evidence" {
  bucket = "sapper-evidence-116137268889"
}

locals {
  # PLAN.md §4: CLAIM_TTL = lambda_timeout + M, M > 1 s, sum at most 30 s. The
  # handler derives CLAIM_TTL from these two and refuses a sum past the ceiling
  # at init. The timeout has one source: this local feeds both the function's
  # timeout and its environment.
  proposer_timeout_seconds = 10
  claim_margin_seconds     = 5

  # A blast-radius cap on a rule that fires per finding. A first-enable burst
  # is throttled and retried from Lambda's async queue, nearly all of it drops
  # at Gate 1 (§3), and a throttled invocation takes no claim (§4).
  proposer_reserved_concurrency = 5
}

data "archive_file" "proposer" {
  type        = "zip"
  source_dir  = "${path.module}/../build/proposer"
  output_path = "${path.module}/../build/proposer.zip"
  # Entry modes come from wheel metadata, not the workstation umask; pinning
  # them keeps the checksum the same from any machine (provider docs).
  output_file_mode = "0644"
}

resource "aws_cloudwatch_log_group" "proposer" {
  #checkov:skip=CKV_AWS_158: proposer logs carry finding ids, drop reasons, and the PROVENANCE metric line, no secrets; KMS adds cost without a threat-model benefit
  #checkov:skip=CKV_AWS_338: 30-day retention, ruled 2026-08-28; the stack is torn down between evidence windows and the banked evidence lives in the repo, not in these logs

  name              = "/aws/lambda/sapper-proposer"
  retention_in_days = 30
}

resource "aws_lambda_function" "proposer" {
  #checkov:skip=CKV_AWS_50: X-Ray tracing is out of scope for a single-function lab; the structured line per finding is the trace
  #checkov:skip=CKV_AWS_116: the async on-failure destination is an event-invoke config, not a dead-letter config, and lands in P3 (PLAN.md §9)
  #checkov:skip=CKV_AWS_117: the function reaches S3 only and no VPC resources exist in the lab
  #checkov:skip=CKV_AWS_173: the environment carries a bucket name, a bucket ARN, and two integers, nothing a KMS key would protect
  #checkov:skip=CKV_AWS_272: code signing is out of scope for a lab deployed from a pinned, locally built tree

  function_name = "sapper-proposer"
  description   = "Detect and propose. Holds no path to a target mutation or an approval."
  role          = data.aws_iam_role.proposer.arn
  runtime       = "python3.12"
  architectures = ["x86_64"]
  handler       = "sapper.handler.handle"

  filename         = data.archive_file.proposer.output_path
  source_code_hash = data.archive_file.proposer.output_base64sha256

  timeout                        = local.proposer_timeout_seconds
  memory_size                    = 256
  reserved_concurrent_executions = local.proposer_reserved_concurrency

  environment {
    variables = {
      EVIDENCE_BUCKET          = data.aws_s3_bucket.evidence.bucket
      SCOPE_ARNS               = aws_s3_bucket.lab.arn
      PROPOSER_TIMEOUT_SECONDS = tostring(local.proposer_timeout_seconds)
      CLAIM_MARGIN_SECONDS     = tostring(local.claim_margin_seconds)
    }
  }

  # The PROVENANCE metric rides the function's own log lines in embedded metric
  # format (§3). Text format passes every printed line through unfiltered;
  # under JSON format an application log level above INFO would drop the
  # metric line and blind P3's alarm. P3 carries that constraint. The group is
  # bound by reference: the role holds no logs:CreateLogGroup (boundary,
  # WriteItsOwnLogs), so it has to exist before the first invocation, and the
  # reference orders the creation.
  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.proposer.name
  }
}

resource "aws_cloudwatch_event_target" "proposer" {
  rule = aws_cloudwatch_event_rule.securityhub_findings.name
  arn  = aws_lambda_function.proposer.arn
}

resource "aws_lambda_permission" "securityhub_findings_rule" {
  statement_id  = "AllowSecurityHubFindingsRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.proposer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.securityhub_findings.arn
}
