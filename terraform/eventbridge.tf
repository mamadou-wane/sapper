resource "aws_cloudwatch_event_rule" "securityhub_findings" {
  name        = "sapper-securityhub-findings"
  description = "Matches real Security Hub CSPM findings for sapper proposer"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
  })
}
