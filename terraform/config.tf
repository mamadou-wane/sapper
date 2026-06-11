resource "aws_iam_role" "config" {
  name = "sapper-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_s3_bucket" "config_delivery" {
  #checkov:skip=CKV_AWS_144: single-region lab delivery bucket; cross-region replication is out of scope for Phase 1
  #checkov:skip=CKV_AWS_145: lab delivery bucket uses SSE-S3; KMS adds cost without Phase 1 threat-model benefit
  #checkov:skip=CKV_AWS_18: access logging deferred for lab delivery bucket; bucket policy, BPA, and encryption are the controls here
  #checkov:skip=CKV_AWS_21: Config delivery bucket is ephemeral AWS Config delivery output and force-destroyed by Terraform
  #checkov:skip=CKV2_AWS_61: lifecycle policy deferred; Config delivery bucket stores temporary AWS Config delivery output for Phase 1
  #checkov:skip=CKV2_AWS_62: Event notifications are out of scope for the AWS Config delivery bucket

  bucket        = "sapper-config-delivery-116137268889"
  force_destroy = true

  # This bucket only stores AWS Config delivery objects for the lab.
  # force_destroy is intentional so terraform destroy can fully tear down
  # continuously billing detective services without being blocked by delivered objects.
}

resource "aws_s3_bucket_public_access_block" "config_delivery" {
  bucket = aws_s3_bucket.config_delivery.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_delivery" {
  bucket = aws_s3_bucket.config_delivery.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "config_delivery" {
  statement {
    sid    = "AWSConfigBucketPermissionsCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions = ["s3:GetBucketAcl"]

    resources = [
      aws_s3_bucket.config_delivery.arn
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = ["116137268889"]
    }
  }

  statement {
    sid    = "AWSConfigBucketExistenceCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions = ["s3:ListBucket"]

    resources = [
      aws_s3_bucket.config_delivery.arn
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = ["116137268889"]
    }
  }

  statement {
    sid    = "AWSConfigBucketDelivery"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions = ["s3:PutObject"]

    resources = [
      "${aws_s3_bucket.config_delivery.arn}/AWSLogs/116137268889/Config/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = ["116137268889"]
    }
  }
}

resource "aws_s3_bucket_policy" "config_delivery" {
  bucket = aws_s3_bucket.config_delivery.id
  policy = data.aws_iam_policy_document.config_delivery.json
}

resource "aws_config_configuration_recorder" "main" {
  #checkov:skip=CKV2_AWS_45: Phase 1 intentionally scopes AWS Config to S3 buckets and EC2 security groups as a cost guard

  name     = "sapper-config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types = [
      "AWS::S3::Bucket",
      "AWS::EC2::SecurityGroup",
    ]
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "sapper-config-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config_delivery.bucket

  depends_on = [
    aws_config_configuration_recorder.main,
    aws_s3_bucket_policy.config_delivery
  ]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [
    aws_config_delivery_channel.main
  ]
}
