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
