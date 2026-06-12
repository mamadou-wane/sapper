# runbook: AWS Config substrate

Related ADR: `adr/0002-inline-checkov-suppressions.md`

## Purpose

T4 builds the AWS Config foundation for sapper. It brings AWS Config under Terraform control, scoped to the two resource types Phase 1 needs:

- AWS::S3::Bucket
- AWS::EC2::SecurityGroup

This keeps the detective layer aligned with the lab scope and avoids recording the entire account.

## What T4 creates

1. AWS Config service role
2. AWS Config delivery bucket
3. Public access block for the delivery bucket
4. Server-side encryption for the delivery bucket
5. Bucket policy allowing AWS Config delivery
6. AWS Config configuration recorder
7. AWS Config delivery channel
8. AWS Config recorder status

Main file: `terraform/config.tf`

## T4.1: AWS Config service role

### Resource

```hcl
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
```

### Verification

```bash
aws iam get-role --role-name sapper-config-role
aws iam list-attached-role-policies --role-name sapper-config-role
```

Expected:

```
Trust principal: config.amazonaws.com
Attached policy: arn:aws:iam::aws:policy/service-role/AWS_ConfigRole
Tags: Project=sapper, Environment=lab
```

## T4.2: AWS Config delivery bucket

### Resource

```hcl
resource "aws_s3_bucket" "config_delivery" {
  bucket        = "sapper-config-delivery-116137268889"
  force_destroy = true
  # This bucket only stores AWS Config delivery objects for the lab.
  # force_destroy is intentional so terraform destroy can fully tear down
  # continuously billing detective services without being blocked by delivered objects.
}
```

### Why force_destroy = true

AWS Config writes delivery objects into this bucket, and a non-empty S3 bucket blocks `terraform destroy` until the objects are removed. Because this is an ephemeral lab, `force_destroy = true` is intentional. It preserves the project rule that `terraform destroy` / `make destroy` must be able to tear down the full detective stack without leaving billing residue behind.

## T4.3: Delivery bucket hardening

### Public access block

```hcl
resource "aws_s3_bucket_public_access_block" "config_delivery" {
  bucket = aws_s3_bucket.config_delivery.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
```

### Server-side encryption

```hcl
resource "aws_s3_bucket_server_side_encryption_configuration" "config_delivery" {
  bucket = aws_s3_bucket.config_delivery.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
```

### Verification

```bash
aws s3api get-public-access-block \
  --bucket sapper-config-delivery-116137268889
```

Expected:

```json
{
  "PublicAccessBlockConfiguration": {
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }
}
```

Check encryption:

```bash
aws s3api get-bucket-encryption \
  --bucket sapper-config-delivery-116137268889
```

Expected: `SSEAlgorithm = AES256`

## T4.4: Delivery bucket policy

### Resource

```hcl
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
```

### What the policy allows

The AWS Config service principal can check the bucket ACL, check bucket existence, and write delivery objects under `AWSLogs/116137268889/Config/*`. All three statements require `aws:SourceAccount = 116137268889`, and object delivery requires `s3:x-amz-acl = bucket-owner-full-control`.

### Verification

```bash
aws s3api get-bucket-policy \
  --bucket sapper-config-delivery-116137268889
```

## T4.5: Scoped configuration recorder

### Resource

```hcl
resource "aws_config_configuration_recorder" "main" {
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
```

### Scope decision

The recorder is scoped to exactly two resource types: `AWS::S3::Bucket` and `AWS::EC2::SecurityGroup`. This is the Phase 1 cost guard. The recorder does not monitor all supported resources and does not include global resource types.

## T4.6: Delivery channel

### Resource

```hcl
resource "aws_config_delivery_channel" "main" {
  name           = "sapper-config-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config_delivery.bucket
  depends_on = [
    aws_config_configuration_recorder.main,
    aws_s3_bucket_policy.config_delivery
  ]
}
```

### Dependency note

AWS Config can race during creation. A failed apply occurred when Terraform attempted to create the delivery channel before AWS Config considered the recorder available. The fix was to make the delivery channel explicitly depend on `aws_config_configuration_recorder.main` and `aws_s3_bucket_policy.config_delivery`. Details under "Known issue encountered" below.

## T4.7: Recorder status

### Resource

```hcl
resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [
    aws_config_delivery_channel.main
  ]
}
```

### Why it depends on the delivery channel

AWS Config cannot start recording until a delivery channel exists. This dependency keeps recorder startup sequenced after the delivery channel.

## Validation commands

```bash
terraform -chdir=terraform fmt
terraform -chdir=terraform validate
terraform -chdir=terraform plan
```

Expected after completion:

```
No changes. Your infrastructure matches the configuration.
```

## AWS verification commands

Check the recorder:

```bash
aws configservice describe-configuration-recorders
```

Expected:

```
name: sapper-config-recorder
roleARN: arn:aws:iam::116137268889:role/sapper-config-role
allSupported: false
includeGlobalResourceTypes: false
resourceTypes:
  - AWS::EC2::SecurityGroup
  - AWS::S3::Bucket
recordingStrategy: INCLUSION_BY_RESOURCE_TYPES
recordingScope: PAID
```

Check the delivery channel:

```bash
aws configservice describe-delivery-channels
```

Expected:

```
name: sapper-config-delivery-channel
s3BucketName: sapper-config-delivery-116137268889
```

Check recorder status:

```bash
aws configservice describe-configuration-recorder-status
```

Expected:

```
recording: true
lastStatus: SUCCESS
```

Immediately after creation, `lastStatus` may briefly show `PENDING`. That is acceptable during startup.

## Known issue encountered

During the first apply of the recorder/channel/status block, Terraform created the recorder but AWS Config rejected the delivery channel:

```
NoAvailableConfigurationRecorderException:
Configuration recorder is not available to put delivery channel.
```

### Cause

AWS Config had not yet made the newly created recorder available by the time Terraform attempted to create the delivery channel.

### Fix

Add the recorder to the delivery channel dependency list:

```hcl
depends_on = [
  aws_config_configuration_recorder.main,
  aws_s3_bucket_policy.config_delivery
]
```

After this change, Terraform planned only the remaining two resources: `aws_config_delivery_channel.main` and `aws_config_configuration_recorder_status.main`.

## Delivery proof

AWS Config delivery was proven by listing objects under:

```text
s3://sapper-config-delivery-116137268889/AWSLogs/116137268889/Config/
```

Observed objects included:

```text
AWSLogs/116137268889/Config/ConfigWritabilityCheckFile
AWSLogs/116137268889/Config/us-east-1/2026/6/11/ConfigHistory/...AWS::Config::ConfigurationRecorder...
AWSLogs/116137268889/Config/us-east-1/2026/6/11/ConfigHistory/...AWS::S3::Bucket...
```

This proves:

```text
AWS Config recorder -> delivery channel -> S3 bucket policy -> S3 object delivery
```

## Git commits

T4 was committed in small checkpoints:

```
infra: add aws config service role
infra: add aws config delivery bucket
infra: allow aws config delivery to s3
infra: add scoped aws config recorder
```

## T4 addendum: Checkov suppression refactor

### Problem

After the Config substrate landed, CI failed: Checkov flagged controls that are intentionally out of scope for the Phase 1 lab. The first fix was a global `skip_check` list in `.github/workflows/ci.yml`. That made CI green and blinded the gate at the same time, because every future resource would inherit the same exemptions. The clearest risk is the evidence-storage resources coming later, where versioning, lifecycle rules, and access logging will likely be required.

### Decision

The global skips are removed. Each suppression is declared inline on the exact Terraform resource it applies to, with a written reason. The gate keeps evaluating everything built after this, and each exception carries its reason in the code.

### Final CI pattern

The workflow runs a pinned Checkov CLI in place of the mutable `bridgecrewio/checkov-action@master`, so a moving upstream tag cannot change the gate's behavior between runs:

```yaml
- name: Install Checkov
  run: pipx install checkov==3.2.530

- name: Run Checkov
  run: checkov -d terraform --skip-path terraform/bootstrap
```

One path-level exclusion remains: `terraform/bootstrap`. Bootstrap creates the remote-state foundation and sits outside the runtime lab guardrail surface.

### Suppression syntax

Inline, on the resource, with a reason:

```
#checkov:skip=<CHECK_ID>: <reason>
```

### What is suppressed and why

S3 checks suppressed on both lab buckets:

| Check | Control |
|---|---|
| CKV_AWS_18 | Access logging |
| CKV_AWS_21 | Versioning |
| CKV_AWS_144 | Cross-region replication |
| CKV_AWS_145 | KMS encryption |
| CKV2_AWS_61 | Lifecycle policy |
| CKV2_AWS_62 | Event notifications |

| Resource | Suppressed checks | Reason |
|---|---|---|
| Config delivery bucket | All six S3 checks above | Temporary AWS Config delivery output for the Phase 1 lab, force-destroyed by Terraform on teardown. The durable evidence bucket is a separate future resource. |
| Lab target bucket | All six S3 checks above | Intentionally minimal detection target for the Phase 1 drift demonstration. Stores no durable evidence. |
| Config recorder | CKV2_AWS_45, CKV2_AWS_48 | Phase 1 deliberately scopes the recorder to `AWS::S3::Bucket` and `AWS::EC2::SecurityGroup` as the cost and scope guard. Recording all supported resources is out of scope by design. |
| Recorder status | CKV2_AWS_45 | Checkov evaluates the enabled recorder status under the same graph-level control. The recorder is enabled and intentionally scoped. |

### Terminology

The AWS Config delivery bucket is never called an evidence bucket, in docs or in code. The delivery bucket holds temporary service output and dies with the stack. The future evidence bucket is a separate resource and will likely require versioning, delete protection, a lifecycle policy, and tighter access controls. Naming the two the same thing is how the wrong suppressions end up on the wrong bucket.

### Result

- Global `skip_check`: removed
- Checkov CLI: pinned to 3.2.530
- Suppressions: inline and resource-scoped, each with a written reason
- Terraform plan: clean
- CI: green
- Checks on future resources: preserved

### Lesson

CI went green twice here. The first green hid the findings behind a global skip; the second documented each one on the resource it belongs to. Only the second counts.

A suppression is acceptable when all four hold:

1. It is tied to one specific resource.
2. It carries a written reason.
3. The reason matches the project threat model.
4. It leaves the scanner active for future resources.

The global skip failed the first and the fourth.

## Next step

T4 is complete. Next is T5: Terraform-managed Security Hub + FSBP, sequenced after T4 because Security Hub needs the AWS Config substrate in place for standards and control evaluation.
