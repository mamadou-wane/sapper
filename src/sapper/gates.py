"""The hardened gate chain, field half (PLAN.md §3): Gates 0-4 plus the
suppressed drop, evaluated in order with short-circuit on first drop.

Cheap field checks only. Gate 5, the live-state read, makes the one AWS call and
lives in its own function so these stay pure and fast. Gate 5b (incarnation) was
retired from the R1 contract 2026-08-26; PRODUCTION_GAP.md records why.
"""

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from botocore.exceptions import ClientError

from sapper.findings import Finding

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

GENERATOR_ID_PREFIX = "security-control/"
NO_BPA_CONFIGURATION_ERROR = "NoSuchPublicAccessBlockConfiguration"


class DropReason(Enum):
    PROVENANCE = "PROVENANCE"
    CONTROL_ID = "CONTROL_ID"
    SUPPRESSED = "SUPPRESSED"
    COMPLIANCE_STATUS = "COMPLIANCE_STATUS"
    RECORD_STATE = "RECORD_STATE"
    SCOPE = "SCOPE"
    STALE_FINDING = "STALE_FINDING"


@dataclass(frozen=True)
class Drop:
    reason: DropReason
    detail: str


def native_product_arn(region: str) -> str:
    # Derived from the finding's own region rather than hardcoded, so a second
    # region does not silently drop everything (§3 Gate 0).
    return f"arn:aws:securityhub:{region}::product/aws/securityhub"


def evaluate_field_gates(
    finding: Finding,
    allowed_controls: frozenset[str],
    scope_arns: frozenset[str],
) -> Drop | None:
    if finding.product_arn != native_product_arn(finding.region) or not (
        finding.generator_id.startswith(GENERATOR_ID_PREFIX)
    ):
        return Drop(
            DropReason.PROVENANCE,
            f"ProductArn {finding.product_arn!r} / GeneratorId {finding.generator_id!r}",
        )
    if finding.security_control_id not in allowed_controls:
        return Drop(DropReason.CONTROL_ID, f"control {finding.security_control_id!r} not allowed")
    if finding.workflow_status == "SUPPRESSED":
        return Drop(DropReason.SUPPRESSED, "a human suppressed this finding")
    if finding.compliance_status != "FAILED":
        return Drop(DropReason.COMPLIANCE_STATUS, f"status {finding.compliance_status!r}")
    if finding.record_state != "ACTIVE":
        return Drop(DropReason.RECORD_STATE, f"record state {finding.record_state!r}")
    if finding.resource_arn not in scope_arns:
        return Drop(DropReason.SCOPE, f"resource {finding.resource_arn!r} outside lab scope")
    return None


@dataclass(frozen=True)
class FreshnessResult:
    drop: Drop | None
    before_state: dict[str, bool] | None


def evaluate_freshness_gate(finding: Finding, s3_client: "S3Client") -> FreshnessResult:
    """Gate 5 (§3): the one AWS call. The read is both the freshness gate and the
    proposal's before-state. The S3.8 predicate is "the fix this plan would apply
    is still needed": at least one Block Public Access flag false."""
    bucket_name = finding.resource_arn.rpartition(":")[2]
    try:
        flags = s3_client.get_public_access_block(Bucket=bucket_name)[
            "PublicAccessBlockConfiguration"
        ]
        before_state = {
            "configuration_present": True,
            "block_public_acls": flags["BlockPublicAcls"],
            "ignore_public_acls": flags["IgnorePublicAcls"],
            "block_public_policy": flags["BlockPublicPolicy"],
            "restrict_public_buckets": flags["RestrictPublicBuckets"],
        }
    except ClientError as exc:
        # Raised when no BPA configuration exists at all, which is precisely a
        # state needing remediation (§3): all four flags false, and the absence
        # recorded so the plan and rollback know there was nothing to restore.
        if exc.response["Error"]["Code"] != NO_BPA_CONFIGURATION_ERROR:
            raise
        before_state = {
            "configuration_present": False,
            "block_public_acls": False,
            "ignore_public_acls": False,
            "block_public_policy": False,
            "restrict_public_buckets": False,
        }
    flag_names = (
        "block_public_acls",
        "ignore_public_acls",
        "block_public_policy",
        "restrict_public_buckets",
    )
    if all(before_state[name] for name in flag_names):
        return FreshnessResult(
            Drop(DropReason.STALE_FINDING, "all four BPA flags already true; drift is gone"),
            None,
        )
    return FreshnessResult(None, before_state)
