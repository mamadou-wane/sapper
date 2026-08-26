"""Gate 5, the freshness/live-state read (§3), under moto.

Where the moto line falls (PLAN.md §12): moto 5.0.14+ implements If-None-Match on
put_object and raises NoSuchPublicAccessBlockConfiguration like real S3, but moto
never evaluates bucket policies. So these tests prove parsing, gate order, drop
reasons, and client-side error handling. They prove nothing about what the bucket
policy enforces; live AWS is the only place a policy outcome is proven, which is
what P1.5 proved and P5 will prove again.
"""

from typing import Any

import boto3
import pytest
from moto import mock_aws

from sapper.findings import parse_finding
from sapper.gates import DropReason, evaluate_freshness_gate

LAB_BUCKET = "sapper-lab-public-116137268889"


@pytest.fixture()
def s3_client() -> Any:
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=LAB_BUCKET)
        yield client


def set_bpa(client: Any, **flags: bool) -> None:
    client.put_public_access_block(
        Bucket=LAB_BUCKET,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": flags.get("block_public_acls", False),
            "IgnorePublicAcls": flags.get("ignore_public_acls", False),
            "BlockPublicPolicy": flags.get("block_public_policy", False),
            "RestrictPublicBuckets": flags.get("restrict_public_buckets", False),
        },
    )


def test_drifted_bucket_passes_with_before_state(
    raw_finding: dict[str, Any], s3_client: Any
) -> None:
    # One flag false is enough: the predicate is "the fix is still needed" (§3).
    set_bpa(s3_client, block_public_acls=True, ignore_public_acls=True, block_public_policy=True)

    result = evaluate_freshness_gate(parse_finding(raw_finding), s3_client)

    assert result.before_state == {
        "configuration_present": True,
        "block_public_acls": True,
        "ignore_public_acls": True,
        "block_public_policy": True,
        "restrict_public_buckets": False,
    }


def test_fully_compliant_bucket_drops_stale_finding(
    raw_finding: dict[str, Any], s3_client: Any
) -> None:
    set_bpa(
        s3_client,
        block_public_acls=True,
        ignore_public_acls=True,
        block_public_policy=True,
        restrict_public_buckets=True,
    )

    result = evaluate_freshness_gate(parse_finding(raw_finding), s3_client)

    assert result.drop is not None and result.drop.reason is DropReason.STALE_FINDING


def test_absent_bpa_configuration_is_the_drifted_state(
    raw_finding: dict[str, Any], s3_client: Any
) -> None:
    # GetPublicAccessBlock raises NoSuchPublicAccessBlockConfiguration when no
    # configuration exists at all, which is precisely a state needing remediation:
    # caught and recorded as all four false, configuration_present False (§3).
    result = evaluate_freshness_gate(parse_finding(raw_finding), s3_client)

    assert result.before_state == {
        "configuration_present": False,
        "block_public_acls": False,
        "ignore_public_acls": False,
        "block_public_policy": False,
        "restrict_public_buckets": False,
    }


def test_pass_result_carries_no_drop(raw_finding: dict[str, Any], s3_client: Any) -> None:
    result = evaluate_freshness_gate(parse_finding(raw_finding), s3_client)

    assert result.drop is None
