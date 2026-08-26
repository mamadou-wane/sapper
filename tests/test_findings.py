"""findings.py is the one place raw ASFF is read; everything downstream consumes
the parsed shape. These tests pin the contract to the banked fixture."""

from typing import Any

import pytest

from sapper.findings import FindingParseError, parse_finding


def test_parses_the_banked_fixture(raw_finding: dict[str, Any]) -> None:
    finding = parse_finding(raw_finding)

    assert finding.finding_id == (
        "arn:aws:securityhub:us-east-1:116137268889:"
        "security-control/S3.8/finding/d9e45e0f-a518-4110-88ea-66821b2c7bd9"
    )
    assert finding.product_arn == "arn:aws:securityhub:us-east-1::product/aws/securityhub"
    assert finding.generator_id == "security-control/S3.8"
    assert finding.security_control_id == "S3.8"
    assert finding.compliance_status == "FAILED"
    assert finding.record_state == "ACTIVE"
    assert finding.workflow_status == "NEW"
    assert finding.region == "us-east-1"
    assert finding.resource_arn == "arn:aws:s3:::sapper-lab-public-116137268889"
    assert finding.resource_type == "AwsS3Bucket"
    assert finding.updated_at == "2026-06-26T01:22:15.937Z"


def test_missing_resource_details_still_parses(raw_finding: dict[str, Any]) -> None:
    # AWS strips Resource.Details from findings above 240 KB: absent Details is
    # normal, not malformed. Nothing in the parsed shape depends on it (Gate 5b
    # retired 2026-08-26; PRODUCTION_GAP.md).
    del raw_finding["Resources"][0]["Details"]

    finding = parse_finding(raw_finding)

    assert finding.resource_arn == "arn:aws:s3:::sapper-lab-public-116137268889"


def test_missing_workflow_block_parses_with_none_status(raw_finding: dict[str, Any]) -> None:
    # Workflow.Status only ever drops on SUPPRESSED; a finding without the block
    # must still parse and pass that gate.
    del raw_finding["Workflow"]

    finding = parse_finding(raw_finding)

    assert finding.workflow_status is None


@pytest.mark.parametrize(
    "missing_field",
    ["ProductArn", "GeneratorId", "Compliance", "RecordState", "Resources", "Id", "Region"],
)
def test_missing_required_field_raises(raw_finding: dict[str, Any], missing_field: str) -> None:
    del raw_finding[missing_field]

    with pytest.raises(FindingParseError):
        parse_finding(raw_finding)


def test_empty_resources_raises(raw_finding: dict[str, Any]) -> None:
    raw_finding["Resources"] = []

    with pytest.raises(FindingParseError):
        parse_finding(raw_finding)
