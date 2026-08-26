"""The field gates (§3, Gates 0-4 plus the suppressed drop): evaluated in order,
short-circuit on first drop, no AWS call. The live-state gates (5, 5b) are tested
separately with moto."""

from typing import Any

import pytest

from sapper.findings import parse_finding
from sapper.gates import DropReason, evaluate_field_gates

ALLOWED_CONTROLS = frozenset({"S3.8"})
SCOPE_ARNS = frozenset({"arn:aws:s3:::sapper-lab-public-116137268889"})


def evaluate(raw: dict[str, Any]) -> Any:
    return evaluate_field_gates(parse_finding(raw), ALLOWED_CONTROLS, SCOPE_ARNS)


def test_fixture_finding_passes_every_field_gate(raw_finding: dict[str, Any]) -> None:
    assert evaluate(raw_finding) is None


def test_gate0_drops_third_party_product_arn(raw_finding: dict[str, Any]) -> None:
    raw_finding["ProductArn"] = "arn:aws:securityhub:us-east-1::product/prowler/prowler"

    drop = evaluate(raw_finding)

    assert drop is not None and drop.reason is DropReason.PROVENANCE


def test_gate0_drops_wrong_region_product_arn(raw_finding: dict[str, Any]) -> None:
    # The native ARN must match the finding's own region, derived from the finding
    # rather than hardcoded (§3 Gate 0).
    raw_finding["ProductArn"] = "arn:aws:securityhub:us-west-2::product/aws/securityhub"

    drop = evaluate(raw_finding)

    assert drop is not None and drop.reason is DropReason.PROVENANCE


def test_gate0_drops_non_security_control_generator(raw_finding: dict[str, Any]) -> None:
    raw_finding["GeneratorId"] = "aws-foundational-security-best-practices/v/1.0.0/S3.8"

    drop = evaluate(raw_finding)

    assert drop is not None and drop.reason is DropReason.PROVENANCE


def test_gate1_drops_disallowed_control_id(raw_finding: dict[str, Any]) -> None:
    raw_finding["Compliance"]["SecurityControlId"] = "S3.2"

    drop = evaluate(raw_finding)

    assert drop is not None and drop.reason is DropReason.CONTROL_ID


def test_suppressed_workflow_status_drops(raw_finding: dict[str, Any]) -> None:
    raw_finding["Workflow"]["Status"] = "SUPPRESSED"

    drop = evaluate(raw_finding)

    assert drop is not None and drop.reason is DropReason.SUPPRESSED


@pytest.mark.parametrize("status", ["NEW", "NOTIFIED", "RESOLVED"])
def test_non_suppressed_workflow_statuses_pass(raw_finding: dict[str, Any], status: str) -> None:
    # Asymmetric on purpose: SUPPRESSED is a human act worth respecting; the other
    # values are unreliable as positive signals (§3).
    raw_finding["Workflow"]["Status"] = status

    assert evaluate(raw_finding) is None


def test_missing_workflow_block_passes_the_suppressed_gate(raw_finding: dict[str, Any]) -> None:
    del raw_finding["Workflow"]

    assert evaluate(raw_finding) is None


def test_gate2_drops_non_failed_compliance(raw_finding: dict[str, Any]) -> None:
    raw_finding["Compliance"]["Status"] = "PASSED"

    drop = evaluate(raw_finding)

    assert drop is not None and drop.reason is DropReason.COMPLIANCE_STATUS


def test_gate3_drops_archived_record(raw_finding: dict[str, Any]) -> None:
    raw_finding["RecordState"] = "ARCHIVED"

    drop = evaluate(raw_finding)

    assert drop is not None and drop.reason is DropReason.RECORD_STATE


def test_gate4_drops_out_of_scope_resource(raw_finding: dict[str, Any]) -> None:
    raw_finding["Resources"][0]["Id"] = "arn:aws:s3:::someone-elses-bucket"

    drop = evaluate(raw_finding)

    assert drop is not None and drop.reason is DropReason.SCOPE


def test_gates_short_circuit_in_order(raw_finding: dict[str, Any]) -> None:
    # Fails provenance AND control ID AND compliance: the drop must name the
    # earliest gate (§3: evaluated in order, short-circuit on first drop).
    raw_finding["ProductArn"] = "arn:aws:securityhub:us-east-1::product/prowler/prowler"
    raw_finding["Compliance"]["SecurityControlId"] = "S3.2"
    raw_finding["Compliance"]["Status"] = "PASSED"

    drop = evaluate(raw_finding)

    assert drop is not None and drop.reason is DropReason.PROVENANCE


def test_drop_carries_detail_for_the_log_line(raw_finding: dict[str, Any]) -> None:
    raw_finding["Compliance"]["SecurityControlId"] = "S3.2"

    drop = evaluate(raw_finding)

    assert drop is not None and "S3.2" in drop.detail
