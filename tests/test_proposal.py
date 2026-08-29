"""The §6b record contract: key templates, derivable ids, and the immutable
PENDING record. moto proves the write path and the client's 412 handling; it
proves nothing about bucket-policy enforcement (see test_gates_live docstring)."""

import base64
import json
import re
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from sapper.findings import parse_finding
from sapper.plan import build_plan, plan_sha256
from sapper.proposal import (
    TIMESTAMP_FORMAT,
    applied_key,
    build_proposal,
    new_ulid,
    normalize_resource_arn,
    proposal_expires_at_of,
    proposal_id,
    proposal_key,
    proposal_key_of,
    resource_key,
    write_proposal,
)

LAB_ARN = "arn:aws:s3:::sapper-lab-public-116137268889"
ACTION = "s3-block-public-access"
NOW = datetime(2026, 8, 26, 18, 0, 0, tzinfo=UTC)
BEFORE_STATE = {
    "configuration_present": False,
    "BlockPublicAcls": False,
    "IgnorePublicAcls": False,
    "BlockPublicPolicy": False,
    "RestrictPublicBuckets": False,
}


def test_resource_key_is_truncated_sha256() -> None:
    key = resource_key(LAB_ARN)

    assert re.fullmatch(r"[0-9a-f]{32}", key)
    assert key == resource_key(LAB_ARN)


def test_ulid_sorts_lexicographically_by_time() -> None:
    earlier = new_ulid(NOW)
    later = new_ulid(datetime(2026, 8, 26, 18, 0, 1, tzinfo=UTC))

    assert re.fullmatch(r"\d{13}-[0-9a-f]{32}", earlier)
    assert earlier < later


def test_proposal_key_matches_the_template() -> None:
    key = proposal_key(resource_key(LAB_ARN), ACTION, "1753048000000-abcd")

    assert key == (
        f"proposals/{resource_key(LAB_ARN)}/{ACTION}/1753048000000-abcd/proposal.json"
    )


def test_proposal_id_is_unpadded_urlsafe_base64_of_the_key_path() -> None:
    ulid = "1753048000000-abcd"
    pid = proposal_id(resource_key(LAB_ARN), ACTION, ulid)

    assert "=" not in pid
    padded = pid + "=" * (-len(pid) % 4)
    decoded = base64.urlsafe_b64decode(padded).decode()
    assert decoded == f"{resource_key(LAB_ARN)}/{ACTION}/{ulid}"


def build(raw_finding: dict[str, Any], plan: dict[str, Any], now: datetime = NOW) -> Any:
    return build_proposal(
        finding=parse_finding(raw_finding),
        before_state=BEFORE_STATE,
        plan=plan,
        provenance="REAL",
        event_id="ce8b0cc1-3a14-26be-d4d9-3b7ab91427b8",
        now=now,
    )


def decode_proposal_id(pid: str) -> list[str]:
    padded = pid + "=" * (-len(pid) % 4)
    return base64.urlsafe_b64decode(padded).decode().split("/")


def test_build_proposal_matches_the_6b_schema(raw_finding: dict[str, Any]) -> None:
    finding = parse_finding(raw_finding)
    plan = build_plan(LAB_ARN)

    record = build(raw_finding, plan)

    segment, action, ulid = decode_proposal_id(record["proposal_id"])
    assert segment == resource_key(LAB_ARN)
    assert action == ACTION
    assert re.fullmatch(r"\d{13}-[0-9a-f]{32}", ulid)
    assert ulid.startswith(str(int(NOW.timestamp() * 1000)))

    assert record == {
        "schema_version": 1,
        "proposal_id": record["proposal_id"],
        "provenance": "REAL",
        "finding_id": finding.finding_id,
        "control_id": "S3.8",
        "resource_arn": LAB_ARN,
        "remediation_action": ACTION,
        "before_state": BEFORE_STATE,
        "plan": plan,
        "plan_sha256": plan_sha256(plan),
        "proposal_expires_at": "2026-08-29T18:00:00Z",
        "finding_updated_at": "2026-06-26T01:22:15.937Z",
        "workflow_status": "NEW",
        "event_id": "ce8b0cc1-3a14-26be-d4d9-3b7ab91427b8",
        "created_at": "2026-08-26T18:00:00Z",
    }


def test_build_proposal_rejects_target_arn_mismatch(raw_finding: dict[str, Any]) -> None:
    # The plan is the hashed, operator-approved target (§5); a resource_arn that
    # disagrees with it is a wrong-bucket remediation waiting to be signed (F4).
    plan = build_plan("arn:aws:s3:::some-other-bucket")

    with pytest.raises(ValueError):
        build(raw_finding, plan)


def test_build_proposal_rejects_naive_now(raw_finding: dict[str, Any]) -> None:
    plan = build_plan(LAB_ARN)

    with pytest.raises(ValueError):
        build(raw_finding, plan, now=NOW.replace(tzinfo=None))


def test_new_ulid_rejects_naive_now() -> None:
    with pytest.raises(ValueError):
        new_ulid(NOW.replace(tzinfo=None))


def test_non_utc_aware_now_matches_its_utc_equivalent_instant(
    raw_finding: dict[str, Any],
) -> None:
    plan = build_plan(LAB_ARN)
    non_utc_now = NOW.astimezone(timezone(timedelta(hours=-4)))

    utc_record = build(raw_finding, plan, now=NOW)
    non_utc_record = build(raw_finding, plan, now=non_utc_now)

    assert utc_record["created_at"] == non_utc_record["created_at"]
    assert utc_record["proposal_expires_at"] == non_utc_record["proposal_expires_at"]

    utc_epoch = decode_proposal_id(utc_record["proposal_id"])[2].split("-")[0]
    non_utc_epoch = decode_proposal_id(non_utc_record["proposal_id"])[2].split("-")[0]
    assert utc_epoch == non_utc_epoch


def test_proposal_key_of_round_trips_a_built_record(raw_finding: dict[str, Any]) -> None:
    plan = build_plan(LAB_ARN)
    record = build(raw_finding, plan)

    segment, action, ulid = decode_proposal_id(record["proposal_id"])

    assert proposal_key_of(record) == f"proposals/{segment}/{action}/{ulid}/proposal.json"
    assert segment == resource_key(LAB_ARN)
    assert action == ACTION


def test_proposal_key_of_accepts_a_bare_id() -> None:
    pid = proposal_id(resource_key(LAB_ARN), ACTION, "1-a")

    assert proposal_key_of(pid) == proposal_key(resource_key(LAB_ARN), ACTION, "1-a")


def test_write_proposal_is_create_only() -> None:
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="evidence")
        pid = proposal_id(resource_key(LAB_ARN), ACTION, "1-a")
        record = {"schema_version": 1, "proposal_id": pid}

        write_proposal(s3, "evidence", record)

        body = json.loads(
            s3.get_object(Bucket="evidence", Key=proposal_key_of(record))["Body"].read()
        )
        assert body == record

        # A second write to the same key is a failure of the claim invariant, not
        # a normal drop: it must raise so the on-failure path catches it.
        with pytest.raises(ClientError):
            write_proposal(s3, "evidence", record)


def test_normalize_resource_arn_returns_the_canonical_bucket_arn_unchanged() -> None:
    # R-D, ruled 2026-08-28: one helper feeds both resource_key and the lock
    # digest. For R1 the S3 bucket ARN has nothing to fold, so the banked
    # generation 0 key must survive it untouched.
    assert normalize_resource_arn(LAB_ARN) == LAB_ARN


@pytest.mark.parametrize(
    "arn",
    [
        "arn:aws:ec2:us-east-1:116137268889:security-group/sg-0123",
        "arn:aws:s3:::",
        "arn:aws:s3:::sapper-lab-public-116137268889/some-object",
        "sapper-lab-public-116137268889",
    ],
)
def test_normalize_resource_arn_rejects_anything_but_a_bucket_arn(arn: str) -> None:
    with pytest.raises(ValueError):
        normalize_resource_arn(arn)


def test_applied_key_matches_the_template() -> None:
    assert applied_key("OGYxLi4u") == "applied/OGYxLi4u.json"


def test_proposal_expires_at_of_equals_the_record_field(raw_finding: dict[str, Any]) -> None:
    # The suppressor derives expiry from the ULID without reading the record
    # (the proposer holds no GetObject on proposals/*), so the two must agree.
    record = build(raw_finding, build_plan(LAB_ARN), now=NOW.replace(microsecond=789_000))

    derived = proposal_expires_at_of(record["proposal_id"])

    assert derived == datetime.strptime(record["proposal_expires_at"], TIMESTAMP_FORMAT).replace(
        tzinfo=UTC
    )


def test_new_ulid_pads_epoch_milliseconds_to_13_digits() -> None:
    # 2001-09-08 has a 12-digit epoch-millisecond value; 13 digits begin
    # 2001-09-09T01:46:40Z.
    twelve_digit_epoch = datetime(2001, 9, 8, tzinfo=UTC)

    ulid = new_ulid(twelve_digit_epoch)

    assert re.fullmatch(r"0\d{12}-[0-9a-f]{32}", ulid)
