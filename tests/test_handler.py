"""The proposer handler (PLAN.md §3, §4, §6b): per finding, parse, gate, read
live state, build and claim, write PENDING, stop. Under moto, which proves
parsing, gate order, drop reasons, and the client's 412/409 handling, and
nothing about what the bucket policy enforces (see test_gates_live).

One structured line per finding is the log and the PROVENANCE metric at once:
an embedded-metric-format document (§3) carrying ProvenanceDrop 1 or 0.
"""

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
import pytest
from moto import mock_aws

from sapper.config import Settings
from sapper.gates import DropReason
from sapper.handler import LambdaContext, process_event
from sapper.metrics import METRIC_NAMESPACE, PROVENANCE_DROP_METRIC
from sapper.proposal import proposal_key_of
from sapper.suppressor import incident_digest, lock_key

LAB_ARN = "arn:aws:s3:::sapper-lab-public-116137268889"
LAB_BUCKET = "sapper-lab-public-116137268889"
EVIDENCE_BUCKET = "evidence"
NOW = datetime(2026, 8, 26, 18, 0, 0, tzinfo=UTC)
SETTINGS = Settings(
    evidence_bucket=EVIDENCE_BUCKET,
    scope_arns=frozenset({LAB_ARN}),
    claim_margin=timedelta(seconds=5),
    claim_ttl=timedelta(seconds=15),
)
GENERATION_ZERO = lock_key(incident_digest(LAB_ARN, "s3-block-public-access"), 0)


class StubContext:
    """The two context members the handler reads (vendor doc: python-context)."""

    aws_request_id = "req-1"

    def __init__(self, remaining_ms: int = 9_000) -> None:
        self.remaining_ms = remaining_ms

    def get_remaining_time_in_millis(self) -> int:
        return self.remaining_ms


@pytest.fixture()
def s3_client() -> Any:
    # The lab bucket has no BPA configuration at all: the drifted state Gate 5
    # records as configuration_present false.
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=EVIDENCE_BUCKET)
        client.create_bucket(Bucket=LAB_BUCKET)
        yield client


def run(
    client: Any,
    event: dict[str, Any],
    now: datetime = NOW,
    context: LambdaContext | None = None,
) -> list[dict[str, Any]]:
    return list(
        process_event(event, context or StubContext(), SETTINGS, client, clock=lambda: now)
    )


def evidence_keys(client: Any, prefix: str) -> list[str]:
    listing = client.list_objects_v2(Bucket=EVIDENCE_BUCKET, Prefix=prefix)
    return [entry["Key"] for entry in listing.get("Contents", [])]


def test_fixture_event_writes_one_pending_proposal(
    s3_client: Any, finding_event: dict[str, Any]
) -> None:
    lines = run(s3_client, finding_event)

    assert len(lines) == 1
    line = lines[0]
    assert line["outcome"] == "PROPOSED"
    assert line["finding_id"] == finding_event["detail"]["findings"][0]["Id"]

    record = json.loads(
        s3_client.get_object(Bucket=EVIDENCE_BUCKET, Key=proposal_key_of(line["proposal_id"]))[
            "Body"
        ].read()
    )
    assert record["provenance"] == "REAL"
    assert record["event_id"] == finding_event["id"]
    assert record["before_state"]["configuration_present"] is False
    assert record["created_at"] == "2026-08-26T18:00:00Z"
    assert evidence_keys(s3_client, "locks/") == [GENERATION_ZERO]


def test_each_line_is_an_embedded_metric_document(
    s3_client: Any, finding_event: dict[str, Any]
) -> None:
    line = run(s3_client, finding_event)[0]

    assert line[PROVENANCE_DROP_METRIC] == 0
    assert line["_aws"]["Timestamp"] == int(NOW.timestamp() * 1000)
    assert line["_aws"]["CloudWatchMetrics"] == [
        {
            "Namespace": METRIC_NAMESPACE,
            "Dimensions": [[]],
            "Metrics": [{"Name": PROVENANCE_DROP_METRIC, "Unit": "Count"}],
        }
    ]
    assert line["request_id"] == "req-1"


def test_a_second_delivery_is_suppressed_and_writes_nothing(
    s3_client: Any, finding_event: dict[str, Any]
) -> None:
    run(s3_client, finding_event)

    line = run(s3_client, finding_event, now=NOW + timedelta(seconds=5))[0]

    assert line["outcome"] == DropReason.SUPPRESSED_DUPLICATE.value
    assert line["proposal_id"] is None
    assert len(evidence_keys(s3_client, "proposals/")) == 1
    assert evidence_keys(s3_client, "locks/") == [GENERATION_ZERO]


def test_provenance_drop_emits_the_metric_and_writes_nothing(
    s3_client: Any, finding_event: dict[str, Any]
) -> None:
    finding_event["detail"]["findings"][0]["ProductArn"] = (
        "arn:aws:securityhub:us-east-1::product/prowler/prowler"
    )

    line = run(s3_client, finding_event)[0]

    assert line["outcome"] == DropReason.PROVENANCE.value
    assert line[PROVENANCE_DROP_METRIC] == 1
    assert evidence_keys(s3_client, "") == []


def test_stale_finding_drops_after_the_live_read(
    s3_client: Any, finding_event: dict[str, Any]
) -> None:
    s3_client.put_public_access_block(
        Bucket=LAB_BUCKET,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    line = run(s3_client, finding_event)[0]

    assert line["outcome"] == DropReason.STALE_FINDING.value
    assert evidence_keys(s3_client, "") == []


def test_one_unparseable_finding_does_not_abort_the_batch(
    s3_client: Any, finding_event: dict[str, Any]
) -> None:
    good = finding_event["detail"]["findings"][0]
    finding_event["detail"]["findings"] = [{"Id": "broken", "Resources": []}, good]

    lines = run(s3_client, finding_event)

    assert [line["outcome"] for line in lines] == [
        DropReason.UNPARSEABLE.value,
        "PROPOSED",
    ]
    assert lines[0]["finding_id"] == "broken"
    assert len(evidence_keys(s3_client, "proposals/")) == 1


def test_an_unrenderable_plan_drops_before_the_claim(
    s3_client: Any, finding_event: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    # No S3.8 plan can carry a control character today (bucket names cannot),
    # so the one reachable way to exercise the §6 rejection path is a plan
    # builder that returns one. The rest of the chain runs unmocked.
    import sapper.handler

    def unrenderable_plan(target_arn: str) -> dict[str, Any]:
        return {"action": "s3-block-public-access\x1b[0m", "target_arn": target_arn}

    monkeypatch.setattr(sapper.handler, "build_plan", unrenderable_plan)

    line = run(s3_client, finding_event)[0]

    assert line["outcome"] == DropReason.PLAN_UNRENDERABLE.value
    assert evidence_keys(s3_client, "") == []


def test_unknown_event_source_raises(s3_client: Any, finding_event: dict[str, Any]) -> None:
    # Provenance is derived from the source, never asserted (§16): the only
    # source the rule delivers is aws.securityhub, so anything else is an
    # unrecoverable error for the on-failure destination, not a drop.
    finding_event["source"] = "sapper.demo"

    with pytest.raises(ValueError):
        run(s3_client, finding_event)


def test_too_little_remaining_time_raises_before_the_proposal_write(
    s3_client: Any, finding_event: dict[str, Any]
) -> None:
    # Defense in depth (§4): the claim is written, the proposal is not, and the
    # invocation errors so Lambda's retry repairs the orphan after CLAIM_TTL.
    with pytest.raises(RuntimeError):
        run(s3_client, finding_event, context=StubContext(remaining_ms=4_000))

    assert evidence_keys(s3_client, "locks/") == [GENERATION_ZERO]
    assert evidence_keys(s3_client, "proposals/") == []


@pytest.fixture()
def lambda_environment(monkeypatch: pytest.MonkeyPatch) -> Any:
    import sapper.handler

    monkeypatch.setenv("EVIDENCE_BUCKET", EVIDENCE_BUCKET)
    monkeypatch.setenv("SCOPE_ARNS", f"{LAB_ARN},arn:aws:s3:::no-such-lab-bucket")
    monkeypatch.setenv("PROPOSER_TIMEOUT_SECONDS", "10")
    monkeypatch.setenv("CLAIM_MARGIN_SECONDS", "5")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    sapper.handler.load_lambda_settings.cache_clear()
    sapper.handler.lambda_s3_client.cache_clear()
    yield sapper.handler
    sapper.handler.load_lambda_settings.cache_clear()
    sapper.handler.lambda_s3_client.cache_clear()


def printed_lines(capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()]


def test_handle_wires_settings_and_client_from_the_environment_and_prints_each_line(
    s3_client: Any,
    finding_event: dict[str, Any],
    lambda_environment: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    lines = lambda_environment.handle(finding_event, StubContext())

    assert lines[0]["outcome"] == "PROPOSED"
    assert printed_lines(capsys) == lines
    assert len(evidence_keys(s3_client, "proposals/")) == 1


def test_a_raise_mid_batch_still_prints_the_lines_before_it(
    s3_client: Any,
    finding_event: dict[str, Any],
    lambda_environment: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The second finding names an in-scope bucket that does not exist, so
    # Gate 5's read raises past the handler (§9). The first finding already
    # wrote its proposal; its line, and its metric datapoint, must not be lost.
    good = finding_event["detail"]["findings"][0]
    missing = json.loads(json.dumps(good))
    missing["Resources"][0]["Id"] = "arn:aws:s3:::no-such-lab-bucket"
    finding_event["detail"]["findings"] = [good, missing]

    with pytest.raises(Exception, match="NoSuchBucket"):
        lambda_environment.handle(finding_event, StubContext())

    printed = printed_lines(capsys)
    assert [line["outcome"] for line in printed] == ["PROPOSED"]
    assert len(evidence_keys(s3_client, "proposals/")) == 1
