"""The proposer Lambda entrypoint (PLAN.md §3, §4, §6b). Orchestration only:
per finding in detail.findings[], parse, gate, read live state, build the plan
and the record, claim the incident, write PENDING, stop. Dropping is normal and
logs a reason; a genuine error raises, so the on-failure destination (§9) has
something to catch.
"""

import json
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache
from typing import TYPE_CHECKING, Any, Protocol

import boto3

from sapper.config import ALLOWED_CONTROLS, Settings, load_settings
from sapper.findings import FindingParseError, parse_finding
from sapper.gates import Drop, DropReason, evaluate_field_gates, evaluate_freshness_gate
from sapper.metrics import with_provenance_metric
from sapper.plan import PlanUnrenderable, build_plan
from sapper.proposal import build_proposal, write_proposal
from sapper.suppressor import claim_incident

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

# Provenance derives from the event source, never from the record (§16). The
# rule delivers one source; the demo twin's DEMO mapping lands with its rule.
PROVENANCE_BY_SOURCE = {"aws.securityhub": "REAL"}


class LambdaContext(Protocol):
    aws_request_id: str

    def get_remaining_time_in_millis(self) -> int: ...


@dataclass(frozen=True)
class Outcome:
    finding_id: str | None
    drop: Drop | None
    proposal_id: str | None


def handle(event: dict[str, Any], context: LambdaContext) -> list[dict[str, Any]]:
    # Printed as each finding finishes, so a later finding that raises (§9)
    # cannot lose the lines, and the metric datapoints, of the ones before it.
    lines = []
    for line in process_event(event, context, load_lambda_settings(), lambda_s3_client(), utc_now):
        print(json.dumps(line))
        lines.append(line)
    return lines


@cache
def load_lambda_settings() -> Settings:
    return load_settings(os.environ)


@cache
def lambda_s3_client() -> "S3Client":
    return boto3.client("s3")


def utc_now() -> datetime:
    return datetime.now(UTC)


def process_event(
    event: dict[str, Any],
    context: LambdaContext,
    settings: Settings,
    s3_client: "S3Client",
    clock: Callable[[], datetime],
) -> Iterator[dict[str, Any]]:
    """One structured line per finding: the log and the PROVENANCE metric at once."""
    provenance = provenance_of(event["source"])
    for raw in event["detail"]["findings"]:
        outcome = process_finding(raw, provenance, event["id"], context, settings, s3_client, clock)
        yield with_provenance_metric(
            {
                "request_id": context.aws_request_id,
                "finding_id": outcome.finding_id,
                "outcome": "PROPOSED" if outcome.drop is None else outcome.drop.reason.value,
                "detail": None if outcome.drop is None else outcome.drop.detail,
                "proposal_id": outcome.proposal_id,
            },
            dropped=outcome.drop is not None and outcome.drop.reason is DropReason.PROVENANCE,
            now=clock(),
        )


def provenance_of(source: str) -> str:
    if source not in PROVENANCE_BY_SOURCE:
        raise ValueError(f"event source {source!r} has no provenance mapping")
    return PROVENANCE_BY_SOURCE[source]


def process_finding(
    raw: dict[str, Any],
    provenance: str,
    event_id: str,
    context: LambdaContext,
    settings: Settings,
    s3_client: "S3Client",
    clock: Callable[[], datetime],
) -> Outcome:
    try:
        finding = parse_finding(raw)
    except FindingParseError as exc:
        return Outcome(raw.get("Id"), Drop(DropReason.UNPARSEABLE, str(exc)), None)

    drop = evaluate_field_gates(finding, ALLOWED_CONTROLS, settings.scope_arns)
    if drop is not None:
        return Outcome(finding.finding_id, drop, None)
    freshness = evaluate_freshness_gate(finding, s3_client)
    if freshness.before_state is None:
        return Outcome(finding.finding_id, freshness.drop, None)

    try:
        record = build_proposal(
            finding,
            freshness.before_state,
            build_plan(finding.resource_arn),
            provenance,
            event_id,
            clock(),
        )
    except PlanUnrenderable as exc:
        return Outcome(finding.finding_id, Drop(DropReason.PLAN_UNRENDERABLE, str(exc)), None)

    # The record exists before the claim so the lock body can name it; the
    # claim time is read here, not at entry (§4, D2).
    claim_drop = claim_incident(
        s3_client, settings.evidence_bucket, record, settings.claim_ttl, clock()
    )
    if claim_drop is not None:
        return Outcome(finding.finding_id, claim_drop, None)

    require_time_for_the_write(context, settings)
    write_proposal(s3_client, settings.evidence_bucket, record)
    return Outcome(finding.finding_id, None, record["proposal_id"])


def require_time_for_the_write(context: LambdaContext, settings: Settings) -> None:
    # Defense in depth (§4): the serialization argument rests on the margin in
    # CLAIM_TTL, not on this guard. Raising here leaves an orphaned claim that
    # Lambda's retry repairs after CLAIM_TTL, instead of a proposal write that
    # S3 may complete after the kill.
    remaining = timedelta(milliseconds=context.get_remaining_time_in_millis())
    if remaining < settings.claim_margin:
        raise RuntimeError(
            f"{remaining.total_seconds()} s left, under the "
            f"{settings.claim_margin.total_seconds()} s claim margin; "
            "not starting the proposal write"
        )


if "AWS_LAMBDA_FUNCTION_NAME" in os.environ:
    # A bad configuration fails at init (§4), while the module still imports
    # under test with no environment.
    load_lambda_settings()
