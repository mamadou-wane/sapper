"""The lock is a chain of generations (PLAN.md §4, amended 2026-08-28).

moto produces the real 412 and the real listing order. The two stale-listing
races and the 409 concurrent-write conflict cannot be provoked in moto and use
thin wrappers around the real client, the one place a mock is unavoidable.
"""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from sapper.findings import parse_finding
from sapper.gates import DropReason
from sapper.plan import build_plan
from sapper.proposal import (
    PROPOSAL_TTL,
    TIMESTAMP_FORMAT,
    applied_key,
    build_proposal,
    proposal_key_of,
    write_proposal,
)
from sapper.suppressor import (
    MAX_GENERATION,
    claim_incident,
    incident_digest,
    lock_key,
    lock_prefix,
)

LAB_ARN = "arn:aws:s3:::sapper-lab-public-116137268889"
ACTION = "s3-block-public-access"
BUCKET = "evidence"
NOW = datetime(2026, 8, 26, 18, 0, 0, tzinfo=UTC)
CLAIM_TTL = timedelta(seconds=30)
AFTER_CLAIM_EXPIRY = NOW + CLAIM_TTL + timedelta(seconds=1)
DIGEST = incident_digest(LAB_ARN, ACTION)

# What P1.5 banked for this incident: the key (evidence/p15/10-proposer-lock.json)
# and the body the probe wrote at it, which is the runtime contract.
BANKED_LOCK_KEY = "locks/7bdce82ea637f56de6bcc1c25c72c19a5261c2d60577718adff4adabd90257b2.lock"
BANKED_LOCK_BODY = (
    Path(__file__).parent.parent
    / "evidence/p15/record-contract"
    / "locks_7bdce82ea637f56de6bcc1c25c72c19a5261c2d60577718adff4adabd90257b2.lock"
)
# The banked proposal id's ULID starts 2026-08-25T21:15:40Z, so its proposal
# expires 2026-08-28T21:15:40Z; this instant is before that and long after the
# probe's claim.
WINDOW_B = datetime(2026, 8, 28, 20, 0, 0, tzinfo=UTC)

BEFORE_STATE = {
    "configuration_present": False,
    "BlockPublicAcls": False,
    "IgnorePublicAcls": False,
    "BlockPublicPolicy": False,
    "RestrictPublicBuckets": False,
}


@pytest.fixture()
def s3_client() -> Any:
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET)
        yield client


def build_record(raw_finding: dict[str, Any], now: datetime) -> dict[str, Any]:
    return build_proposal(
        finding=parse_finding(raw_finding),
        before_state=BEFORE_STATE,
        plan=build_plan(LAB_ARN),
        provenance="REAL",
        event_id="ce8b0cc1-3a14-26be-d4d9-3b7ab91427b8",
        now=now,
    )


@pytest.fixture()
def record(raw_finding: dict[str, Any]) -> dict[str, Any]:
    return build_record(raw_finding, NOW)


def claim(client: Any, record: dict[str, Any], now: datetime = NOW) -> Any:
    return claim_incident(client, BUCKET, record, claim_ttl=CLAIM_TTL, now=now)


def chain(client: Any) -> list[str]:
    listing = client.list_objects_v2(Bucket=BUCKET, Prefix=lock_prefix(DIGEST))
    return [entry["Key"] for entry in listing.get("Contents", [])]


def read_lock(client: Any, key: str) -> dict[str, Any]:
    body: dict[str, Any] = json.loads(client.get_object(Bucket=BUCKET, Key=key)["Body"].read())
    return body


def put_orphaned_claim(client: Any, record: dict[str, Any], generation: int) -> None:
    body = {
        "proposal_id": record["proposal_id"],
        "provenance": "REAL",
        "created_at": NOW.strftime(TIMESTAMP_FORMAT),
    }
    client.put_object(Bucket=BUCKET, Key=lock_key(DIGEST, generation), Body=json.dumps(body))


# --- key template and listing order --------------------------------------------


def test_generation_zero_key_is_the_banked_p15_key() -> None:
    assert lock_key(DIGEST, 0) == BANKED_LOCK_KEY


def test_later_generations_sit_under_the_digest_zero_padded_to_six_digits() -> None:
    assert lock_key(DIGEST, 1) == f"locks/{DIGEST}/000001.lock"
    assert lock_key(DIGEST, MAX_GENERATION) == f"locks/{DIGEST}/999999.lock"


def test_lock_key_refuses_a_generation_past_the_cap() -> None:
    with pytest.raises(ValueError):
        lock_key(DIGEST, MAX_GENERATION + 1)


def test_generation_zero_lists_before_generation_one(s3_client: Any) -> None:
    # "." (0x2E) sorts before "/" (0x2F): the only place the two key shapes meet.
    s3_client.put_object(Bucket=BUCKET, Key=lock_key(DIGEST, 1), Body=b"{}")
    s3_client.put_object(Bucket=BUCKET, Key=lock_key(DIGEST, 0), Body=b"{}")

    assert chain(s3_client) == [lock_key(DIGEST, 0), lock_key(DIGEST, 1)]


def test_listing_order_holds_across_a_digit_width_boundary(s3_client: Any) -> None:
    for generation in (100000, 99999, 10, 9):
        s3_client.put_object(Bucket=BUCKET, Key=lock_key(DIGEST, generation), Body=b"{}")

    assert chain(s3_client) == [lock_key(DIGEST, g) for g in (9, 10, 99999, 100000)]


# --- the five steps ------------------------------------------------------------


def test_empty_chain_takes_generation_zero_with_the_claim_time_as_created_at(
    s3_client: Any, record: dict[str, Any]
) -> None:
    # D2: created_at is the claim's own creation time, later than the record's.
    claim_time = NOW + timedelta(seconds=2)

    assert claim(s3_client, record, now=claim_time) is None

    assert read_lock(s3_client, lock_key(DIGEST, 0)) == {
        "proposal_id": record["proposal_id"],
        "provenance": "REAL",
        "created_at": "2026-08-26T18:00:02Z",
    }


def test_live_claim_suppresses_before_its_proposal_exists(
    s3_client: Any, record: dict[str, Any], raw_finding: dict[str, Any]
) -> None:
    claim(s3_client, record)
    inside_window = NOW + timedelta(seconds=5)

    drop = claim(s3_client, build_record(raw_finding, inside_window), now=inside_window)

    assert drop is not None and drop.reason is DropReason.SUPPRESSED_DUPLICATE
    assert chain(s3_client) == [lock_key(DIGEST, 0)]


def test_expired_claim_with_an_open_proposal_suppresses(
    s3_client: Any, record: dict[str, Any], raw_finding: dict[str, Any]
) -> None:
    claim(s3_client, record)
    write_proposal(s3_client, BUCKET, record)

    drop = claim(s3_client, build_record(raw_finding, AFTER_CLAIM_EXPIRY), now=AFTER_CLAIM_EXPIRY)

    assert drop is not None and drop.reason is DropReason.SUPPRESSED_DUPLICATE
    assert chain(s3_client) == [lock_key(DIGEST, 0)]


def test_orphaned_claim_permits_the_next_generation(
    s3_client: Any, record: dict[str, Any], raw_finding: dict[str, Any]
) -> None:
    claim(s3_client, record)  # the owner died before write_proposal
    contender = build_record(raw_finding, AFTER_CLAIM_EXPIRY)
    claim_time = AFTER_CLAIM_EXPIRY + timedelta(seconds=2)

    assert claim(s3_client, contender, now=claim_time) is None

    assert chain(s3_client) == [lock_key(DIGEST, 0), lock_key(DIGEST, 1)]
    assert read_lock(s3_client, lock_key(DIGEST, 1)) == {
        "proposal_id": contender["proposal_id"],
        "provenance": "REAL",
        "created_at": claim_time.strftime(TIMESTAMP_FORMAT),
    }


def test_a_claim_expires_at_exactly_created_at_plus_ttl(
    s3_client: Any, record: dict[str, Any], raw_finding: dict[str, Any]
) -> None:
    claim(s3_client, record)  # orphaned
    at_expiry = NOW + CLAIM_TTL

    assert claim(s3_client, build_record(raw_finding, at_expiry), now=at_expiry) is None


def test_a_proposal_expires_at_exactly_its_ulid_plus_the_proposal_ttl(
    s3_client: Any, record: dict[str, Any], raw_finding: dict[str, Any]
) -> None:
    claim(s3_client, record)
    write_proposal(s3_client, BUCKET, record)
    at_expiry = NOW + PROPOSAL_TTL

    assert claim(s3_client, build_record(raw_finding, at_expiry), now=at_expiry) is None


def test_the_lock_digest_goes_through_the_normalizer(record: dict[str, Any]) -> None:
    # D3: the same helper feeds resource_key and the lock digest. A record
    # carrying a non-bucket ARN fails before any S3 call, so no client is needed.
    foreign = {**record, "resource_arn": "arn:aws:ec2:us-east-1:116137268889:security-group/sg-1"}

    no_client: Any = None
    with pytest.raises(ValueError):
        claim_incident(no_client, BUCKET, foreign, claim_ttl=CLAIM_TTL, now=NOW)


def test_expired_proposal_permits_the_next_generation(
    s3_client: Any, record: dict[str, Any], raw_finding: dict[str, Any]
) -> None:
    claim(s3_client, record)
    write_proposal(s3_client, BUCKET, record)
    after_proposal_expiry = NOW + timedelta(hours=72, seconds=1)

    contender = build_record(raw_finding, after_proposal_expiry)

    assert claim(s3_client, contender, now=after_proposal_expiry) is None
    assert chain(s3_client) == [lock_key(DIGEST, 0), lock_key(DIGEST, 1)]


def test_applied_proposal_permits_the_next_generation(
    s3_client: Any, record: dict[str, Any], raw_finding: dict[str, Any]
) -> None:
    claim(s3_client, record)
    write_proposal(s3_client, BUCKET, record)
    s3_client.put_object(Bucket=BUCKET, Key=applied_key(record["proposal_id"]), Body=b"{}")
    contender = build_record(raw_finding, AFTER_CLAIM_EXPIRY)

    assert claim(s3_client, contender, now=AFTER_CLAIM_EXPIRY) is None
    assert chain(s3_client) == [lock_key(DIGEST, 0), lock_key(DIGEST, 1)]


def test_the_cap_fails_closed(
    s3_client: Any, record: dict[str, Any], raw_finding: dict[str, Any]
) -> None:
    put_orphaned_claim(s3_client, record, MAX_GENERATION)

    with pytest.raises(ValueError):
        claim(s3_client, build_record(raw_finding, AFTER_CLAIM_EXPIRY), now=AFTER_CLAIM_EXPIRY)

    assert chain(s3_client) == [lock_key(DIGEST, MAX_GENERATION)]


def test_the_current_generation_comes_from_the_last_page(
    s3_client: Any, record: dict[str, Any], raw_finding: dict[str, Any]
) -> None:
    # 1,001 keys force a second page at S3's 1,000-key page size. A reader that
    # stops at page one takes 1,000 as current, writes 1,001, and loses.
    for generation in range(1, 1002):
        put_orphaned_claim(s3_client, record, generation)
    contender = build_record(raw_finding, AFTER_CLAIM_EXPIRY)

    assert claim(s3_client, contender, now=AFTER_CLAIM_EXPIRY) is None

    s3_client.head_object(Bucket=BUCKET, Key=lock_key(DIGEST, 1002))


def test_naive_now_raises(s3_client: Any, record: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        claim(s3_client, record, now=NOW.replace(tzinfo=None))


# --- the banked generation 0 object, as it sits in the live store ----------------


def put_banked_generation_zero(client: Any) -> str:
    body = BANKED_LOCK_BODY.read_bytes()
    client.put_object(Bucket=BUCKET, Key=BANKED_LOCK_KEY, Body=body)
    banked_proposal_id: str = json.loads(body)["proposal_id"]
    client.put_object(Bucket=BUCKET, Key=proposal_key_of(banked_proposal_id), Body=b"{}")
    return banked_proposal_id


def test_banked_generation_zero_lock_permits_through_applied(
    s3_client: Any, raw_finding: dict[str, Any]
) -> None:
    banked_proposal_id = put_banked_generation_zero(s3_client)
    s3_client.put_object(Bucket=BUCKET, Key=applied_key(banked_proposal_id), Body=b"{}")

    assert claim(s3_client, build_record(raw_finding, WINDOW_B), now=WINDOW_B) is None

    assert chain(s3_client) == [BANKED_LOCK_KEY, lock_key(DIGEST, 1)]


def test_banked_generation_zero_lock_suppresses_while_its_proposal_is_open(
    s3_client: Any, raw_finding: dict[str, Any]
) -> None:
    put_banked_generation_zero(s3_client)

    drop = claim(s3_client, build_record(raw_finding, WINDOW_B), now=WINDOW_B)

    assert drop is not None and drop.reason is DropReason.SUPPRESSED_DUPLICATE
    assert chain(s3_client) == [BANKED_LOCK_KEY]


# --- races: a stale listing loses the create-only swap ----------------------------


class FrozenListing:
    """Wraps the moto client; the chain listing is frozen at construction, so a
    later contender reads a listing that predates another contender's write.
    Every other call, including the existence lists, delegates live."""

    def __init__(self, real: Any) -> None:
        self.real = real
        self.snapshot = real.list_objects_v2(Bucket=BUCKET, Prefix=lock_prefix(DIGEST))

    def list_objects_v2(self, **kwargs: Any) -> Any:
        if kwargs.get("Prefix") == lock_prefix(DIGEST):
            return self.snapshot
        return self.real.list_objects_v2(**kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.real, name)


def test_a_stale_listing_loses_generation_zero_to_the_contender_that_wrote_it(
    s3_client: Any, record: dict[str, Any], raw_finding: dict[str, Any]
) -> None:
    stale = FrozenListing(s3_client)  # sees an empty chain
    claim(s3_client, record)  # the other contender writes generation 0 first
    a_moment_later = NOW + timedelta(seconds=1)

    drop = claim(stale, build_record(raw_finding, a_moment_later), now=a_moment_later)

    assert drop is not None and drop.reason is DropReason.SUPPRESSED_DUPLICATE
    assert chain(s3_client) == [lock_key(DIGEST, 0)]


def test_a_stale_listing_loses_generation_n_plus_one_to_the_contender_that_reclaimed_first(
    s3_client: Any, record: dict[str, Any], raw_finding: dict[str, Any]
) -> None:
    claim(s3_client, record)  # generation 0, orphaned
    stale = FrozenListing(s3_client)  # sees generation 0 as current
    winner = build_record(raw_finding, AFTER_CLAIM_EXPIRY)
    assert claim(s3_client, winner, now=AFTER_CLAIM_EXPIRY) is None

    drop = claim(stale, build_record(raw_finding, AFTER_CLAIM_EXPIRY), now=AFTER_CLAIM_EXPIRY)

    assert drop is not None and drop.reason is DropReason.SUPPRESSED_DUPLICATE
    assert chain(s3_client) == [lock_key(DIGEST, 0), lock_key(DIGEST, 1)]


# --- 409, the concurrent-write conflict --------------------------------------------


class ConflictOnce:
    """Wraps the moto client; the first `failures` put_object calls raise 409,
    the rest delegate."""

    def __init__(self, real: Any, failures: int) -> None:
        self.real = real
        self.failures_left = failures

    def put_object(self, **kwargs: Any) -> Any:
        if self.failures_left > 0:
            self.failures_left -= 1
            raise ClientError(
                {
                    "Error": {"Code": "ConditionalRequestConflict", "Message": "conflict"},
                    "ResponseMetadata": {"HTTPStatusCode": 409},
                },
                "PutObject",
            )
        return self.real.put_object(**kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.real, name)


def test_409_once_retries_and_owns_the_incident(s3_client: Any, record: dict[str, Any]) -> None:
    assert claim(ConflictOnce(s3_client, failures=1), record) is None

    assert chain(s3_client) == [lock_key(DIGEST, 0)]


def test_409_twice_drops_claim_contention(s3_client: Any, record: dict[str, Any]) -> None:
    drop = claim(ConflictOnce(s3_client, failures=2), record)

    # Two 409s prove a concurrent write race, never that another proposal holds
    # the incident, so this is not SUPPRESSED_DUPLICATE.
    assert drop is not None and drop.reason is DropReason.CLAIM_CONTENTION
    assert chain(s3_client) == []
