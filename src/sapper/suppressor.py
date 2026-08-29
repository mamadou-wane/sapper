"""The lock is a chain of generations (PLAN.md §4, amended 2026-08-28).

Mutual exclusion is a create-only write on one key. Generation 0 is the key
P1.5 banked; reclaiming an incident is a create-only write of the next
generation, so contenders race on one key and exactly one wins. The listing
is the compare, the write is the swap, and a stale compare fails the swap.

Once a claim expires, proposal state decides: an expired, applied, or absent
proposal permits the next generation; an open one suppresses. Expiry is
evaluated by reading the object, never by S3 lifecycle.
"""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from sapper.gates import Drop, DropReason
from sapper.proposal import (
    TIMESTAMP_FORMAT,
    applied_key,
    normalize_resource_arn,
    proposal_expires_at_of,
    proposal_key_of,
    require_utc,
)

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

GENERATION_DIGITS = 6
MAX_GENERATION = 10**GENERATION_DIGITS - 1
HTTP_PRECONDITION_FAILED = 412
HTTP_CONFLICT = 409
CONFLICT_RETRIES = 1  # §4: retry once, then drop


def incident_digest(normalized_resource_arn: str, action: str) -> str:
    return hashlib.sha256(f"{normalized_resource_arn}|{action}".encode()).hexdigest()


def lock_prefix(digest: str) -> str:
    return f"locks/{digest}"


def lock_key(digest: str, generation: int) -> str:
    # Generation 0 is the bare key P1.5 banked. "." sorts before "/", so it
    # lists first, and the fixed width keeps decimal order equal to byte order.
    # The width cannot widen in place, so the chain fails closed at the cap.
    if generation == 0:
        return f"{lock_prefix(digest)}.lock"
    if not 0 < generation <= MAX_GENERATION:
        raise ValueError(
            f"generation {generation} for incident {digest} is outside 1..{MAX_GENERATION}; "
            "failing closed"
        )
    return f"{lock_prefix(digest)}/{generation:0{GENERATION_DIGITS}d}.lock"


def generation_of(key: str, digest: str) -> int:
    suffix = key.removeprefix(lock_prefix(digest))
    if suffix == ".lock":
        return 0
    return int(suffix.removeprefix("/").removesuffix(".lock"))


def claim_incident(
    s3_client: "S3Client",
    bucket: str,
    record: dict[str, Any],
    claim_ttl: timedelta,
    now: datetime,
) -> Drop | None:
    """Returns None when this invocation owns the incident and may write the
    proposal; a Drop when it must not. `now` is the claim's own
    creation time, read immediately before the call, and becomes the lock
    body's created_at (D2): it is neither the record's created_at nor the
    handler's entry time."""
    now = require_utc(now, "now")
    digest = incident_digest(
        normalize_resource_arn(record["resource_arn"]), record["remediation_action"]
    )

    keys = _list_chain(s3_client, bucket, digest)
    if not keys:
        return _write_claim(s3_client, bucket, lock_key(digest, 0), record, now)

    current = keys[-1]
    suppression = _evaluate_claim(s3_client, bucket, current, claim_ttl, now)
    if suppression is not None:
        return suppression
    next_generation = generation_of(current, digest) + 1
    return _write_claim(s3_client, bucket, lock_key(digest, next_generation), record, now)


def _list_chain(s3_client: "S3Client", bucket: str, digest: str) -> list[str]:
    # The current generation is the last key of the last page, so every page
    # is read. An empty page carries no Contents key at all.
    page = s3_client.list_objects_v2(Bucket=bucket, Prefix=lock_prefix(digest))
    keys = [entry["Key"] for entry in page.get("Contents", [])]
    while page.get("IsTruncated"):
        page = s3_client.list_objects_v2(
            Bucket=bucket,
            Prefix=lock_prefix(digest),
            ContinuationToken=page["NextContinuationToken"],
        )
        keys.extend(entry["Key"] for entry in page.get("Contents", []))
    return keys


def _evaluate_claim(
    s3_client: "S3Client", bucket: str, key: str, claim_ttl: timedelta, now: datetime
) -> Drop | None:
    claim: dict[str, Any] = json.loads(s3_client.get_object(Bucket=bucket, Key=key)["Body"].read())
    # The stored suffix is always "Z" (TIMESTAMP_FORMAT): parse it as UTC outright.
    created_at = datetime.strptime(claim["created_at"], TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    claim_expires_at = created_at + claim_ttl
    if claim_expires_at > now:
        return Drop(
            DropReason.SUPPRESSED_DUPLICATE,
            f"claim {key!r} live until {claim_expires_at.strftime(TIMESTAMP_FORMAT)}",
        )

    # The claim has expired, so proposal state decides (§4, step 4). The orphan
    # test comes before the applied/ one so the crash repair path needs no more
    # than the proposals/* list grant.
    pid = claim["proposal_id"]
    if proposal_expires_at_of(pid) <= now:
        return None
    if not _exists(s3_client, bucket, proposal_key_of(pid)):
        return None  # orphaned claim: the owner died before writing its proposal
    if _exists(s3_client, bucket, applied_key(pid)):
        return None
    return Drop(DropReason.SUPPRESSED_DUPLICATE, f"open proposal {pid!r} holds {key!r}")


def _exists(s3_client: "S3Client", bucket: str, key: str) -> bool:
    # The proposer holds no GetObject on proposals/* or applied/*, so existence
    # is a one-key prefix-scoped list (§4). KeyCount is present when Contents
    # is not.
    return s3_client.list_objects_v2(Bucket=bucket, Prefix=key, MaxKeys=1)["KeyCount"] > 0


def _write_claim(
    s3_client: "S3Client", bucket: str, key: str, record: dict[str, Any], now: datetime
) -> Drop | None:
    body = json.dumps(
        {
            "proposal_id": record["proposal_id"],
            "provenance": record["provenance"],
            "created_at": now.strftime(TIMESTAMP_FORMAT),
        }
    ).encode("utf-8")

    for attempt in range(CONFLICT_RETRIES + 1):
        try:
            s3_client.put_object(Bucket=bucket, Key=key, Body=body, IfNoneMatch="*")
            return None
        except ClientError as exc:
            status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
            if status == HTTP_PRECONDITION_FAILED:
                # A contender wrote this generation after our listing: the stale
                # compare failed the swap. Whatever its state, the next delivery
                # re-evaluates it; this invocation must not write a second
                # proposal.
                return Drop(
                    DropReason.SUPPRESSED_DUPLICATE, f"lost the create-only race for {key!r}"
                )
            if status == HTTP_CONFLICT and attempt < CONFLICT_RETRIES:
                continue
            if status == HTTP_CONFLICT:
                return Drop(
                    DropReason.CLAIM_CONTENTION, f"409 conflict twice while writing {key!r}"
                )
            raise
    raise AssertionError("unreachable: the loop returns or raises")
