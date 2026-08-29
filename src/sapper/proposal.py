"""The §6b record contract: key templates, derivable ids, and the immutable
PENDING proposal record.

Every key below is derivable from the proposal id and nothing else, which is
what lets status be computed by HEADs instead of listing (§4). The record is
written once, create-only, and never updated.
"""

import base64
import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sapper.findings import Finding
from sapper.plan import REMEDIATION_ACTION, plan_sha256

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

SCHEMA_VERSION = 1
PROPOSAL_TTL = timedelta(hours=72)  # §6b: long enough to survive a weekend
RESOURCE_KEY_HEX_CHARS = 32
ULID_EPOCH_MS_DIGITS = 13  # every real value until 2286; the pad only pins fixtures
S3_BUCKET_ARN_PREFIX = "arn:aws:s3:::"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def require_utc(moment: datetime, field: str) -> datetime:
    """Fail fast on a naive datetime instead of guessing its zone; an aware one
    converts to UTC so every derived timestamp is unambiguous regardless of the
    caller's own zone (F1)."""
    if moment.tzinfo is None:
        raise ValueError(f"{field} must be a timezone-aware datetime")
    return moment.astimezone(UTC)


def normalize_resource_arn(resource_arn: str) -> str:
    """The one normalizer (§3, §6b; R-D ruled 2026-08-28). Its output feeds both
    resource_key and the lock digest, so a future normalizer cannot land on one
    path only. R1's S3 bucket ARN has a single canonical form with nothing to
    fold, so this validates the form and returns it unchanged, which keeps the
    banked generation 0 key."""
    bucket_name = resource_arn.removeprefix(S3_BUCKET_ARN_PREFIX)
    if bucket_name == resource_arn or not bucket_name or "/" in bucket_name:
        raise ValueError(f"not a canonical S3 bucket ARN: {resource_arn!r}")
    return resource_arn


def resource_key(normalized_resource_arn: str) -> str:
    digest = hashlib.sha256(normalized_resource_arn.encode("utf-8")).hexdigest()
    return digest[:RESOURCE_KEY_HEX_CHARS]


def new_ulid(now: datetime) -> str:
    # Python 3.12 has no stdlib ULID; <epoch_ms>-<uuid4hex> sorts
    # lexicographically by time and adds no dependency (§6b).
    now = require_utc(now, "now")
    return f"{int(now.timestamp() * 1000):0{ULID_EPOCH_MS_DIGITS}d}-{uuid.uuid4().hex}"


def proposal_key(resource_key_segment: str, action: str, ulid: str) -> str:
    return f"proposals/{resource_key_segment}/{action}/{ulid}/proposal.json"


def proposal_id(resource_key_segment: str, action: str, ulid: str) -> str:
    path = f"{resource_key_segment}/{action}/{ulid}"
    return base64.urlsafe_b64encode(path.encode("utf-8")).decode("ascii").rstrip("=")


def _decode_proposal_id(pid: str) -> tuple[str, str, str]:
    padded = pid + "=" * (-len(pid) % 4)
    segment, action, ulid = base64.urlsafe_b64decode(padded).decode("utf-8").split("/")
    return segment, action, ulid


def proposal_key_of(record_or_id: dict[str, Any] | str) -> str:
    """Derives the S3 key from the record's own proposal_id rather than a
    caller-supplied key, so key and record identity can never disagree (F4)."""
    pid = record_or_id["proposal_id"] if isinstance(record_or_id, dict) else record_or_id
    return proposal_key(*_decode_proposal_id(pid))


def applied_key(pid: str) -> str:
    return f"applied/{pid}.json"


def proposal_expires_at_of(pid: str) -> datetime:
    """The suppressor reads no proposal record (no GetObject on proposals/*), so
    expiry derives from the ULID's epoch milliseconds. Whole seconds, because
    the record's field carries whole seconds and build_proposal mints both from
    one now."""
    _, _, ulid = _decode_proposal_id(pid)
    epoch_ms = int(ulid.split("-")[0])
    return datetime.fromtimestamp(epoch_ms // 1000, tz=UTC) + PROPOSAL_TTL


def build_proposal(
    finding: Finding,
    before_state: dict[str, bool],
    plan: dict[str, Any],
    provenance: str,
    event_id: str,
    now: datetime,
) -> dict[str, Any]:
    # The plan is the hashed, operator-approved target (§5); resource_arn sits
    # outside that hash, so a mismatch would sign approval for the wrong bucket.
    if plan["target_arn"] != finding.resource_arn:
        raise ValueError(
            f"plan target_arn {plan['target_arn']!r} does not match finding "
            f"resource_arn {finding.resource_arn!r}"
        )
    now = require_utc(now, "now")
    key_segment = resource_key(normalize_resource_arn(finding.resource_arn))
    ulid = new_ulid(now)
    return {
        "schema_version": SCHEMA_VERSION,
        "proposal_id": proposal_id(key_segment, REMEDIATION_ACTION, ulid),
        "provenance": provenance,
        "finding_id": finding.finding_id,
        "control_id": finding.security_control_id,
        "resource_arn": finding.resource_arn,
        "remediation_action": REMEDIATION_ACTION,
        "before_state": before_state,
        "plan": plan,
        "plan_sha256": plan_sha256(plan),
        "proposal_expires_at": (now + PROPOSAL_TTL).strftime(TIMESTAMP_FORMAT),
        "finding_updated_at": finding.updated_at,
        "workflow_status": finding.workflow_status,
        "event_id": event_id,
        "created_at": now.strftime(TIMESTAMP_FORMAT),
    }


def write_proposal(s3_client: "S3Client", bucket: str, record: dict[str, Any]) -> None:
    """Create-only write, keyed by the record's own identity (F4). A failure
    here is a broken claim invariant, so it raises to the caller rather than
    dropping (F6)."""
    s3_client.put_object(
        Bucket=bucket,
        Key=proposal_key_of(record),
        Body=json.dumps(record).encode("utf-8"),
        IfNoneMatch="*",
    )
