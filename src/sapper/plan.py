"""The dry-run plan and its canonical hash (PLAN.md §6, ADR-0006).

The canonicalizer is a security control rather than a formatter: the hashed
bytes are the bytes the operator reads at approval time (§5), so any string
that could render differently from how it hashes is rejected. The proposer
drops PLAN_UNRENDERABLE on rejection; the P4 CLI refuses the same plans.
"""

import hashlib
import json
import math
import unicodedata
from typing import Any

REMEDIATION_ACTION = "s3-block-public-access"
CANONICAL_FORM_MAX_BYTES = 8192
PRINTABLE_ASCII_MIN = 0x20
PRINTABLE_ASCII_MAX = 0x7E


class PlanUnrenderable(Exception):
    """A plan whose canonical form could mislead the operator or exceed the cap."""


def build_plan(target_arn: str) -> dict[str, Any]:
    # The shape is the §6b contract verbatim; the "set" keys carry the AWS
    # request casing PutPublicAccessBlock expects.
    return {
        "action": REMEDIATION_ACTION,
        "target_arn": target_arn,
        "set": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    }


def canonical_plan_bytes(plan: dict[str, Any]) -> bytes:
    _reject_unrenderable(plan)
    canonical = json.dumps(
        plan, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
    if len(canonical) > CANONICAL_FORM_MAX_BYTES:
        raise PlanUnrenderable(f"canonical form is {len(canonical)} bytes, cap is 8 KB")
    return canonical


def plan_sha256(plan: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_plan_bytes(plan)).hexdigest()


def _reject_unrenderable(value: Any) -> None:
    # Default-deny: every accepted type is named explicitly, and anything else
    # falls to the else branch rather than passing through unchecked (F3).
    if isinstance(value, str):
        for char in value:
            if unicodedata.category(char) in ("Cc", "Cf") or not (
                PRINTABLE_ASCII_MIN <= ord(char) <= PRINTABLE_ASCII_MAX
            ):
                raise PlanUnrenderable(f"string carries unrenderable codepoint U+{ord(char):04X}")
    elif value is None or isinstance(value, bool | int):
        pass
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise PlanUnrenderable(f"float {value!r} is not finite")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PlanUnrenderable(f"dict key {key!r} is type {type(key).__name__}, not str")
            _reject_unrenderable(key)
            _reject_unrenderable(item)
    elif isinstance(value, list):
        for item in value:
            _reject_unrenderable(item)
    else:
        raise PlanUnrenderable(f"value {value!r} is type {type(value).__name__}, unsupported")
