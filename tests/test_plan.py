"""The dry-run plan and the §6 canonical hash. The canonicalizer is a security
control: the hashed bytes are the bytes the operator reads, so anything that can
render differently from how it hashes is rejected, drop reason PLAN_UNRENDERABLE."""

import hashlib

import pytest

from sapper.plan import (
    PlanUnrenderable,
    build_plan,
    canonical_plan_bytes,
    plan_sha256,
)

LAB_ARN = "arn:aws:s3:::sapper-lab-public-116137268889"


def test_plan_shape_matches_the_6b_contract() -> None:
    assert build_plan(LAB_ARN) == {
        "action": "s3-block-public-access",
        "target_arn": LAB_ARN,
        "set": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    }


def test_canonical_form_is_sorted_compact_ascii() -> None:
    plan = {"b": "two", "a": {"d": "x", "c": "y"}}

    assert canonical_plan_bytes(plan) == b'{"a":{"c":"y","d":"x"},"b":"two"}'


def test_hash_is_sha256_of_the_canonical_bytes() -> None:
    plan = build_plan(LAB_ARN)

    expected = hashlib.sha256(canonical_plan_bytes(plan)).hexdigest()

    assert plan_sha256(plan) == expected


def test_same_plan_same_hash_different_plan_different_hash() -> None:
    plan = build_plan(LAB_ARN)

    assert plan_sha256(plan) == plan_sha256(build_plan(LAB_ARN))
    assert plan_sha256(plan) != plan_sha256(build_plan("arn:aws:s3:::other-bucket"))


@pytest.mark.parametrize(
    "poisoned",
    [
        "esc\x1b[31mred",
        "carriage\rreturn",
        "bidi\u202eoverride",
        "zero\u200bwidth",
        "non-ascii-é",
        "tab\there",
    ],
)
def test_control_bearing_or_non_ascii_strings_are_rejected(poisoned: str) -> None:
    plan = build_plan(LAB_ARN)
    plan["target_arn"] = poisoned

    with pytest.raises(PlanUnrenderable):
        canonical_plan_bytes(plan)


def test_over_cap_canonical_form_is_rejected() -> None:
    plan = build_plan(LAB_ARN)
    plan["target_arn"] = "a" * 9000

    with pytest.raises(PlanUnrenderable):
        canonical_plan_bytes(plan)


def test_tuple_value_is_rejected() -> None:
    # Default-deny (F3): a tuple is neither a recognized scalar nor a dict/list,
    # so it must fall to the else branch rather than passing unchecked.
    plan = build_plan(LAB_ARN)
    plan["set"] = (True, False)

    with pytest.raises(PlanUnrenderable):
        canonical_plan_bytes(plan)


def test_non_str_dict_key_is_rejected() -> None:
    plan = build_plan(LAB_ARN)
    plan["set"] = {1: True}

    with pytest.raises(PlanUnrenderable):
        canonical_plan_bytes(plan)


def test_non_finite_float_is_rejected() -> None:
    plan = build_plan(LAB_ARN)
    plan["target_arn"] = float("nan")

    with pytest.raises(PlanUnrenderable):
        canonical_plan_bytes(plan)
