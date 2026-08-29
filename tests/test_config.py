"""Settings come from the function's environment, which Terraform fills from
its own outputs. The claim model (PLAN.md §4): CLAIM_TTL = lambda_timeout + M,
M > 1 s, sum at most 30 s; anything else is rejected before a finding is read."""

from datetime import timedelta

import pytest

from sapper.config import load_settings

ENV = {
    "EVIDENCE_BUCKET": "sapper-evidence-116137268889",
    "SCOPE_ARNS": "arn:aws:s3:::sapper-lab-public-116137268889,arn:aws:s3:::second-lab",
    "PROPOSER_TIMEOUT_SECONDS": "10",
    "CLAIM_MARGIN_SECONDS": "5",
}


def test_settings_derive_claim_ttl_from_timeout_plus_margin() -> None:
    settings = load_settings(ENV)

    assert settings.evidence_bucket == "sapper-evidence-116137268889"
    assert settings.scope_arns == frozenset(
        {"arn:aws:s3:::sapper-lab-public-116137268889", "arn:aws:s3:::second-lab"}
    )
    assert settings.claim_margin == timedelta(seconds=5)
    assert settings.claim_ttl == timedelta(seconds=15)


@pytest.mark.parametrize(("timeout", "margin"), [("29", "1.5"), ("25", "5.5")])
def test_claim_ttl_above_thirty_seconds_is_rejected(timeout: str, margin: str) -> None:
    with pytest.raises(ValueError):
        load_settings(
            {**ENV, "PROPOSER_TIMEOUT_SECONDS": timeout, "CLAIM_MARGIN_SECONDS": margin}
        )


def test_claim_ttl_of_exactly_thirty_seconds_is_allowed() -> None:
    settings = load_settings({**ENV, "PROPOSER_TIMEOUT_SECONDS": "25", "CLAIM_MARGIN_SECONDS": "5"})

    assert settings.claim_ttl == timedelta(seconds=30)


@pytest.mark.parametrize("timeout", ["0", "-100"])
def test_non_positive_timeout_is_rejected(timeout: str) -> None:
    # A claim that expires at or before created_at has no live window, so two
    # concurrent invocations would both proceed (§4, step 3).
    with pytest.raises(ValueError):
        load_settings({**ENV, "PROPOSER_TIMEOUT_SECONDS": timeout})


@pytest.mark.parametrize("margin", ["1", "0.5"])
def test_margin_of_one_second_or_less_is_rejected(margin: str) -> None:
    # created_at carries one-second resolution, which is why M > 1 s (§4).
    with pytest.raises(ValueError):
        load_settings({**ENV, "CLAIM_MARGIN_SECONDS": margin})


@pytest.mark.parametrize(
    "scope",
    [
        " arn:aws:s3:::sapper-lab-public-116137268889",
        "arn:aws:ec2:us-east-1:116137268889:security-group/sg-1",
    ],
)
def test_scope_entries_that_are_not_canonical_bucket_arns_are_rejected(scope: str) -> None:
    # Gate 4 compares strings, so a stray space would drop every finding as
    # SCOPE with no error; the normalizer turns that into an init failure.
    with pytest.raises(ValueError):
        load_settings({**ENV, "SCOPE_ARNS": scope})


def test_empty_scope_is_rejected() -> None:
    with pytest.raises(ValueError):
        load_settings({**ENV, "SCOPE_ARNS": ""})


def test_missing_setting_raises() -> None:
    with pytest.raises(KeyError):
        load_settings({key: value for key, value in ENV.items() if key != "EVIDENCE_BUCKET"})
