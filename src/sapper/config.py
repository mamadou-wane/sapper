"""Settings from the function's environment (PLAN.md §4, §12). Terraform fills
the variables from its own outputs, so the lab allowlist and the timeout have
one source; the handler derives CLAIM_TTL here and refuses a configuration
outside the ruled bounds before any finding is read.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta

from sapper.proposal import normalize_resource_arn

ALLOWED_CONTROLS = frozenset({"S3.8"})  # §3 Gate 1, R1-minimal
CLAIM_TTL_CEILING = timedelta(seconds=30)  # §4: half Lambda's one-minute retry wait
CLAIM_MARGIN_FLOOR = timedelta(seconds=1)  # §4: created_at carries one-second resolution


@dataclass(frozen=True)
class Settings:
    evidence_bucket: str
    scope_arns: frozenset[str]
    claim_margin: timedelta
    claim_ttl: timedelta


def load_settings(env: Mapping[str, str]) -> Settings:
    # Gate 4 compares strings, so each entry goes through the one normalizer:
    # a malformed allowlist fails here instead of dropping every finding as SCOPE.
    scope_arns = frozenset(
        normalize_resource_arn(arn) for arn in env["SCOPE_ARNS"].split(",") if arn
    )
    if not scope_arns:
        raise ValueError("SCOPE_ARNS is empty: the proposer would have no lab scope")

    timeout = timedelta(seconds=float(env["PROPOSER_TIMEOUT_SECONDS"]))
    if timeout <= timedelta(0):
        raise ValueError(
            f"PROPOSER_TIMEOUT_SECONDS is {timeout.total_seconds()}; it must be positive"
        )
    margin = timedelta(seconds=float(env["CLAIM_MARGIN_SECONDS"]))
    if margin <= CLAIM_MARGIN_FLOOR:
        raise ValueError(
            f"CLAIM_MARGIN_SECONDS is {margin.total_seconds()}; "
            f"it must exceed {CLAIM_MARGIN_FLOOR.total_seconds()} s (§4)"
        )
    claim_ttl = timeout + margin
    if claim_ttl > CLAIM_TTL_CEILING:
        raise ValueError(
            f"timeout plus margin is {claim_ttl.total_seconds()} s, "
            f"above the {CLAIM_TTL_CEILING.total_seconds()} s ceiling (§4)"
        )

    return Settings(env["EVIDENCE_BUCKET"], scope_arns, margin, claim_ttl)
