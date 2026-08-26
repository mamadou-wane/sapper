"""ASFF parsing, isolated: the only module that reads a raw Security Hub finding.

Everything downstream consumes Finding, so the EventBridge contract stays
re-verifiable in one place (PLAN.md §3; the banked shape is
fixtures/sample-finding-event.json).
"""

from dataclasses import dataclass
from typing import Any


class FindingParseError(Exception):
    """A finding the parser cannot read. Callers drop it with a reason; they never crash."""


@dataclass(frozen=True)
class Finding:
    finding_id: str
    product_arn: str
    generator_id: str
    security_control_id: str
    compliance_status: str
    record_state: str
    workflow_status: str | None
    region: str
    resource_arn: str
    resource_type: str
    updated_at: str


def parse_finding(raw: dict[str, Any]) -> Finding:
    try:
        resources = raw["Resources"]
        if not resources:
            raise FindingParseError("Resources is empty")
        resource = resources[0]
        return Finding(
            finding_id=raw["Id"],
            product_arn=raw["ProductArn"],
            generator_id=raw["GeneratorId"],
            security_control_id=raw["Compliance"]["SecurityControlId"],
            compliance_status=raw["Compliance"]["Status"],
            record_state=raw["RecordState"],
            workflow_status=raw.get("Workflow", {}).get("Status"),
            region=raw["Region"],
            resource_arn=resource["Id"],
            resource_type=resource["Type"],
            updated_at=raw["UpdatedAt"],
        )
    except (KeyError, IndexError, TypeError, AttributeError, ValueError) as exc:
        raise FindingParseError(f"unreadable finding: {exc!r}") from exc
