"""Shared fixtures. The event fixture is a banked real capture (P1); tests treat it
as ground truth for the ASFF shapes the parser must accept."""

import json
from pathlib import Path
from typing import Any

import pytest

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "sample-finding-event.json"


@pytest.fixture()
def finding_event() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text())


@pytest.fixture()
def raw_finding(finding_event: dict[str, Any]) -> dict[str, Any]:
    return finding_event["detail"]["findings"][0]
