"""Scaffold smoke tests: they prove the harness, not the proposer (PR 2 onward)."""

import json
from pathlib import Path

import sapper

FIXTURE = Path(__file__).parent.parent / "fixtures" / "sample-finding-event.json"


def test_package_imports() -> None:
    assert sapper.__doc__ is not None


def test_fixture_is_tracked_and_iterable() -> None:
    event = json.loads(FIXTURE.read_text())
    assert isinstance(event["detail"]["findings"], list)
