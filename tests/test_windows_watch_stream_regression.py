"""Every routine engine event must survive the desktop's strict stream bridge."""

from __future__ import annotations

import copy
import json
import sys
import threading
from pathlib import Path

import pytest

GUI_ROOT = Path(__file__).resolve().parents[1] / "apps" / "windows-ui"
if str(GUI_ROOT) not in sys.path:
    sys.path.insert(0, str(GUI_ROOT))

from zsec_desktop.bridge import WatchSession  # noqa: E402
from zsec_desktop.contracts import ContractError, validate_watch_event  # noqa: E402


def event(name: str, sequence: int = 1, **fields: object) -> dict[str, object]:
    return {
        "schema": "zsec.shield.watch-event.v1",
        "session_id": "stream-regression-session",
        "sequence": sequence,
        "generated_at": "2026-10-02T14:00:00Z",
        "event": name,
        **fields,
    }


def inventory() -> dict[str, object]:
    return event(
        "metadata_inventory_completed",
        outcome="metadata_inventory_complete",
        triggers=["initial_metadata_inventory"],
        scan={
            "findings": [],
            "observations": [],
            "issues": [],
            "stats": {"files_hashed": 0, "errors": 0},
        },
        quarantine=[],
    )


def superseded() -> dict[str, object]:
    return event(
        "events_superseded",
        count=3,
        sample_paths=["C:/Downloads/a.tmp", "C:/Downloads/b.tmp"],
        sample_paths_omitted=1,
        triggers=["periodic_reconciliation"],
        reason="paths_vanished_during_scan",
    )


@pytest.mark.parametrize("outcome", ["metadata_inventory_complete", "incomplete"])
def test_inventory_completion_is_a_supported_engine_event(outcome: str) -> None:
    value = inventory()
    value["outcome"] = outcome
    assert validate_watch_event(value)["outcome"] == outcome


@pytest.mark.parametrize(
    "field,value",
    [
        ("outcome", "future_unknown_outcome"),
        ("quarantine", [{"id": "unexpected"}]),
        (
            "scan",
            {
                "findings": [],
                "observations": [],
                "issues": [],
                "stats": {"files_hashed": 1, "errors": 0},
            },
        ),
        (
            "scan",
            {
                "findings": [],
                "observations": [],
                "issues": [{"code": "denied"}],
                "stats": {"files_hashed": 0, "errors": 1},
            },
        ),
    ],
)
def test_inventory_never_authorizes_unknown_outcomes_or_content_actions(
    field: str,
    value: object,
) -> None:
    payload = inventory()
    payload[field] = value
    with pytest.raises(ContractError):
        validate_watch_event(payload)


def test_vanished_download_records_are_supported_and_bounded() -> None:
    assert validate_watch_event(superseded())["count"] == 3
    single = event(
        "event_superseded",
        path="C:/Downloads/a.tmp",
        triggers=["created"],
        reason="path_vanished_before_scan",
    )
    assert validate_watch_event(single)["event"] == "event_superseded"
    malformed = copy.deepcopy(superseded())
    malformed["count"] = 999
    with pytest.raises(ContractError, match="counters"):
        validate_watch_event(malformed)


def test_inventory_issues_remain_readable_when_outcome_is_incomplete() -> None:
    payload = inventory()
    payload["outcome"] = "incomplete"
    payload["scan"] = {
        "findings": [],
        "observations": [],
        "issues": [{"code": "denied"}],
        "stats": {"files_hashed": 0, "errors": 1},
    }
    assert validate_watch_event(payload)["outcome"] == "incomplete"


def test_real_pipe_keeps_inventory_and_vanished_files_alive(tmp_path: Path) -> None:
    records = [
        event("session_started", backend_active="native"),
        inventory(),
        event(
            "event_superseded",
            path="C:/Downloads/a.tmp",
            triggers=["created"],
            reason="path_vanished_before_scan",
        ),
        superseded(),
        event("health_heartbeat", backend_active="native", operational_incomplete=False),
        event("session_completed", summary={}),
    ]
    for sequence, record in enumerate(records, 1):
        record["sequence"] = sequence
    source = tmp_path / "watch-stream.jsonl"
    source.write_text("\n".join(json.dumps(value) for value in records) + "\n", encoding="utf-8")
    received: list[dict[str, object]] = []
    completion: list[tuple[int, str | None]] = []
    finished = threading.Event()

    def on_complete(code: int, error: str | None) -> None:
        completion.append((code, error))
        finished.set()

    session = WatchSession(
        argv=[
            sys.executable,
            "-c",
            "import pathlib,sys;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())",
            str(source),
        ],
        on_event=received.append,
        on_complete=on_complete,
        quarantine=False,
    )
    session.start()
    try:
        assert finished.wait(10), "watch bridge failed to drain a completed stream"
        assert completion == [(0, None)]
        assert received == records
    finally:
        session.stop()
