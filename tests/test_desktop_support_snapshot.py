from __future__ import annotations

import copy
import json
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

GUI_ROOT = Path(__file__).resolve().parents[1] / "apps" / "windows-ui"
if str(GUI_ROOT) not in sys.path:
    sys.path.insert(0, str(GUI_ROOT))

from zsec_desktop.contracts import ContractError  # noqa: E402
from zsec_desktop.support import build_support_snapshot, save_support_snapshot  # noqa: E402

from tests.test_windows_gui_contracts import (  # noqa: E402
    valid_companion,
    valid_healthy_companion,
    valid_status,
)


def test_support_snapshot_is_bounded_path_free_and_truthful() -> None:
    status = valid_status()
    companion = valid_healthy_companion()
    companion["health"]["last_record"] = {  # type: ignore[index]
        "roots": [r"C:\Users\person\Desktop", r"C:\Users\person\Documents"],
        "process_id": 4242,
        "device_key": "must-not-escape",
    }
    snapshot = build_support_snapshot(
        status,
        companion,
        desktop_version="0.3.31",
        generated_at=datetime(2026, 8, 23, 0, 0, tzinfo=UTC),
    )
    encoded = json.dumps(snapshot, sort_keys=True)
    assert snapshot["schema"] == "zsec.antivirus.support-snapshot.v1"
    assert snapshot["automation"]["protected_root_count"] == 2
    assert snapshot["boundary"] == {
        "zsec_primary_antivirus": False,
        "zsec_real_time_protection": False,
        "existing_provider_must_remain_active": True,
    }
    for secret in ("person", "Desktop", "Documents", "4242", "must-not-escape"):
        assert secret not in encoded


def test_support_snapshot_rejects_unvalidated_or_contradictory_evidence() -> None:
    status = valid_status()
    status["real_time_protection"] = True
    with pytest.raises(ContractError, match="real-time protection"):
        build_support_snapshot(status, valid_companion(), desktop_version="0.3.31")

    companion = copy.deepcopy(valid_companion())
    companion["healthy"] = True
    with pytest.raises(ContractError, match="not_installed"):
        build_support_snapshot(valid_status(), companion, desktop_version="0.3.31")


def test_support_snapshot_rejects_unbounded_version() -> None:
    with pytest.raises(ValueError, match="bounded"):
        build_support_snapshot(valid_status(), valid_companion(), desktop_version="x" * 33)


def test_support_export_retains_observation_age_without_refreshing_or_relabeling_health() -> None:
    now = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
    snapshot = build_support_snapshot(
        valid_status(), valid_healthy_companion(), desktop_version="0.3.38",
        generated_at=now, status_observed_at=now - timedelta(seconds=60),
        companion_observed_at=now - timedelta(hours=2),
    )
    assert snapshot["evidence"]["status"]["freshness"] == "recent"
    assert snapshot["evidence"]["status"]["age_seconds"] == 60
    assert snapshot["evidence"]["windows_protection"]["freshness"] == "stale"
    assert snapshot["evidence"]["windows_protection"]["age_seconds"] == 7200
    assert snapshot["evidence"]["rechecked_during_export"] is False
    assert snapshot["automation"]["healthy"] is True


def test_missing_or_future_observation_is_never_called_recent() -> None:
    now = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
    snapshot = build_support_snapshot(
        valid_status(), valid_companion(), desktop_version="0.3.38",
        generated_at=now, companion_observed_at=now + timedelta(microseconds=1),
    )
    assert snapshot["evidence"]["status"]["freshness"] == "unknown"
    assert snapshot["evidence"]["windows_protection"]["freshness"] == "clock_ahead"


@pytest.mark.parametrize("field", ["generated_at", "status_observed_at", "companion_observed_at"])
def test_naive_times_are_rejected_before_local_timezone_can_change_the_evidence(field: str) -> None:
    with pytest.raises(ValueError, match="timezone"):
        build_support_snapshot(
            valid_status(), valid_companion(), desktop_version="0.3.38",
            **{field: datetime(2026, 10, 23, 12, 0)},
        )


def test_observation_offsets_are_normalized_and_recent_boundary_is_explicit() -> None:
    now = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
    snapshot = build_support_snapshot(
        valid_status(), valid_companion(), desktop_version="0.3.38", generated_at=now,
        status_observed_at=datetime(2026, 10, 23, 12, 55, tzinfo=timezone(timedelta(hours=1))),
        companion_observed_at=now - timedelta(seconds=301),
    )
    assert snapshot["evidence"]["status"]["age_seconds"] == 300
    assert snapshot["evidence"]["status"]["freshness"] == "recent"
    assert snapshot["evidence"]["windows_protection"]["freshness"] == "stale"


def test_support_snapshot_save_is_atomic_json_and_rejects_wrong_extension(
    tmp_path: Path,
) -> None:
    snapshot = build_support_snapshot(
        valid_status(), valid_companion(), desktop_version="0.3.31"
    )
    destination = tmp_path / "support.json"
    save_support_snapshot(destination, snapshot)
    assert json.loads(destination.read_text(encoding="utf-8")) == snapshot
    assert not list(tmp_path.glob(".zsec-support-*.tmp"))
    with pytest.raises(ValueError, match=r"end in \.json"):
        save_support_snapshot(tmp_path / "support.txt", snapshot)
