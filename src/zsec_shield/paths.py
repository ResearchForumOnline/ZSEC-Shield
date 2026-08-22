"""Platform-correct application paths without third-party dependencies."""

from __future__ import annotations

import os
import platform
from importlib.resources import files
from pathlib import Path


def default_state_dir() -> Path:
    override = os.environ.get("ZSEC_SHIELD_HOME")
    if override:
        return Path(override).expanduser().absolute()

    system = platform.system()
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "ZSEC" / "Shield"
        return Path.home() / "AppData" / "Local" / "ZSEC" / "Shield"
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "ZSEC Shield"

    base = os.environ.get("XDG_STATE_HOME")
    if base:
        return Path(base) / "zsec-shield"
    return Path.home() / ".local" / "state" / "zsec-shield"


def bundled_keyring_path() -> Path:
    return Path(str(files("zsec_shield").joinpath("data", "trusted_keys.json")))


def resolve_keyring_path(state_dir: Path, explicit: Path | None = None) -> Path:
    if explicit is not None:
        return explicit.expanduser().absolute()
    environment = os.environ.get("ZSEC_SHIELD_KEYRING")
    if environment:
        return Path(environment).expanduser().absolute()
    local = state_dir / "trusted_keys.json"
    if local.is_file():
        return local
    return bundled_keyring_path()


def feed_document_path(state_dir: Path) -> Path:
    return state_dir / "feed" / "current.json"


def feed_state_path(state_dir: Path) -> Path:
    return state_dir / "feed" / "state.json"


def feed_lock_path(state_dir: Path) -> Path:
    return state_dir / "feed" / ".update.lock"


def feed_last_known_good_document_path(state_dir: Path) -> Path:
    return state_dir / "feed" / "last-known-good.json"


def feed_last_known_good_state_path(state_dir: Path) -> Path:
    return state_dir / "feed" / "last-known-good-state.json"


def automatic_update_status_path(state_dir: Path) -> Path:
    return state_dir / "feed" / "automatic-update-status.json"


def intelligence_document_path(state_dir: Path) -> Path:
    return state_dir / "intelligence" / "current.json"


def intelligence_envelope_path(state_dir: Path) -> Path:
    return state_dir / "intelligence" / "current-envelope.json"


def intelligence_state_path(state_dir: Path) -> Path:
    return state_dir / "intelligence" / "state.json"


def intelligence_last_known_good_path(state_dir: Path) -> Path:
    return state_dir / "intelligence" / "last-known-good-envelope.json"


def quarantine_entries_dir(state_dir: Path) -> Path:
    return state_dir / "quarantine" / "entries"
