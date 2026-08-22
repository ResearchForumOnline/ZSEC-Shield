"""Domain errors with messages safe to present at the command line."""

from __future__ import annotations


class ZsecShieldError(Exception):
    """Base class for expected ZSEC Shield failures."""


class FeedError(ZsecShieldError):
    """A rule feed or trust-store operation failed closed."""


class ScanConfigurationError(ZsecShieldError):
    """A scan option is unsafe or invalid."""


class WatchError(ZsecShieldError):
    """Foreground filesystem monitoring could not maintain honest coverage."""


class QuarantineError(ZsecShieldError):
    """A quarantine operation could not be completed safely."""


class QuarantinePartialError(QuarantineError):
    """A verified recovery copy exists, but the original was not removed."""

    def __init__(self, message: str, entry_id: str) -> None:
        super().__init__(message)
        self.entry_id = entry_id
