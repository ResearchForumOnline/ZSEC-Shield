"""Fail-closed replacement-readiness policy for supported desktop platforms."""

from __future__ import annotations

import platform
from typing import Any

from zsec_shield import __version__
from zsec_shield.util import format_utc

READINESS_SCHEMA = "zero.security.replacement-readiness.v1"

_PLATFORM_ALIASES = {
    "windows": "windows",
    "linux": "linux",
    "darwin": "macos",
    "macos": "macos",
}

_FOUNDATIONS: tuple[tuple[str, str], ...] = (
    (
        "deterministic_on_demand_scanner",
        "Streaming SHA-256 and exact configured-rule checks are implemented and tested.",
    ),
    (
        "signed_data_only_feed",
        "Ed25519 feed verification, expiry and rollback checks are implemented.",
    ),
    (
        "authenticated_encrypted_quarantine",
        "ZSV2 authenticated encrypted quarantine is implemented as a preview.",
    ),
    (
        "cross_platform_native_archives",
        "Unsigned preview archives are built and smoke-tested on Windows, macOS and Linux.",
    ),
)

_COMMON_GATES: tuple[tuple[str, str, str], ...] = (
    (
        "locked_efficacy_evaluation",
        "Independent malware and cleanware evaluation",
        "Versioned, held-out efficacy and false-positive results must meet published thresholds.",
    ),
    (
        "publisher_signed_release",
        "Publisher-signed production release",
        "Installer, binaries and update metadata must verify to the approved publisher identity.",
    ),
    (
        "binary_update_rollback",
        "Expiring staged updates and rollback",
        (
            "Binary, engine and rule updates need expiry, freeze protection, health "
            "halts and tested rollback."
        ),
    ),
    (
        "parser_isolation",
        "Hostile-file parser isolation",
        (
            "Archive, document and executable parsers must run with bounded resources "
            "and reduced privilege."
        ),
    ),
    (
        "performance_compatibility",
        "Desktop performance and compatibility fleet",
        (
            "Supported hardware, filesystems, applications and operating-system "
            "updates must pass regression gates."
        ),
    ),
    (
        "recovery_drills",
        "Quarantine and key-recovery certification",
        "Crash, corruption, lost-key, restore and rollback drills must preserve recoverability.",
    ),
    (
        "coexistence_cutover_rollback",
        "Coexistence and transactional cutover",
        (
            "A pilot must prove the old provider stays active until Zero Security is "
            "active and can be restored automatically."
        ),
    ),
    (
        "support_incident_response",
        "Support and incident-response operation",
        (
            "Signed emergency releases, revocation, vulnerability intake and user "
            "recovery procedures must be staffed."
        ),
    ),
)

_PLATFORM_GATES: dict[str, tuple[tuple[str, str, str], ...]] = {
    "windows": (
        (
            "windows_minifilter",
            "Signed FltMgr minifilter",
            (
                "A Microsoft-assigned altitude, HVCI-compatible driver and bounded "
                "verdict path must pass HLK and Verifier."
            ),
        ),
        (
            "windows_protected_service",
            "Protected service and restricted workers",
            (
                "The broker, parser workers and authenticated IPC must pass tamper and "
                "privilege-boundary tests."
            ),
        ),
        (
            "windows_amsi_elam",
            "x86/x64 AMSI and ELAM coverage",
            (
                "Both AMSI architectures, boot-start ELAM and safe failure behavior "
                "must be independently exercised."
            ),
        ),
        (
            "windows_security_registration",
            "Approved Windows Security registration",
            (
                "Microsoft onboarding and independently verified active/current "
                "Windows Security state are required."
            ),
        ),
    ),
    "linux": (
        (
            "linux_supported_matrix",
            "Supported distribution and kernel matrix",
            (
                "Exact distributions, kernels, architectures, filesystems and lifecycle "
                "dates must be published and tested."
            ),
        ),
        (
            "linux_realtime_broker",
            "Privileged fanotify real-time broker",
            (
                "Permission and notification modes need fail-safe policy, queue-overflow "
                "handling and filesystem coverage tests."
            ),
        ),
        (
            "linux_service_confinement",
            "systemd, SELinux and AppArmor confinement",
            (
                "The daemon and workers must use least privilege, capability bounds, "
                "syscall controls and supported MAC profiles."
            ),
        ),
        (
            "linux_signed_packages",
            "Signed distribution packages and repositories",
            (
                "Reproducible DEB/RPM packages, repository metadata, dependency policy "
                "and uninstall/rollback must be verified."
            ),
        ),
    ),
    "macos": (
        (
            "macos_endpoint_security",
            "Endpoint Security system extension",
            (
                "The approved entitlement, event coverage, deadline behavior and "
                "overload handling must pass release tests."
            ),
        ),
        (
            "macos_signed_notarized_app",
            "Developer ID, hardened runtime and notarization",
            (
                "The app, system extension and updater must be signed, notarized and "
                "accepted without bypassing Gatekeeper."
            ),
        ),
        (
            "macos_consent_and_coexistence",
            "Consent, Full Disk Access and Apple-control coexistence",
            (
                "System-extension activation and privacy consent must be clear while "
                "XProtect, Gatekeeper and SIP stay enabled."
            ),
        ),
        (
            "macos_architecture_matrix",
            "Apple silicon and supported Intel coverage",
            (
                "Supported macOS releases, architectures, filesystems, sleep/wake and "
                "OS-upgrade paths must pass a real fleet."
            ),
        ),
    ),
}


def normalize_platform(system: str | None = None) -> str:
    detected = system if system is not None else platform.system()
    return _PLATFORM_ALIASES.get(detected.strip().lower(), "unsupported")


def replacement_readiness(system: str | None = None) -> dict[str, Any]:
    """Return the immutable public-preview decision for one desktop platform.

    The current release has no evidence-ingestion or override mechanism. A caller
    cannot turn missing production gates into passed gates by editing a local flag.
    """

    platform_name = normalize_platform(system)
    platform_gates = _PLATFORM_GATES.get(
        platform_name,
        (
            (
                "supported_platform",
                "Supported desktop platform",
                "Zero Security has no production replacement programme for this platform.",
            ),
        ),
    )
    blockers = [
        {
            "id": gate_id,
            "title": title,
            "state": "not_met",
            "evidence_required": evidence,
        }
        for gate_id, title, evidence in (*_COMMON_GATES, *platform_gates)
    ]
    return {
        "schema": READINESS_SCHEMA,
        "generated_at": format_utc(),
        "version": __version__,
        "platform": platform_name,
        "release_stage": "on-demand-preview",
        "decision": "keep_existing_protection",
        "eligible_for_primary_replacement": False,
        "existing_provider_must_remain_active": True,
        "automatic_uninstall_available": False,
        "manual_override_available": False,
        "implemented_foundations": [
            {"id": foundation_id, "state": "implemented_preview", "evidence": evidence}
            for foundation_id, evidence in _FOUNDATIONS
        ],
        "blocking_gates": blockers,
        "gate_counts": {
            "met": 0,
            "not_met": len(blockers),
            "total": len(blockers),
        },
        "cutover_rule": (
            "Zero Security may offer removal of another antivirus only after every "
            "platform and common gate is independently evidenced on the exact release, "
            "a coexistence pilot passes, Zero Security is verified active and current, "
            "and automatic rollback proves the previous or operating-system provider can "
            "be restored."
        ),
        "next_action": (
            "Keep the currently active antivirus and operating-system protections enabled; "
            "use Zero Security only as an on-demand preview."
        ),
    }


__all__ = ["READINESS_SCHEMA", "normalize_platform", "replacement_readiness"]
