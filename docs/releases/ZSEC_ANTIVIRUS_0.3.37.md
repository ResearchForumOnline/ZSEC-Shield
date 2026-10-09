# ZSEC Antivirus 0.3.37 delivery receipt

The source and direct Windows release are published on GitHub. Microsoft Partner
Center accepted the exact validated 0.3.37.0 MSIX as Submission 8 on 9 October 2026.
Its final overview shows **Update in certification**, submission complete and
pre-processing in progress. Certification and publishing have not completed.
Publication is automatic after certification. This machine still has Store version
0.3.36.0; installed 0.3.37 and clean-VM startup/upgrade acceptance are not claimed.

Source revision: `3bf01935ce44a5728599ccb4cbdcd7d441014ca1`; clean native build.
All 387 source tests passed. Focused watcher tests passed 64 tests and six subtests.
Ruff passed across source, tests and desktop UI; mypy passed all 28 source modules.
[CI run](https://github.com/ResearchForumOnline/ZSEC-Shield/actions/runs/37946094117)
passed all ten jobs, including Windows and Ubuntu Python 3.13. CodeQL and dependency
graph workflows also passed. The prior 01a7fd5 retry-jitter failure was already
repaired in 0.3.36; this release addresses monitoring and notification behavior.

Three genuine Windows scenarios passed against the exact packaged native engine:
exclusive access lock followed by authoritative recovery, native disappearance
superseded without degrading current health, and an oversized file followed by
shrink and authoritative recovery. No scanner mocks or fake observers were used.
Current state recovered without erasing historical incomplete session evidence.
Unchanged oversized files remain incomplete in repeated differential reconciliations;
unrelated stable metadata entries remain cached for performance.

The exact MSIX received WACK overall PASS, complete run, 24 checks. The optional
Blocked executables check reports FAIL for process-launch APIs and bundled runtime
string references in Python/Tcl/OpenSSL. That warning is retained in the JSON
receipt, not represented as every check passing. The bridge has fixed argv and
shell=False, and advisory updates remain signed data-only operations.

[Public release](https://github.com/ResearchForumOnline/ZSEC-Shield/releases/tag/v0.3.37-windows)
was downloaded again and matches the native build SHA-256. Full artifact hashes
and package identity/version provenance are in the matching JSON receipt. Private
live-root event logs and development mock screenshots were not published or
uploaded as installed acceptance evidence.

Routine folder diagnostics never create desktop notifications. The live observer
uses calm running status during a large initial inventory or partial inspection;
Advanced options retain incomplete scope evidence. Detections, integrity failures
and primary Windows protection faults retain alerts. Standard-folder setup,
advisory maintenance and observer restart remain automatic. Windows controls Store
updates and package-owned startup; user and administrator startup choices remain
respected. Defender or another active primary antivirus supplies real-time
protection. ZSEC retains its supplementary security and recovery boundary.
