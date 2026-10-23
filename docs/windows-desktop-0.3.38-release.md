# ZSEC Antivirus 0.3.38 source update

Support exports now include separate observation timestamps, ages and freshness states for engine status and Windows protection evidence. Reports distinguish recent observations (within five minutes), stale observations, unknown observation times and a clock ahead of export time. They explicitly state that export uses saved observations and does not perform a live protection check. The existing validated protection result remains intact so historical evidence is not silently rewritten.

The desktop records observation times only when it accepts a successful status/protection response. Failed status refreshes still invalidate export readiness. The support exporter rejects timezone-naive times before conversion, fixing a guard that previously accepted them by implicitly assigning the computer's local timezone. Evidence times are normalized to UTC.

This is an additive local diagnostic feature. Export still excludes file paths, device/user identifiers, quarantine contents and raw provider details. Quiet automatic monitoring, signed advisory updates, primary-protection alerts, Windows StartupTask policy and explicit quarantine controls retain their existing behavior.

Version 0.3.38 source and Store package verification are recorded separately from Store certification, public delivery and installed acceptance. Previous 0.3.37 delivery evidence remains historical.
