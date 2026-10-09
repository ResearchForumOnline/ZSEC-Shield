# ZSEC Antivirus 0.3.36: quiet automatic operation

Open ZSEC once and leave it running in the notification area. Standard user-folder
monitoring, signed advisory maintenance and recovery from transient observer
failures run automatically. Windows owns sign-in startup and Microsoft Store
binary updates; an existing user or administrator startup opt-out is respected.

Routine successful scans, review-only observations and closing to the tray no
longer create notifications. Temporary monitoring interruptions receive a
five-minute recovery window before a health notification. Repeated identical
alerts are limited to one per thirty minutes. Distinct detection evidence,
integrity faults and primary Windows protection problems remain actionable.
Advanced options retain detailed monitoring, scanning, settings and recovery.
Incomplete coverage remains accurately recorded rather than being called healthy.

When validated evidence confirms active Microsoft Defender and stale signatures,
the Store app requests a fixed signature refresh on a background worker, at most
once an hour. The Windows action rechecks Defender immediately before requesting
the update. It changes no preferences, exclusions, providers or firewall settings.
Failed signed data checks retry in one to three hours while preserving the prior
verified data. Successful checks keep their existing daily schedule.

Microsoft Defender or another supported primary antivirus supplies malware
enforcement. ZSEC adds local Windows health evidence, signed advisories,
post-change file inspection, reports and explicit encrypted recovery tools.
Its built-in exact rules are wiring tests, not evidence of broad malware efficacy.
ZSEC does not register as a primary antivirus or claim independent efficacy
certification. Protection wording requires verified Windows evidence.

Local validation: 369 tests and 14 subtests passed, source type checking and
changed-file lint passed, and Python source/wheel distributions built. Native
packaging, public GitHub delivery, Store validation, certification and installed
acceptance are recorded separately in the matching delivery receipt.
