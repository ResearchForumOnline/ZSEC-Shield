# ZSEC Antivirus 0.3.34: Windows startup and monitoring reliability

## User-visible repair

The 0.3.33 Store Settings screen displayed a disabled startup checkbox. Its
implementation also treated Store startup as false without querying Windows,
although the MSIX manifest already declared the ZSECAntivirusStartup task.

This update uses the native Windows StartupTask interface in the packaged GUI.
It reads the real task state, applies explicit enable/disable requests and reads
back the result. When Windows reports DisabledByUser, the app explains how to
enable it in Windows Settings and offers Open Windows Startup apps and Refresh.
Administrator policy remains authoritative.

## Actual protection work

The local watcher inspects changed files within its monitored folders using
deterministic content rules and file hashes, plus independent reconciliation.
The Store GUI now supervises watcher failures, persists the user's enabled or
paused choice, delivers small pipe events promptly and reports incomplete or
stale coverage rather than inferring that the process is healthy.

Detection and coverage-interruption notifications are local. No file samples
are sent to the publisher. Existing explicit quarantine and no-overwrite
recovery boundaries remain in place.

Microsoft Defender or another supported active provider remains the real-time
pre-access enforcement layer. ZSEC is a user-mode post-change companion, not a
kernel filter, protected service or replacement Windows Security provider.

## Delivery evidence

Source changes, build checks, direct publication, Store submission, Store
certification and installed acceptance are separate stages. Consult the matching
release receipt for the stages actually completed; this document alone does not
establish publication or installation.

Windows StartupTask documentation:
https://learn.microsoft.com/uwp/api/windows.applicationmodel.startuptask
