# Popup regression harness

This is an isolated black-box test for the installed ZSEC Browser. It opens only
the checked-in, network-isolated fixture packaged under the existing
`https://newtab.zsec.local` virtual host. It never contacts a reported or
third-party test URL.

Close ZSEC Browser first, then run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\browser\zsec-desktop-preview\tests\popup-regression\Test-PopupRegression.ps1 -ReportPath .\artifacts\popup-regression.json
```

The harness verifies the installed executable and fixture hashes against the
installation inventory, launches it with the explicit authenticated
local-automation opt-in, and checks `TabCount` and
`ActiveTab` after load, timer, synthetic click, synthetic `target=_blank`, popup
storm, unsafe-scheme, and direct accessibility-click cases. The direct case
invokes the fixture's named button through Windows UI Automation. When Chromium
has not exposed its accessibility subtree, it sends Enter to the already
focused autofocus button. Both paths avoid DOM inspection, arbitrary JavaScript
and general click/type commands on the automation pipe.

The fixture uses `example.invalid` as a non-resolving HTTPS popup destination;
default denial occurs before it can navigate. Unsafe schemes can be rejected by WebView2 before `NewWindowRequested`; for
those cases an unchanged tab count and active-tab index are the required
black-box result. The report records whether a native popup event was observed.

The test refuses to close an existing browser session. It closes only the exact,
hash-verified process it started; if profile close-to-tray policy prevents a
graceful exit, it terminates that recorded PID during cleanup.
