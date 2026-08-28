# ZSEC Antivirus 0.3.32 Store acceptance

This is the release gate for the exact Microsoft Store candidate. Passing source
tests or launching an unpackaged development executable does not satisfy it. Record
the Store package identity, package SHA-256, packaged executable SHA-256, Windows
build, test timestamp, and result for every run. Use only benign synthetic data.

## Product boundary

ZSEC Antivirus 0.3.32 is a user-mode Windows security companion. Microsoft
Defender or another supported primary provider must remain active. ZSEC is not a
registered Windows Security provider, protected service, kernel pre-access filter,
or independently certified primary antivirus. A completed bounded scan does not
prove that the computer is clean.

The installed package owns startup of its GUI and packaged companion tools. It
must not require a source checkout, developer path, interactive script prompt,
administrator elevation, or writes to the read-only package directory. Mutable
state belongs in the documented per-user data location and must be handled safely
across relaunch, restart, upgrade, and uninstall.

Microsoft Store delivery is the executable update path. The ZSEC advisory feed is
a separate signed, data-only channel for advisories and exact rules. Feed handling
must verify the configured signing identity, reject invalid signatures and
rollbacks, and must never execute content or replace application binaries.

## Clean-VM matrix

Run on clean, supported Windows 10 and Windows 11 x64 VMs with Microsoft Defender
enabled. Test both a new Windows user and an ordinary standard user where practical.

| Gate | Procedure | Required evidence |
| --- | --- | --- |
| Fresh install | Install the exact Store-signed candidate and launch it from Start. | Correct package/version; GUI and packaged companion start without a checkout, elevation, or writable-package assumption. |
| App relaunch | Close the GUI normally and reopen it from Start. | Settings and supported per-user evidence remain valid; one healthy current-user companion instance; fresh bounded status. |
| Windows restart | Restart Windows and sign back into the same ordinary user. | Package-owned startup recovers automatically; fresh heartbeat; no duplicate companion; Defender remains active and unchanged. |
| Functional smoke | Refresh evidence, request Defender intelligence update and Quick scan, scan and monitor a benign disposable folder, cancel a second scan, and run isolated synthetic recovery. | Real scope and completion states; cancellation stays incomplete; recovery has no-overwrite and tamper checks; no primary-AV or clean-device claim. |
| Store upgrade | Install the prior Store release, create benign settings/evidence, then accept the Store update to 0.3.32. | Package binaries and displayed version advance; supported per-user state survives; companion restarts from the new package path; no obsolete package-owned startup target remains. |
| Advisory feed | Apply a valid newer signed data feed, then test an invalid signature and a lower sequence/version. | Valid data accepted; invalid and rollback inputs rejected; no executable or script is written or launched by feed content. |
| Uninstall | Uninstall through Windows Settings and restart Windows. | Package and package-owned startup removed; no packaged process remains; Defender/provider/firewall configuration unchanged; retained per-user data matches the disclosed policy. |

Any crash, indefinite loading state, stale heartbeat presented as healthy, duplicate
startup, unsupported security claim, unexplained WACK result, or package/feed update
ambiguity fails this gate. Do not submit until the exact Store candidate passes and
the evidence is attached to the release record.
