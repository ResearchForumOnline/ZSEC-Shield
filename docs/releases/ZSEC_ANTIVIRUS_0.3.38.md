# ZSEC Antivirus 0.3.38 Store candidate

Prepared and verified 23 October 2026 from clean application source commit `d8f19e5c777fa1494fcbeb9c073342ba1348319f`. Source is public on GitHub. Microsoft Partner Center accepted the exact validated 0.3.38.0 package in Submission 9, ID `1152921505702214959`; the final overview shows **Update in certification**, with pre-processing in progress. Automatic publication after approval is preserved. Prior Submission 8 remains live. Certification, new-version public delivery and installed acceptance are not established. [Store receipt](ZSEC_ANTIVIRUS_0.3.38_STORE.json).

## Change

Privacy-bounded support exports now distinguish the observation times and ages of engine status and Windows protection evidence, with explicit recent/stale/unknown/clock-ahead labels. Export states that it uses saved observations and performs no live protection recheck. Timezone-naive times are rejected before local timezone conversion. Existing validated health evidence is retained rather than silently rewritten when it becomes old.

Ordinary operation remains automatic and quiet. Detections, integrity failures and primary Windows protection failures retain alerts; advanced controls and explicit recovery remain available. No Defender preferences, exclusions, firewall rules, primary-provider registration or server configuration were changed.

## Verification

- Full test suite: 393 tests and 22 subtests passed. Focused support/UI/quiet automation checks: 65 tests passed.
- Ruff passed across the repository. CI-scope mypy passed for `src/zsec_shield` and `packaging/native_release.py` (29 files).
- Native GUI and engine were built with version 0.3.38.0 from a clean source tree. Native builder verifies PE identity, executable manifests and CLI smoke contracts.
- Microsoft SDK MakeAppx schema validation/package creation passed. The staged payload was rehashed after staging. All 1,093 MSIX ZIP entries passed integrity, and all 1,090 payload files matched recorded sizes and SHA-256 digests.
- The unregistered Store payload GUI started and remained responsive with disposable state. This smoke does not establish behavior after a clean Store-signed installation or update.
- WACK 10.0.28000.2270 completed 24 tests, PARTIAL_RUN FALSE, overall PASS for exact identity/version `talktoai.ZSECAntivirus` / `0.3.38.0`. The optional Blocked executables test failed on static process-launch references in bundled Python/Tcl/OpenSSL components. This finding is retained; not every optional check passed.

## Artifact

Filename: `ZSEC-Antivirus-0.3.38.0-x64.msix`

Size: 36,441,245 bytes.

SHA-256: `7424fdf3117c0797d10d5d4b48ada173a028f24ec147425d8de44617a5b51fff`.

Identity: `talktoai.ZSECAntivirus`; publisher: `CN=9B704446-6F62-4D52-954E-775436315422`; x64; Windows.Desktop minimum `10.0.17763.0`. Only runFullTrust is requested. The package-owned `ZSECAntivirusStartup` task remains declared and respects Windows user/administrator startup state at runtime. The upload MSIX is unsigned for Microsoft Store processing.

WACK report SHA-256: `3124e6c1ec2d31b6e502e68ea269bc6a8ace44863a230f68e97d23a3efc2e642`.

The matching direct archive is `zsec-antivirus-desktop-0.3.38-windows-x86_64.zip`, SHA-256 `b0fc7dead5e1c3b856bdefbdee0f7ca9066d029148ff98ae67dea87abe3373b6`. This local archive is not a receipt for a public GitHub binary release.

[Reviewer notes](ZSEC_ANTIVIRUS_0.3.38_REVIEWER.txt) describe account-free review and the preserved static-test caveat.

Partner Center package validation completed before its same-target 0.3.37 package was removed from the new submission. Reviewer instructions including the optional WACK caveat were saved and verified after reload. The English What's New field was updated for 0.3.38 and saved. Other submission settings and the existing automatic publishing choice were retained.
