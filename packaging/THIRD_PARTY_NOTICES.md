# Third-party notices

The native archive is assembled with PyInstaller and contains a Python interpreter
plus the runtime libraries needed by ZSEC Shield. The build script copies available
license texts for Python, PyInstaller, `cryptography`, `watchdog`, and installed
transitive components into the archive's `LICENSES` directory. Exact component versions and
copied license paths are recorded in `NATIVE-MANIFEST.json`.

For Python, the build prefers the target interpreter's own license file. When the
runner does not expose one, it copies the checksum-pinned CPython 3.11 license from
`packaging/licenses/CPython-3.11-LICENSE.txt`.

ZSEC Shield itself is licensed under Apache License 2.0; its license is the archive's
top-level `LICENSE` file. The presence of a third-party notice does not imply that the
third party endorses ZSEC Shield.
