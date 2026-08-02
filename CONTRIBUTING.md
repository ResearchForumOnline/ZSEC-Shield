# Contributing

Keep runtime behavior deterministic, inspectable, cross-platform, and non-AI. New
feed capabilities must remain data-only and should narrow—not broaden—the accepted
schema. Any filesystem mutation requires an explicit operator action, a recoverable
path, and tests for partial failure.

Before proposing a change, run:

```bash
python -m pytest
ruff check src tests
mypy src/zsec_shield
python -m build
```

For native packaging changes, also install the pinned build dependency and exercise
the build on the current operating system:

```bash
python -m pip install -e ".[native]"
ruff check packaging/native_release.py tests/test_native_packaging.py
mypy packaging/native_release.py
python packaging/native_release.py build
```

Add regression tests for Windows, macOS, and Linux behavior where relevant. Do not
commit malware samples, the contiguous EICAR test string, secrets, private keys,
runtime state, quarantine objects, or host reports.
