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

Add regression tests for Windows, macOS, and Linux behavior where relevant. Do not
commit malware samples, the contiguous EICAR test string, secrets, private keys,
runtime state, quarantine objects, or host reports.

