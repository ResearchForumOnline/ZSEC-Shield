"""Create a ZSEC Ed25519 update key outside the repository without printing it."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]


def _inside_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT.resolve())
    except ValueError:
        return False
    return True


def generate(private_output: Path, public_output: Path) -> dict[str, str]:
    if _inside_repo(private_output):
        raise ValueError("private key output must be outside the repository")
    if private_output.resolve() == public_output.resolve():
        raise ValueError("private and public output paths must differ")
    if private_output.exists() or public_output.exists():
        raise ValueError("refusing to overwrite an existing key file")
    private_output.parent.mkdir(parents=True, exist_ok=True)
    public_output.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private_raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    private_output.write_text(base64.b64encode(private_raw).decode() + "\n", encoding="ascii")
    public_output.write_text(base64.b64encode(public_raw).decode() + "\n", encoding="ascii")
    os.chmod(private_output, 0o600)
    os.chmod(public_output, 0o644)
    return {
        "private_output": str(private_output.resolve()),
        "public_key": base64.b64encode(public_raw).decode(),
        "public_output": str(public_output.resolve()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-output", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = generate(args.private_output, args.public_output)
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "ok": False}, sort_keys=True))
        return 2
    # The public key may be logged; the private key is deliberately never printed.
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
