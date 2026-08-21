"""Automatic device-bound key handling for encrypted quarantine objects."""

from __future__ import annotations

import base64
import contextlib
import ctypes
import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from zsec_shield.errors import FeedError, QuarantineError
from zsec_shield.util import atomic_write_json, canonical_json_bytes, strict_json_loads

DEVICE_KEY_SCHEMA = "zero.security.device-root.v1"
VAULT_FORMAT = "ZSV2"
VAULT_PROFILE = "zero-security-quarantine-aes256gcm-v1"
KEY_BYTES = 32
NONCE_BYTES = 12
SALT_BYTES = 32
DPAPI_ENTROPY = b"ZERO-SECURITY/DEVICE-ROOT/V1\x00"
WRAP_INFO = b"ZERO-SECURITY/ZSV2/KEY-WRAP/V1\x00"
MAC_INFO = b"ZERO-SECURITY/ZSV2/METADATA-MAC/V1\x00"


@dataclass(frozen=True, slots=True)
class DeviceRoot:
    key: bytes
    protection: str


@dataclass(frozen=True, slots=True)
class VaultEnvelope:
    salt: bytes
    wrap_nonce: bytes
    wrapped_key: bytes
    content_nonce: bytes

    def to_dict(self, protection: str) -> dict[str, str]:
        return {
            "format": VAULT_FORMAT,
            "profile": VAULT_PROFILE,
            "cipher": "AES-256-GCM",
            "key_derivation": "HKDF-SHA-256",
            "device_key_protection": protection,
            "salt": _b64(self.salt),
            "wrap_nonce": _b64(self.wrap_nonce),
            "wrapped_key": _b64(self.wrapped_key),
            "content_nonce": _b64(self.content_nonce),
        }

    @classmethod
    def from_dict(cls, value: Any) -> VaultEnvelope:
        if not isinstance(value, dict):
            raise QuarantineError("vault envelope must be an object")
        required = {
            "format",
            "profile",
            "cipher",
            "key_derivation",
            "device_key_protection",
            "salt",
            "wrap_nonce",
            "wrapped_key",
            "content_nonce",
        }
        if set(value) != required:
            raise QuarantineError("vault envelope fields are invalid")
        expected = {
            "format": VAULT_FORMAT,
            "profile": VAULT_PROFILE,
            "cipher": "AES-256-GCM",
            "key_derivation": "HKDF-SHA-256",
        }
        for field, expected_value in expected.items():
            if value.get(field) != expected_value:
                raise QuarantineError(f"unsupported vault envelope field: {field}")
        protection = value.get("device_key_protection")
        if protection not in {"windows-dpapi-current-user", "filesystem-0600-preview"}:
            raise QuarantineError("unsupported device-key protection")
        salt = _decode(value.get("salt"), SALT_BYTES, "vault salt")
        wrap_nonce = _decode(value.get("wrap_nonce"), NONCE_BYTES, "key-wrap nonce")
        wrapped_key = _decode(value.get("wrapped_key"), KEY_BYTES + 16, "wrapped key")
        content_nonce = _decode(value.get("content_nonce"), NONCE_BYTES, "content nonce")
        return cls(salt, wrap_nonce, wrapped_key, content_nonce)


def load_device_root(state_dir: Path, *, create: bool) -> DeviceRoot:
    """Load the local root, creating and sealing it only when explicitly allowed."""

    key_directory = state_dir / "vault" / "keys"
    key_path = key_directory / "device-root.json"
    if not key_path.exists():
        if not create:
            raise QuarantineError("device root key is unavailable")
        key_directory.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(key_directory, 0o700)
        key = os.urandom(KEY_BYTES)
        if os.name == "nt":
            protection = "windows-dpapi-current-user"
            protected = _dpapi_protect(key)
        else:
            protection = "filesystem-0600-preview"
            protected = key
        record = {
            "schema": DEVICE_KEY_SCHEMA,
            "protection": protection,
            "protected_key": _b64(protected),
        }
        atomic_write_json(key_path, record, mode=0o600)
    try:
        value = strict_json_loads(key_path.read_bytes())
    except (OSError, FeedError) as exc:
        raise QuarantineError(f"cannot read device root key: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "protection",
        "protected_key",
    }:
        raise QuarantineError("device root key record is invalid")
    if value.get("schema") != DEVICE_KEY_SCHEMA:
        raise QuarantineError("unsupported device root key schema")
    stored_protection = value.get("protection")
    if not isinstance(stored_protection, str):
        raise QuarantineError("device root protection must be text")
    protected_key = _decode_variable(value.get("protected_key"), "protected device root")
    if stored_protection == "windows-dpapi-current-user":
        if os.name != "nt":
            raise QuarantineError("Windows DPAPI device root cannot be opened on this platform")
        key = _dpapi_unprotect(protected_key)
    elif stored_protection == "filesystem-0600-preview":
        if os.name == "nt":
            raise QuarantineError("unsealed preview device root is refused on Windows")
        key = protected_key
    else:
        raise QuarantineError("unsupported device root protection")
    if len(key) != KEY_BYTES:
        raise QuarantineError("device root key length is invalid")
    return DeviceRoot(key=key, protection=stored_protection)


def create_envelope(
    device: DeviceRoot, *, entry_id: str, aad: bytes
) -> tuple[VaultEnvelope, bytes]:
    content_key = os.urandom(KEY_BYTES)
    salt = os.urandom(SALT_BYTES)
    wrap_nonce = os.urandom(NONCE_BYTES)
    content_nonce = os.urandom(NONCE_BYTES)
    wrap_key = _derive(device.key, salt=salt, info=WRAP_INFO + entry_id.encode("ascii"))
    wrapped_key = AESGCM(wrap_key).encrypt(wrap_nonce, content_key, aad)
    return VaultEnvelope(salt, wrap_nonce, wrapped_key, content_nonce), content_key


def unwrap_content_key(
    device: DeviceRoot, *, entry_id: str, envelope: VaultEnvelope, aad: bytes
) -> bytes:
    wrap_key = _derive(
        device.key, salt=envelope.salt, info=WRAP_INFO + entry_id.encode("ascii")
    )
    try:
        key = AESGCM(wrap_key).decrypt(envelope.wrap_nonce, envelope.wrapped_key, aad)
    except Exception as exc:
        raise QuarantineError("vault content-key authentication failed") from exc
    if len(key) != KEY_BYTES:
        raise QuarantineError("unwrapped content key length is invalid")
    return key


def sign_metadata(device: DeviceRoot, metadata: dict[str, Any]) -> dict[str, Any]:
    unsigned = {key: value for key, value in metadata.items() if key != "metadata_mac"}
    mac_key = _derive(device.key, salt=None, info=MAC_INFO)
    signed = dict(unsigned)
    signed["metadata_mac"] = hmac.new(
        mac_key, canonical_json_bytes(unsigned), hashlib.sha256
    ).hexdigest()
    return signed


def verify_metadata(device: DeviceRoot, metadata: dict[str, Any]) -> None:
    supplied = metadata.get("metadata_mac")
    if not isinstance(supplied, str) or len(supplied) != 64:
        raise QuarantineError("vault metadata MAC is invalid")
    expected = sign_metadata(device, metadata)["metadata_mac"]
    if not hmac.compare_digest(supplied, expected):
        raise QuarantineError("vault metadata authentication failed")


def _derive(root: bytes, *, salt: bytes | None, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=salt, info=info).derive(root)


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: Any, expected_length: int, label: str) -> bytes:
    decoded = _decode_variable(value, label)
    if len(decoded) != expected_length:
        raise QuarantineError(f"{label} length is invalid")
    return decoded


def _decode_variable(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise QuarantineError(f"{label} must be base64 text")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise QuarantineError(f"{label} is invalid base64") from exc


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _input_blob(value: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_char]]:
    buffer = ctypes.create_string_buffer(value)
    blob = _DataBlob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    return blob, buffer


def _dpapi_protect(value: bytes) -> bytes:
    if os.name != "nt":
        raise QuarantineError("DPAPI is available only on Windows")
    input_blob, input_buffer = _input_blob(value)
    entropy_blob, entropy_buffer = _input_blob(DPAPI_ENTROPY)
    output_blob = _DataBlob()
    crypt32 = ctypes.windll.crypt32
    success = crypt32.CryptProtectData(
        ctypes.byref(input_blob),
        "Zero Security device root",
        ctypes.byref(entropy_blob),
        None,
        None,
        0x1,
        ctypes.byref(output_blob),
    )
    del input_buffer, entropy_buffer
    if not success:
        error = ctypes.get_last_error()
        raise QuarantineError(f"DPAPI protection failed with Windows error {error}")
    return _take_output_blob(output_blob)


def _dpapi_unprotect(value: bytes) -> bytes:
    if os.name != "nt":
        raise QuarantineError("DPAPI is available only on Windows")
    input_blob, input_buffer = _input_blob(value)
    entropy_blob, entropy_buffer = _input_blob(DPAPI_ENTROPY)
    output_blob = _DataBlob()
    description = ctypes.c_wchar_p()
    crypt32 = ctypes.windll.crypt32
    success = crypt32.CryptUnprotectData(
        ctypes.byref(input_blob),
        ctypes.byref(description),
        ctypes.byref(entropy_blob),
        None,
        None,
        0x1,
        ctypes.byref(output_blob),
    )
    del input_buffer, entropy_buffer
    if not success:
        raise QuarantineError(f"DPAPI unseal failed with Windows error {ctypes.get_last_error()}")
    try:
        return _take_output_blob(output_blob)
    finally:
        if description:
            ctypes.windll.kernel32.LocalFree(description)


def _take_output_blob(blob: _DataBlob) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob.pbData)
