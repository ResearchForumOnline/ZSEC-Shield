"""Path-free hostile-content worker with a bounded streaming protocol.

The broker opens and validates each file, then streams bytes from that same open
descriptor while independently hashing them. The worker never receives a
filesystem path and has no quarantine or policy authority. A timeout, crash,
oversized frame, digest disagreement, or malformed response fails the file
closed instead of silently falling back to in-process content handling.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib
import json
import multiprocessing
import os
import signal
import uuid
from dataclasses import dataclass
from typing import Any

from zsec_shield.errors import ScanWorkerError
from zsec_shield.models import Rule

MAX_PROTOCOL_BYTES = 1024 * 1024
DEFAULT_WORKER_TIMEOUT_SECONDS = 45.0
DEFAULT_WORKER_MAX_REQUESTS = 512
WORKER_PROTOCOL = "zsec.scan-worker.v1"


@dataclass(frozen=True, slots=True)
class WorkerScan:
    sha256: str
    bytes_read: int
    literal_rule_ids: frozenset[str]


def _encode(value: dict[str, Any]) -> bytes:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(raw) > MAX_PROTOCOL_BYTES:
        raise ScanWorkerError("content worker protocol frame exceeded 1 MiB")
    return raw


def _decode(raw: bytes) -> dict[str, Any]:
    def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ScanWorkerError("content worker JSON contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScanWorkerError("content worker returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise ScanWorkerError("content worker frame must be a JSON object")
    return value


def _require_fields(value: dict[str, Any], required: set[str]) -> None:
    if set(value) != required:
        raise ScanWorkerError("content worker frame has missing or unknown fields")


def _send(connection: Any, value: dict[str, Any]) -> None:
    connection.send_bytes(_encode(value))


def _receive(connection: Any, timeout: float | None) -> dict[str, Any]:
    if timeout is not None and not connection.poll(timeout):
        raise ScanWorkerError("content worker exceeded its response deadline")
    try:
        return _decode(connection.recv_bytes(MAX_PROTOCOL_BYTES))
    except (EOFError, OSError) as exc:
        raise ScanWorkerError("content worker closed its protocol channel") from exc


def _rules_payload(rules: tuple[Rule, ...]) -> list[dict[str, str]]:
    payload: list[dict[str, str]] = []
    for rule in rules:
        if rule.kind == "literal":
            payload.append(
                {
                    "id": rule.rule_id,
                    "kind": "literal",
                    "value": base64.b64encode(rule.literal or b"").decode("ascii"),
                }
            )
    return payload


def _apply_posix_limits() -> None:
    if os.name == "nt":
        return
    try:
        resource: Any = importlib.import_module("resource")
        memory = 512 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
        if hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
        if hasattr(resource, "RLIMIT_AS"):
            resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    except (ImportError, OSError, ValueError):
        # The path-free protocol and broker timeout remain mandatory. Some
        # platforms do not permit an unprivileged child to lower every rlimit.
        pass


def _scan_stream(
    connection: Any,
    request: dict[str, Any],
    literal_rules: tuple[tuple[str, bytes], ...],
    chunk_bytes: int,
    max_file_bytes: int,
) -> dict[str, Any]:
    expected_size = request.get("size")
    if not isinstance(expected_size, int):
        raise ScanWorkerError("worker request has invalid file metadata")
    if expected_size > max_file_bytes:
        raise ScanWorkerError("file exceeds the content worker size policy")

    digest = hashlib.sha256()
    matches: set[str] = set()
    maximum_literal = max((len(value) for _identifier, value in literal_rules), default=0)
    tail = b""
    bytes_read = 0
    while bytes_read < expected_size:
        try:
            chunk = connection.recv_bytes(chunk_bytes)
        except (EOFError, OSError) as exc:
            raise ScanWorkerError("content stream ended before its declared length") from exc
        if not chunk or len(chunk) > chunk_bytes:
            raise ScanWorkerError("content stream frame is empty or oversized")
        bytes_read += len(chunk)
        if bytes_read > expected_size or bytes_read > max_file_bytes:
            raise ScanWorkerError("file grew beyond the content worker size policy")
        digest.update(chunk)
        window = tail + chunk
        for identifier, literal in literal_rules:
            if identifier not in matches and literal in window:
                matches.add(identifier)
        if maximum_literal > 1:
            tail = window[-(maximum_literal - 1) :]

    return {
        "ok": True,
        "sha256": digest.hexdigest(),
        "bytes_read": bytes_read,
        "literal_rule_ids": sorted(matches),
    }


def _worker_main(connection: Any) -> None:
    """Multiprocessing entry point. Never call application policy from here."""

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    os.umask(0o077)
    _apply_posix_limits()
    try:
        _send(
            connection,
            {"protocol": WORKER_PROTOCOL, "pid": os.getpid(), "ready": True},
        )
        configuration = _receive(connection, None)
        _require_fields(configuration, {"protocol", "chunk_bytes", "max_file_bytes", "rules"})
        if configuration.get("protocol") != WORKER_PROTOCOL:
            raise ScanWorkerError("worker configuration protocol mismatch")
        chunk_bytes = configuration.get("chunk_bytes")
        max_file_bytes = configuration.get("max_file_bytes")
        raw_rules = configuration.get("rules")
        if (
            not isinstance(chunk_bytes, int)
            or not isinstance(max_file_bytes, int)
            or not isinstance(raw_rules, list)
        ):
            raise ScanWorkerError("worker configuration is invalid")
        literals: list[tuple[str, bytes]] = []
        for raw_rule in raw_rules:
            if not isinstance(raw_rule, dict):
                raise ScanWorkerError("worker rule configuration is invalid")
            _require_fields(raw_rule, {"id", "kind", "value"})
            if raw_rule.get("kind") != "literal":
                continue
            identifier = raw_rule.get("id")
            value = raw_rule.get("value")
            if not isinstance(identifier, str) or not isinstance(value, str):
                raise ScanWorkerError("worker literal configuration is invalid")
            try:
                decoded = base64.b64decode(value, validate=True)
            except ValueError as exc:
                raise ScanWorkerError("worker literal is not valid base64") from exc
            if not decoded:
                raise ScanWorkerError("worker literal may not be empty")
            literals.append((identifier, decoded))
        literal_rules = tuple(literals)
        _send(connection, {"protocol": WORKER_PROTOCOL, "configured": True})

        while True:
            request = _receive(connection, None)
            if request.get("operation") == "shutdown":
                _require_fields(request, {"protocol", "operation"})
                if request.get("protocol") != WORKER_PROTOCOL:
                    raise ScanWorkerError("worker shutdown protocol violation")
                return
            _require_fields(request, {"protocol", "operation", "request_id", "size"})
            if request.get("operation") != "scan" or request.get("protocol") != WORKER_PROTOCOL:
                raise ScanWorkerError("worker request protocol violation")
            request_id = request.get("request_id")
            if (
                not isinstance(request_id, str)
                or len(request_id) != 32
                or any(character not in "0123456789abcdef" for character in request_id)
            ):
                raise ScanWorkerError("worker request correlation ID is invalid")
            try:
                response = _scan_stream(
                    connection,
                    request,
                    literal_rules,
                    chunk_bytes,
                    max_file_bytes,
                )
            except (OSError, ScanWorkerError) as exc:
                response = {"ok": False, "error": str(exc)[:500]}
            _send(
                connection,
                {"protocol": WORKER_PROTOCOL, "request_id": request_id, **response},
            )
    except (EOFError, OSError, ScanWorkerError):
        return
    finally:
        connection.close()


class BoundedScanWorker:
    """Persistent crash/timeout boundary for hostile file bytes."""

    def __init__(
        self,
        rules: tuple[Rule, ...],
        *,
        chunk_bytes: int,
        max_file_bytes: int,
        timeout_seconds: float = DEFAULT_WORKER_TIMEOUT_SECONDS,
        max_requests: int = DEFAULT_WORKER_MAX_REQUESTS,
    ) -> None:
        self._rules = rules
        self._chunk_bytes = chunk_bytes
        self._max_file_bytes = max_file_bytes
        self._timeout_seconds = timeout_seconds
        self._max_requests = max_requests
        self._process: Any = None
        self._connection: Any = None
        self._requests = 0

    def _start(self) -> None:
        self.close()
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=True)
        process = context.Process(target=_worker_main, args=(child,), daemon=True)
        process.start()
        child.close()
        self._process = process
        self._connection = parent
        try:
            hello = _receive(parent, self._timeout_seconds)
            _require_fields(hello, {"protocol", "pid", "ready"})
            if (
                hello.get("protocol") != WORKER_PROTOCOL
                or hello.get("ready") is not True
                or hello.get("pid") != process.pid
            ):
                raise ScanWorkerError("content worker hello was invalid")
            _send(
                parent,
                {
                    "protocol": WORKER_PROTOCOL,
                    "chunk_bytes": self._chunk_bytes,
                    "max_file_bytes": self._max_file_bytes,
                    "rules": _rules_payload(self._rules),
                },
            )
            acknowledgement = _receive(parent, self._timeout_seconds)
            if acknowledgement != {"protocol": WORKER_PROTOCOL, "configured": True}:
                raise ScanWorkerError("content worker rejected its configuration")
            self._requests = 0
        except ScanWorkerError:
            self.close()
            raise

    def _ensure_started(self) -> tuple[Any, Any]:
        if (
            self._process is None
            or self._connection is None
            or not self._process.is_alive()
            or self._requests >= self._max_requests
        ):
            self._start()
        assert self._process is not None
        assert self._connection is not None
        return self._process, self._connection

    def inspect(self, descriptor: int, opened: os.stat_result) -> WorkerScan:
        _process, connection = self._ensure_started()
        request_id = uuid.uuid4().hex
        request = {
            "protocol": WORKER_PROTOCOL,
            "operation": "scan",
            "request_id": request_id,
            "size": opened.st_size,
        }
        try:
            _send(connection, request)
            broker_digest = hashlib.sha256()
            bytes_sent = 0
            while True:
                chunk = os.read(descriptor, self._chunk_bytes)
                if not chunk:
                    break
                bytes_sent += len(chunk)
                if bytes_sent > opened.st_size or bytes_sent > self._max_file_bytes:
                    raise ScanWorkerError("file changed while broker streamed it")
                broker_digest.update(chunk)
                connection.send_bytes(chunk)
            after = os.fstat(descriptor)
            if (
                after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
                or bytes_sent != opened.st_size
            ):
                raise ScanWorkerError("file changed while broker streamed it")
            response = _receive(connection, self._timeout_seconds)
            self._requests += 1
            result = self._validate_response(response, opened.st_size, request_id)
            if result.sha256 != broker_digest.hexdigest():
                raise ScanWorkerError("broker and worker content digests disagreed")
            return result
        except (OSError, ScanWorkerError) as exc:
            self.close()
            if isinstance(exc, ScanWorkerError):
                raise
            raise ScanWorkerError(f"content worker transport failed: {exc}") from exc

    def _validate_response(
        self,
        response: dict[str, Any],
        expected_size: int,
        request_id: str,
    ) -> WorkerScan:
        if response.get("protocol") != WORKER_PROTOCOL:
            raise ScanWorkerError("content worker response protocol mismatch")
        if response.get("request_id") != request_id:
            raise ScanWorkerError("content worker response correlation mismatch")
        if response.get("ok") is not True:
            _require_fields(response, {"protocol", "request_id", "ok", "error"})
            message = response.get("error")
            raise ScanWorkerError(
                str(message)[:500] if isinstance(message, str) else "content worker failed"
            )
        digest = response.get("sha256")
        bytes_read = response.get("bytes_read")
        identifiers = response.get("literal_rule_ids")
        _require_fields(
            response,
            {
                "protocol",
                "request_id",
                "ok",
                "sha256",
                "bytes_read",
                "literal_rule_ids",
            },
        )
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not isinstance(bytes_read, int)
            or bytes_read != expected_size
            or not isinstance(identifiers, list)
            or not all(isinstance(identifier, str) for identifier in identifiers)
        ):
            raise ScanWorkerError("content worker response schema was invalid")
        allowed = {rule.rule_id for rule in self._rules if rule.kind == "literal"}
        returned = frozenset(identifiers)
        if len(returned) != len(identifiers) or not returned.issubset(allowed):
            raise ScanWorkerError("content worker returned an unknown or duplicate rule ID")
        return WorkerScan(digest, bytes_read, returned)

    def close(self) -> None:
        process = self._process
        connection = self._connection
        self._process = None
        self._connection = None
        self._requests = 0
        if connection is not None:
            try:
                if process is not None and process.is_alive():
                    _send(connection, {"protocol": WORKER_PROTOCOL, "operation": "shutdown"})
            except (OSError, ScanWorkerError):
                pass
            connection.close()
        if process is not None:
            process.join(timeout=1.0)
            if process.is_alive():
                process.kill()
                process.join(timeout=1.0)

    def __enter__(self) -> BoundedScanWorker:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        # Best-effort only; command paths close the worker deterministically.
        with contextlib.suppress(Exception):
            self.close()
