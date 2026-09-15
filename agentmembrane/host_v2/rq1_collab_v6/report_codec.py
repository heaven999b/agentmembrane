"""Bounded, append-only storage for a workflow's evaluated report.

New runs store canonical JSON in a deterministic gzip member. Existing runs
with ``report.json`` and a ``status.report_sha256`` remain readable. The status
hashes are integrity checks relative to the status artifact, not signatures.
"""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import re
import stat
import uuid
import zlib
import gzip

from ..rq1_collab_v1.audit import canonical, strict_loads


REPORT_JSON = "report.json"
REPORT_GZIP = "report.json.gz"
ENCODING = "gzip"
MAX_REPORT_BYTES = 256 * 1024 * 1024
MAX_ENCODED_BYTES = MAX_REPORT_BYTES + 1024 * 1024
_CHUNK = 64 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _regular_path(root: Path, filename: str) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("report_directory_must_be_regular")
    path = root / filename
    if path.is_symlink():
        raise ValueError("report_symlink_forbidden")
    return path


def _selected_path(root: Path, *, compressed: bool) -> Path:
    raw = _regular_path(root, REPORT_JSON)
    encoded = _regular_path(root, REPORT_GZIP)
    if os.path.lexists(raw) and os.path.lexists(encoded):
        raise ValueError("ambiguous_dual_report_artifacts")
    selected = encoded if compressed else raw
    opposite = raw if compressed else encoded
    if os.path.lexists(opposite):
        raise ValueError("report_encoding_path_mismatch")
    if not os.path.lexists(selected):
        raise ValueError("report_artifact_missing")
    return selected


def _open_regular(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError("report_artifact_not_regular")
    return os.fdopen(fd, "rb")


def _require_hash(status: dict, key: str) -> str:
    value = status.get(key)
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError("invalid_report_hash_metadata")
    return value


def _require_size(status: dict, key: str, limit: int) -> int:
    value = status.get(key)
    if type(value) is not int or not 0 <= value <= limit:
        raise ValueError("invalid_report_size_metadata")
    return value


def _atomic_write_new(path: Path, payload: bytes) -> None:
    """Publish a complete file without replacing any existing report."""
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path, follow_symlinks=False)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def write_report(folder: str | Path, report: dict) -> dict:
    """Create ``report.json.gz`` and return fields to add to ``status.json``.

    The decoded stream is exactly ``canonical(report) + b'\\n'``, matching the
    historical JSON file. Neither an existing compressed nor legacy report is
    overwritten. The caller writes its own status only after this returns.
    """
    if type(report) is not dict:
        raise ValueError("report_object_required")
    root = Path(folder)
    raw_path = _regular_path(root, REPORT_JSON)
    encoded_path = _regular_path(root, REPORT_GZIP)
    if os.path.lexists(raw_path) or os.path.lexists(encoded_path):
        raise FileExistsError("report_artifact_already_exists")
    decoded = canonical(report) + b"\n"
    if len(decoded) > MAX_REPORT_BYTES:
        raise ValueError("report_decoded_size_limit_exceeded")
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0,
                       compresslevel=6) as handle:
        handle.write(decoded)
    encoded = buffer.getvalue()
    if len(encoded) > MAX_ENCODED_BYTES:
        raise ValueError("report_encoded_size_limit_exceeded")
    _atomic_write_new(encoded_path, encoded)
    return {"report_encoding": ENCODING,
            "report_sha256": _digest(encoded),
            "report_decoded_sha256": _digest(decoded),
            "report_bytes": len(encoded),
            "report_decoded_bytes": len(decoded)}


def _read_legacy(path: Path, expected_sha: str) -> bytes:
    digest = hashlib.sha256()
    result = io.BytesIO()
    total = 0
    with _open_regular(path) as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            total += len(chunk)
            if total > MAX_REPORT_BYTES:
                raise ValueError("report_decoded_size_limit_exceeded")
            digest.update(chunk)
            result.write(chunk)
    if digest.hexdigest() != expected_sha:
        raise ValueError("report_sha256_mismatch")
    return result.getvalue()


def _read_gzip(path: Path, expected_sha: str, expected_raw_sha: str,
               expected_size: int, expected_raw_size: int) -> bytes:
    digest = hashlib.sha256()
    decoded_digest = hashlib.sha256()
    decoder = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    output = io.BytesIO()
    encoded_count = decoded_count = 0
    try:
        with _open_regular(path) as handle:
            for chunk in iter(lambda: handle.read(_CHUNK), b""):
                encoded_count += len(chunk)
                if encoded_count > MAX_ENCODED_BYTES:
                    raise ValueError("report_encoded_size_limit_exceeded")
                digest.update(chunk)
                if decoder.eof:
                    raise ValueError("trailing_gzip_data_forbidden")
                pending = chunk
                while True:
                    room = min(_CHUNK, MAX_REPORT_BYTES - decoded_count + 1)
                    before = len(pending)
                    part = decoder.decompress(pending, room)
                    pending = decoder.unconsumed_tail
                    decoded_count += len(part)
                    if decoded_count > MAX_REPORT_BYTES:
                        raise ValueError("report_decoded_size_limit_exceeded")
                    decoded_digest.update(part)
                    output.write(part)
                    if decoder.unused_data:
                        raise ValueError("trailing_gzip_data_forbidden")
                    if decoder.eof:
                        break
                    if pending and len(pending) == before and not part:
                        raise ValueError("gzip_decoder_made_no_progress")
                    if not pending and len(part) < room:
                        break
                    pending = pending or b""
    except zlib.error as exc:
        raise ValueError("invalid_gzip_report") from exc
    if not decoder.eof:
        raise ValueError("truncated_gzip_report")
    if encoded_count != expected_size or digest.hexdigest() != expected_sha:
        raise ValueError("report_sha256_mismatch")
    if decoded_count != expected_raw_size or decoded_digest.hexdigest() != expected_raw_sha:
        raise ValueError("report_decoded_sha256_mismatch")
    return output.getvalue()


def read_report(folder: str | Path, status: dict) -> dict:
    """Verify and decode a new or historical report; fail closed on ambiguity."""
    if type(status) is not dict:
        raise ValueError("report_status_object_required")
    root = Path(folder)
    expected_sha = _require_hash(status, "report_sha256")
    encoding = status.get("report_encoding")
    if "report_encoding" not in status:
        if any(key in status for key in ("report_decoded_sha256", "report_bytes", "report_decoded_bytes")):
            raise ValueError("incomplete_report_encoding_metadata")
        decoded = _read_legacy(_selected_path(root, compressed=False), expected_sha)
    elif encoding == ENCODING:
        raw_sha = _require_hash(status, "report_decoded_sha256")
        encoded_size = _require_size(status, "report_bytes", MAX_ENCODED_BYTES)
        decoded_size = _require_size(status, "report_decoded_bytes", MAX_REPORT_BYTES)
        decoded = _read_gzip(_selected_path(root, compressed=True), expected_sha,
                             raw_sha, encoded_size, decoded_size)
    else:
        raise ValueError("unsupported_report_encoding")
    report = strict_loads(decoded)
    if type(report) is not dict:
        raise ValueError("report_object_required")
    if encoding == ENCODING and canonical(report) + b"\n" != decoded:
        raise ValueError("noncanonical_gzip_report")
    return report
