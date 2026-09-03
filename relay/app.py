#!/usr/bin/env python3
"""Small authenticated, receive-only relay for ScreenConnect incident bundles.

The relay intentionally has no public listing or download endpoint. Uploaded
archives are validated, encrypted with an age recipient, and stored under a
private directory for later administrator export.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import zipfile
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Callable, Optional
from urllib.parse import urlsplit


TOKEN_PATTERN = re.compile(r"^[0-9a-f]{64}$")
RECEIPT_PATTERN = re.compile(r"^[0-9a-f]{32}$")
FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
DEFAULT_MAX_UPLOAD_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_UNCOMPRESSED_BYTES = 250 * 1024 * 1024
DEFAULT_MAX_ZIP_ENTRIES = 1024
DEFAULT_RETENTION_SECONDS = 30 * 24 * 60 * 60


Encryptor = Callable[[Path, Path, str], None]
STORE_LOCK = threading.Lock()


@dataclass
class RelayConfig:
    storage_dir: Path
    token_digest: str
    age_recipient: str
    age_binary: str = "/usr/bin/age"
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES
    max_zip_entries: int = DEFAULT_MAX_ZIP_ENTRIES
    retention_seconds: int = DEFAULT_RETENTION_SECONDS
    encryptor: Optional[Encryptor] = None

    def __post_init__(self) -> None:
        self.storage_dir = Path(self.storage_dir)
        self.token_digest = self.token_digest.strip().lower()
        if not TOKEN_PATTERN.fullmatch(self.token_digest):
            raise ValueError("token_digest must be a 64-character SHA-256 hex digest")
        if not self.age_recipient:
            raise ValueError("age_recipient is required")
        if self.max_upload_bytes <= 0 or self.max_uncompressed_bytes <= 0:
            raise ValueError("upload limits must be positive")
        if self.max_zip_entries <= 0:
            raise ValueError("max_zip_entries must be positive")
        if self.retention_seconds <= 0:
            raise ValueError("retention_seconds must be positive")

    def prepare_storage(self) -> None:
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.storage_dir, 0o700)


def sha256_token(token: str) -> str:
    """Return the digest used for constant-time bearer-token validation."""

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def safe_filename(value: str) -> str:
    """Keep client metadata bounded and free of path separators."""

    value = (value or "").strip()
    if FILENAME_PATTERN.fullmatch(value):
        return value
    return "report.zip"


def _is_safe_archive_name(name: str) -> bool:
    if not name or "\\" in name or name.startswith("/"):
        return False
    if re.match(r"^[A-Za-z]:", name):
        return False
    parts = PurePosixPath(name).parts
    return ".." not in parts


def validate_zip_file(path: Path, max_uncompressed_bytes: int, max_zip_entries: int) -> int:
    """Validate ZIP structure and names without extracting anything."""

    if not zipfile.is_zipfile(path):
        raise ValueError("upload is not a valid ZIP archive")
    total_uncompressed = 0
    try:
        with zipfile.ZipFile(path, "r") as archive:
            entries = archive.infolist()
            if not entries:
                raise ValueError("upload ZIP is empty")
            if len(entries) > max_zip_entries:
                raise ValueError("upload ZIP contains too many entries")
            for info in entries:
                if not _is_safe_archive_name(info.filename):
                    raise ValueError("upload contains an unsafe archive path")
                # Unix symlink entries must not be accepted even though the
                # relay never extracts the archive.
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise ValueError("upload contains a symlink entry")
                total_uncompressed += max(0, info.file_size)
                if total_uncompressed > max_uncompressed_bytes:
                    raise ValueError("upload expands beyond the configured limit")
    except zipfile.BadZipFile as exc:
        raise ValueError("upload is not a valid ZIP archive") from exc
    return total_uncompressed


def cleanup_expired(config: RelayConfig, now: Optional[float] = None) -> int:
    """Remove only relay-owned expired files; return the number removed."""

    now = time.time() if now is None else now
    cutoff = now - config.retention_seconds
    removed = 0
    if not config.storage_dir.is_dir():
        return removed
    for item in config.storage_dir.iterdir():
        if item.suffix not in (".age", ".json", ".tmp"):
            continue
        if not RECEIPT_PATTERN.fullmatch(item.name.split(".", 1)[0]):
            continue
        try:
            if item.stat().st_mtime < cutoff:
                item.unlink()
                removed += 1
        except FileNotFoundError:
            pass
    return removed


def find_receipt_by_digest(config: RelayConfig, digest: str) -> Optional[dict]:
    """Return an existing receipt with this body hash, if both files exist."""

    if not config.storage_dir.is_dir():
        return None
    for metadata_path in config.storage_dir.iterdir():
        if metadata_path.suffix != ".json" or not RECEIPT_PATTERN.fullmatch(metadata_path.stem):
            continue
        encrypted_path = config.storage_dir / (metadata_path.stem + ".age")
        if not encrypted_path.is_file():
            continue
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if (
            isinstance(metadata, dict)
            and isinstance(metadata.get("receipt_id"), str)
            and RECEIPT_PATTERN.fullmatch(metadata["receipt_id"])
            and metadata.get("sha256") == digest
        ):
            return metadata
    return None


def encrypt_to_age(config: RelayConfig, source: Path, destination: Path) -> None:
    """Encrypt a validated upload into the final private storage path."""

    if config.encryptor is not None:
        config.encryptor(source, destination, config.age_recipient)
        os.chmod(destination, 0o600)
        return
    temporary_destination = destination.with_suffix(destination.suffix + ".tmp")
    try:
        subprocess.run(
            [
                config.age_binary,
                "-r",
                config.age_recipient,
                "-o",
                str(temporary_destination),
                str(source),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=120,
            text=True,
        )
        os.chmod(temporary_destination, 0o600)
        os.replace(temporary_destination, destination)
    finally:
        try:
            temporary_destination.unlink()
        except FileNotFoundError:
            pass


def _write_private_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class RelayHandler(BaseHTTPRequestHandler):
    """HTTP boundary: health check plus authenticated raw ZIP uploads."""

    server_version = ""
    sys_version = ""

    @property
    def config(self) -> RelayConfig:
        return self.server.relay_config  # type: ignore[attr-defined]

    def log_message(self, _format: str, *_args: object) -> None:
        # Do not log paths, filenames, addresses, or headers containing data.
        return

    def _respond(self, status: int, payload: object, include_body: bool = True) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not include_body:
            return
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return False
        token = header[7:].strip()
        if not token:
            return False
        supplied_digest = sha256_token(token)
        return hmac.compare_digest(supplied_digest, self.config.token_digest)

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._respond(HTTPStatus.OK, {"ok": True}, include_body=False)
            return
        self._respond(HTTPStatus.NOT_FOUND, {"error": "not found"}, include_body=False)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._respond(HTTPStatus.OK, {"ok": True})
            return
        self._respond(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        if path != "/v1/uploads":
            self.close_connection = True
            self._respond(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self._authorized():
            self.close_connection = True
            self._respond(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return

        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type not in ("application/zip", "application/octet-stream"):
            self.close_connection = True
            self._respond(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "ZIP content required"})
            return
        raw_length = self.headers.get("Content-Length")
        try:
            content_length = int(raw_length) if raw_length is not None else -1
        except ValueError:
            content_length = -1
        if content_length < 0:
            self.close_connection = True
            self._respond(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length required"})
            return
        if content_length > self.config.max_upload_bytes:
            self.close_connection = True
            self._respond(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "upload is too large"})
            return

        expected_digest = self.headers.get("X-Report-SHA256", "").strip().lower()
        if expected_digest and not TOKEN_PATTERN.fullmatch(expected_digest):
            self.close_connection = True
            self._respond(HTTPStatus.BAD_REQUEST, {"error": "X-Report-SHA256 must be a SHA-256 hex digest"})
            return

        receipt_id = secrets.token_hex(16)
        temporary = self.config.storage_dir / (receipt_id + ".tmp")
        encrypted = self.config.storage_dir / (receipt_id + ".age")
        metadata = self.config.storage_dir / (receipt_id + ".json")
        digest = hashlib.sha256()
        remaining = content_length
        response_status = HTTPStatus.CREATED
        response_payload: object = {}
        stored = False
        try:
            with temporary.open("xb") as output:
                os.chmod(temporary, 0o600)
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("request body ended early")
                    output.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
            actual_digest = digest.hexdigest()
            if expected_digest and expected_digest != actual_digest:
                raise ValueError("X-Report-SHA256 does not match request body")
            uncompressed_bytes = validate_zip_file(temporary, self.config.max_uncompressed_bytes, self.config.max_zip_entries)
            with STORE_LOCK:
                # Deduplication is deliberately based on the digest of the body
                # that was actually received (actual_digest), never on the
                # X-Report-SHA256 claim alone. A duplicate response therefore
                # always refers to bytes that were really read and validated.
                cleanup_expired(self.config)
                existing = find_receipt_by_digest(self.config, actual_digest)
                if existing is not None:
                    response_status = HTTPStatus.OK
                    response_payload = {
                        "bytes": existing.get("bytes", content_length),
                        "expires_unix": existing.get("expires_unix", 0),
                        "receipt_id": existing["receipt_id"],
                        "sha256": existing["sha256"],
                        "status": "already_stored",
                    }
                else:
                    encrypt_to_age(self.config, temporary, encrypted)
                    received = int(time.time())
                    _write_private_json(
                        metadata,
                        {
                            "bytes": content_length,
                            "filename": safe_filename(self.headers.get("X-Report-Filename", "")),
                            "received_unix": received,
                            "expires_unix": received + self.config.retention_seconds,
                            "receipt_id": receipt_id,
                            "sha256": actual_digest,
                            "uncompressed_bytes": uncompressed_bytes,
                        },
                    )
                    response_payload = {
                        "bytes": content_length,
                        "expires_unix": received + self.config.retention_seconds,
                        "receipt_id": receipt_id,
                        "sha256": actual_digest,
                        "status": "stored",
                    }
                    stored = True
        except ValueError as exc:
            response_status = HTTPStatus.BAD_REQUEST
            response_payload = {"error": str(exc)}
        except Exception:
            # Details stay in the service journal, not in a public response.
            response_status = HTTPStatus.INTERNAL_SERVER_ERROR
            response_payload = {"error": "upload could not be stored"}
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            if not stored:
                for path_to_remove in (encrypted, metadata):
                    try:
                        path_to_remove.unlink()
                    except FileNotFoundError:
                        pass

        # Cleanup completes before the client receives the terminal response.
        self._respond(response_status, response_payload)


class RelayServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], config: RelayConfig):
        config.prepare_storage()
        self.relay_config = config
        super().__init__(server_address, RelayHandler)


def make_server(host: str, port: int, config: RelayConfig) -> RelayServer:
    return RelayServer((host, port), config)


def config_from_environment() -> RelayConfig:
    digest = os.environ.get("RELAY_TOKEN_SHA256", "")
    recipient = os.environ.get("AGE_RECIPIENT", "")
    storage = os.environ.get("STORAGE_DIR", "/var/lib/screenconnect-report-relay/inbox")
    return RelayConfig(
        storage_dir=Path(storage),
        token_digest=digest,
        age_recipient=recipient,
        age_binary=os.environ.get("AGE_BINARY", "/usr/bin/age"),
        max_upload_bytes=int(os.environ.get("MAX_UPLOAD_BYTES", DEFAULT_MAX_UPLOAD_BYTES)),
        max_uncompressed_bytes=int(os.environ.get("MAX_UNCOMPRESSED_BYTES", DEFAULT_MAX_UNCOMPRESSED_BYTES)),
        max_zip_entries=int(os.environ.get("MAX_ZIP_ENTRIES", DEFAULT_MAX_ZIP_ENTRIES)),
        retention_seconds=int(os.environ.get("RETENTION_SECONDS", DEFAULT_RETENTION_SECONDS)),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("BIND_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("BIND_PORT", "9127")))
    args = parser.parse_args()
    config = config_from_environment()
    server = make_server(args.host, args.port, config)
    print("screenconnect-report-relay listening on %s:%d" % (args.host, args.port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
