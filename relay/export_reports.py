#!/usr/bin/env python3
"""Create a private bulk bundle from encrypted relay receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Callable, Optional

try:
    from .app import DEFAULT_MAX_UNCOMPRESSED_BYTES, DEFAULT_MAX_ZIP_ENTRIES, RECEIPT_PATTERN, validate_zip_file
except ImportError:  # pragma: no cover - direct script execution
    from app import DEFAULT_MAX_UNCOMPRESSED_BYTES, DEFAULT_MAX_ZIP_ENTRIES, RECEIPT_PATTERN, validate_zip_file


Decryptor = Callable[[Path, Path, Path], None]
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def decrypt_with_age(source: Path, destination: Path, identity_file: Path, age_binary: str = "/usr/bin/age") -> None:
    """Decrypt one receipt without invoking a shell."""

    subprocess.run(
        [
            age_binary,
            "--decrypt",
            "--identity",
            str(identity_file),
            "--output",
            str(destination),
            str(source),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=120,
        text=True,
    )


def _read_metadata(path: Path, receipt_id: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("invalid metadata for receipt " + receipt_id) from exc
    if not isinstance(value, dict) or value.get("receipt_id") != receipt_id:
        raise ValueError("metadata receipt mismatch for " + receipt_id)
    digest = value.get("sha256")
    if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
        raise ValueError("metadata hash missing for " + receipt_id)
    received = value.get("received_unix")
    if not isinstance(received, int) or received < 0:
        raise ValueError("metadata timestamp missing for " + receipt_id)
    return value


def _discover_records(storage_dir: Path) -> list[tuple[str, Path, Path, dict]]:
    if not storage_dir.is_dir():
        return []
    records: list[tuple[str, Path, Path, dict]] = []
    encrypted_ids: set[str] = set()
    metadata_ids: set[str] = set()
    for item in storage_dir.iterdir():
        if item.suffix == ".age" and RECEIPT_PATTERN.fullmatch(item.stem):
            encrypted_ids.add(item.stem)
        elif item.suffix == ".json" and RECEIPT_PATTERN.fullmatch(item.stem):
            metadata_ids.add(item.stem)
    if encrypted_ids != metadata_ids:
        missing_metadata = sorted(encrypted_ids - metadata_ids)
        missing_archive = sorted(metadata_ids - encrypted_ids)
        details = []
        if missing_metadata:
            details.append("missing metadata: " + ",".join(missing_metadata))
        if missing_archive:
            details.append("missing archive: " + ",".join(missing_archive))
        raise ValueError("relay storage is incomplete (" + "; ".join(details) + ")")
    for receipt_id in sorted(encrypted_ids):
        encrypted = storage_dir / (receipt_id + ".age")
        metadata_path = storage_dir / (receipt_id + ".json")
        records.append((receipt_id, encrypted, metadata_path, _read_metadata(metadata_path, receipt_id)))
    records.sort(key=lambda record: (record[3]["received_unix"], record[0]))
    return records


def build_bulk_archive(
    storage_dir: Path,
    identity_file: Path,
    output_path: Path,
    since_unix: Optional[int] = None,
    decryptor: Optional[Decryptor] = None,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
    max_zip_entries: int = DEFAULT_MAX_ZIP_ENTRIES,
) -> int:
    """Decrypt and combine receipts into a new archive; preserve source files."""

    storage_dir = Path(storage_dir)
    output_path = Path(output_path)
    if output_path.exists():
        raise ValueError("refusing to overwrite existing output archive")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    records = _discover_records(storage_dir)
    selected = [record for record in records if since_unix is None or record[3]["received_unix"] >= since_unix]
    decrypt = decryptor or (lambda source, destination, identity: decrypt_with_age(source, destination, identity))
    temporary_output = output_path.with_name(output_path.name + ".tmp")
    if temporary_output.exists():
        raise ValueError("temporary output already exists")
    count = 0
    try:
        with zipfile.ZipFile(temporary_output, "w", zipfile.ZIP_DEFLATED) as bundle:
            manifest = {
                "schema_version": 1,
                "reports": [record[3] for record in selected],
            }
            bundle.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            with tempfile.TemporaryDirectory(prefix="screenconnect-report-export-") as temp_dir:
                temp_root = Path(temp_dir)
                for receipt_id, encrypted, _metadata_path, metadata in selected:
                    decrypted = temp_root / (receipt_id + ".zip")
                    decrypt(encrypted, decrypted, Path(identity_file))
                    if not decrypted.is_file():
                        raise ValueError("decryption produced no file for " + receipt_id)
                    actual_hash = hashlib.sha256(decrypted.read_bytes()).hexdigest()
                    if actual_hash != metadata["sha256"]:
                        raise ValueError("hash mismatch for receipt " + receipt_id)
                    validate_zip_file(decrypted, max_uncompressed_bytes, max_zip_entries)
                    bundle.write(decrypted, "reports/" + receipt_id + ".zip")
                    count += 1
        os.chmod(temporary_output, 0o600)
        os.replace(temporary_output, output_path)
    finally:
        try:
            temporary_output.unlink()
        except FileNotFoundError:
            pass
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--storage-dir", default="/var/lib/screenconnect-report-relay/inbox")
    parser.add_argument("--identity-file", default="/etc/screenconnect-report-relay/age-key.txt")
    parser.add_argument("--output", required=True)
    parser.add_argument("--since-unix", type=int)
    args = parser.parse_args()
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        parser.error("bulk export must run as root")
    count = build_bulk_archive(Path(args.storage_dir), Path(args.identity_file), Path(args.output))
    print("exported %d report(s)" % count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
