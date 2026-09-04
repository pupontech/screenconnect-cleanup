#!/usr/bin/env python3
"""Create deduplicated ScreenConnect relay/server IOC outputs from receipts.

Reads only connectwise-report.json from each validated report ZIP, aggregates
observed relay servers (host, port, thumbprints) across every stored receipt,
and writes four private text outputs. Raw evidence and binaries are never
extracted and never copied into the outputs.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Callable, Optional

try:
    from .app import DEFAULT_MAX_UNCOMPRESSED_BYTES, DEFAULT_MAX_ZIP_ENTRIES, validate_zip_file
    from .export_reports import decrypt_with_age, discover_records
except ImportError:  # pragma: no cover - direct script execution
    from app import DEFAULT_MAX_UNCOMPRESSED_BYTES, DEFAULT_MAX_ZIP_ENTRIES, validate_zip_file
    from export_reports import decrypt_with_age, discover_records


Decryptor = Callable[[Path, Path, Path], None]
REPORT_ENTRY_NAME = "connectwise-report.json"
REPORT_JSON_MAX_BYTES = 16 * 1024 * 1024
EXTERNAL_IOC_MAX_BYTES = 2 * 1024 * 1024
MAX_DISTINCT_RELAYS = 200000
MAX_DISTINCT_THUMBPRINTS = 200000
MAX_HOST_LENGTH = 253

# Each line of a report instance must map cleanly to a relay server address.
# Hostnames and IPv4 literals are accepted; schemes, paths, ports embedded in
# the host value are handled explicitly and bounded.
HOST_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$")
THUMBPRINT_PATTERN = re.compile(r"^[0-9A-Za-z:._-]+$")
OUTPUT_FILE_NAMES = (
    "relay-addresses.txt",
    "screenconnect-relays.csv",
    "connectwise-abuse-summary.txt",
    "screenconnect-relays.json",
)


def _utc_stamp(unix_time: int) -> str:
    return datetime.datetime.fromtimestamp(unix_time, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ci_get(instance: dict, key: str) -> object:
    """Read a JSON instance field tolerating PowerShell PascalCase keys."""
    if key in instance:
        return instance[key]
    lowered = key.lower()
    for existing in instance:
        if existing.lower() == lowered:
            return instance[existing]
    return None


def _normalize_host(value: object) -> Optional[str]:
    """Return a bounded lowercase host, or None when the value is unusable."""
    if not isinstance(value, str):
        return None
    host = value.strip().lower()
    if not host or len(host) > MAX_HOST_LENGTH:
        return None
    if not HOST_PATTERN.fullmatch(host):
        return None
    return host


def _normalize_port(value: object) -> Optional[int]:
    """Return an integer port in 1..65535, or None when absent/invalid."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        port = value
    elif isinstance(value, str):
        text = value.strip()
        if not text.isdigit():
            return None
        port = int(text)
    else:
        return None
    if port < 1 or port > 65535:
        return None
    return port


def _parse_relay_fields(host_value: object, port_value: object) -> tuple[Optional[str], Optional[int]]:
    """Resolve a relay host and port from instance fields.

    A host value may carry its own :port suffix (observed in the wild). The
    dedicated RelayPort field wins when both are present; the embedded suffix
    is only used when no separate port was observed.
    """
    port = _normalize_port(port_value)
    if not isinstance(host_value, str):
        return _normalize_host(host_value), port
    raw_host = host_value.strip().lower()
    if ":" not in raw_host:
        return _normalize_host(raw_host), port
    base, separator, suffix = raw_host.rpartition(":")
    if not base or not separator or not suffix or not suffix.isdigit():
        return None, port
    embedded = int(suffix)
    if embedded < 1 or embedded > 65535:
        return None, port
    host = _normalize_host(base)
    if host is None:
        return None, port
    return host, (port if port is not None else embedded)


def _normalize_thumbprint(value: object) -> Optional[str]:
    """Return a bounded lowercase thumbprint, or None when unusable."""
    if not isinstance(value, str):
        return None
    thumbprint = value.strip().lower()
    if not thumbprint or len(thumbprint) > 512:
        return None
    if not THUMBPRINT_PATTERN.fullmatch(thumbprint):
        return None
    return thumbprint


def _read_report_json(decrypted: Path, receipt_id: str) -> dict:
    """Read and parse only connectwise-report.json from a validated ZIP."""
    try:
        with zipfile.ZipFile(decrypted, "r") as archive:
            names = [name for name in archive.namelist() if name == REPORT_ENTRY_NAME]
            if not names:
                raise ValueError("report ZIP has no connectwise-report.json entry for " + receipt_id)
            if len(names) > 1:
                raise ValueError("report ZIP has multiple connectwise-report.json entries for " + receipt_id)
            info = archive.getinfo(names[0])
            if info.file_size > REPORT_JSON_MAX_BYTES:
                raise ValueError("connectwise-report.json exceeds the size bound for " + receipt_id)
            raw = archive.read(info)
    except zipfile.BadZipFile as exc:  # pragma: no cover - guarded by validate_zip_file
        raise ValueError("report ZIP could not be read for " + receipt_id) from exc
    try:
        report = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("connectwise-report.json is invalid JSON for " + receipt_id) from exc
    if not isinstance(report, dict):
        raise ValueError("connectwise-report.json is not an object for " + receipt_id)
    return report


def _report_instances(report: dict) -> list:
    """Locate the instance list, mirroring the client's nested-or-flat shape."""
    screen = report.get("ScreenConnect")
    if isinstance(screen, dict) and isinstance(screen.get("Instances"), list):
        return screen["Instances"]
    if isinstance(report.get("Instances"), list):
        return report["Instances"]
    return []


def _load_external_entries(path: Path) -> tuple[list[str], int]:
    """Parse a bounded external IOC list; return (entries, skipped lines)."""
    size = path.stat().st_size
    if size > EXTERNAL_IOC_MAX_BYTES:
        raise ValueError("external IOC list exceeds the size bound")
    entries: list[str] = []
    seen: set[str] = set()
    skipped = 0
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            token = line.split("#", 1)[0].strip().lower()
            if not token or len(token) > MAX_HOST_LENGTH + 6:
                skipped += 1
                continue
            if token not in seen:
                seen.add(token)
                entries.append(token)
    return entries, skipped


def _endpoint_label(host: str, port: Optional[int]) -> str:
    if port is None:
        return host
    return "%s:%d" % (host, port)


def build_ioc_outputs(
    storage_dir: Path,
    identity_file: Path,
    output_dir: Path,
    since_unix: Optional[int] = None,
    external_ioc_list: Optional[Path] = None,
    decryptor: Optional[Decryptor] = None,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
    max_zip_entries: int = DEFAULT_MAX_ZIP_ENTRIES,
) -> dict:
    """Aggregate observed relays from all receipts and write the IOC outputs.

    Returns a summary dict of counts. Raises ValueError for storage problems,
    unsafe output locations, or any output file that already exists; nothing
    is written unless every receipt has been processed and verified.
    """

    storage_dir = Path(storage_dir)
    output_dir = Path(output_dir)
    identity_file = Path(identity_file)

    resolved_output = output_dir.resolve()
    resolved_storage = storage_dir.resolve()
    if resolved_output == resolved_storage or resolved_storage in resolved_output.parents:
        raise ValueError("refusing to write IOC outputs inside the relay storage directory")
    if output_dir.exists() and not output_dir.is_dir():
        raise ValueError("output path is not a directory")
    existing_outputs = [name for name in OUTPUT_FILE_NAMES if (output_dir / name).exists()]
    if existing_outputs:
        raise ValueError("refusing to overwrite existing output file(s): " + ", ".join(existing_outputs))

    records = discover_records(storage_dir)
    selected = [record for record in records if since_unix is None or record[3]["received_unix"] >= since_unix]
    decrypt = decryptor or (lambda source, destination, identity: decrypt_with_age(source, destination, identity))

    relays: dict[tuple[str, Optional[int]], dict] = {}
    ignored_instances = 0
    usable_instances = 0
    receipts_with_relays = 0

    with tempfile.TemporaryDirectory(prefix="screenconnect-report-ioc-") as temp_dir:
        temp_root = Path(temp_dir)
        for receipt_id, encrypted, _metadata_path, metadata in selected:
            decrypted = temp_root / (receipt_id + ".zip")
            decrypt(encrypted, decrypted, identity_file)
            if not decrypted.is_file():
                raise ValueError("decryption produced no file for " + receipt_id)
            actual_hash = hashlib.sha256(decrypted.read_bytes()).hexdigest()
            if actual_hash != metadata["sha256"]:
                raise ValueError("hash mismatch for receipt " + receipt_id)
            validate_zip_file(decrypted, max_uncompressed_bytes, max_zip_entries)
            report = _read_report_json(decrypted, receipt_id)
            received_unix = int(metadata["received_unix"])
            saw_relay = False
            for instance in _report_instances(report):
                if not isinstance(instance, dict):
                    ignored_instances += 1
                    continue
                host, port = _parse_relay_fields(_ci_get(instance, "RelayHost"), _ci_get(instance, "RelayPort"))
                if host is None:
                    ignored_instances += 1
                    continue
                thumbprint = _normalize_thumbprint(_ci_get(instance, "Thumbprint"))
                if thumbprint is None:
                    thumbprint = _normalize_thumbprint(_ci_get(instance, "Identifier"))
                key = (host, port)
                entry = relays.get(key)
                if entry is None:
                    if len(relays) >= MAX_DISTINCT_RELAYS:
                        raise ValueError("too many distinct relay servers observed")
                    entry = {
                        "host": host,
                        "port": port,
                        "thumbprints": set(),
                        "receipt_ids": set(),
                        "first_seen_unix": received_unix,
                        "last_seen_unix": received_unix,
                    }
                    relays[key] = entry
                if thumbprint is not None:
                    if thumbprint not in entry["thumbprints"] and len(entry["thumbprints"]) >= MAX_DISTINCT_THUMBPRINTS:
                        raise ValueError("too many distinct thumbprints observed for one relay")
                    entry["thumbprints"].add(thumbprint)
                entry["receipt_ids"].add(receipt_id)
                entry["first_seen_unix"] = min(entry["first_seen_unix"], received_unix)
                entry["last_seen_unix"] = max(entry["last_seen_unix"], received_unix)
                saw_relay = True
                usable_instances += 1
            if saw_relay:
                receipts_with_relays += 1

    ordered = sorted(relays.values(), key=lambda entry: (entry["host"], entry["port"] if entry["port"] is not None else -1))
    generated_unix = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    external_entries: list[str] = []
    external_source = ""
    if external_ioc_list is not None:
        external_path = Path(external_ioc_list)
        if not external_path.is_file():
            raise ValueError("external IOC list was not found: " + str(external_path))
        external_entries, _external_skipped = _load_external_entries(external_path)
        external_source = external_path.name

    contents = _build_output_contents(
        ordered,
        generated_unix,
        len(selected),
        len(records),
        ignored_instances,
        usable_instances,
        receipts_with_relays,
        external_entries,
        external_source,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_output_files(output_dir, contents)
    return {
        "receipts_analyzed": len(selected),
        "receipts_total": len(records),
        "relays": len(ordered),
        "ignored_instances": ignored_instances,
        "generated_unix": generated_unix,
    }


def _summary_source_label(source: str) -> str:
    """Plain-text label for the external IOC source, always pure ASCII."""
    if source.isascii():
        return source
    return "(external list: filename is not ASCII)"


def _external_match_labels(relay: dict, external_entries: list[str]) -> bool:
    """True when this observed relay intersects the external IOC entries."""
    external = set(external_entries)
    host = relay["host"]
    if host in external:
        return True
    port = relay["port"]
    if port is not None and _endpoint_label(host, port) in external:
        return True
    return any(thumbprint in external for thumbprint in relay["thumbprints"])


def _build_output_contents(
    relays: list,
    generated_unix: int,
    receipts_analyzed: int,
    receipts_total: int,
    ignored_instances: int,
    usable_instances: int,
    receipts_with_relays: int,
    external_entries: list[str],
    external_source: str,
) -> dict:
    """Render the four output payloads as deterministic ASCII text."""
    generated_utc = _utc_stamp(generated_unix)

    address_lines = []
    csv_rows = []
    summary_lines = []
    observed_json = []

    summary_lines.append("ScreenConnect relay abuse summary (observed data only)")
    summary_lines.append("Generated (UTC): " + generated_utc)
    summary_lines.append("Receipts analyzed: %d (of %d stored)" % (receipts_analyzed, receipts_total))
    summary_lines.append("Receipts with usable relay data: %d" % receipts_with_relays)
    summary_lines.append("ScreenConnect instances with usable relay data: %d" % usable_instances)
    summary_lines.append("Instances ignored (no usable relay host): %d" % ignored_instances)
    summary_lines.append("Distinct relay endpoints observed (host:port): %d" % len(relays))
    if external_source:
        summary_lines.append(
            "External IOC list: %s (%d entries, kept separate)" % (_summary_source_label(external_source), len(external_entries))
        )
    summary_lines.append("")

    for relay in relays:
        host = relay["host"]
        port = relay["port"]
        label = _endpoint_label(host, port)
        address_lines.append(label)
        thumbprints = sorted(relay["thumbprints"])
        receipt_ids = sorted(relay["receipt_ids"])
        csv_rows.append(
            {
                "host": host,
                "port": "" if port is None else str(port),
                "thumbprints": ";".join(thumbprints),
                "first_seen_unix": relay["first_seen_unix"],
                "first_seen_utc": _utc_stamp(relay["first_seen_unix"]),
                "last_seen_unix": relay["last_seen_unix"],
                "last_seen_utc": _utc_stamp(relay["last_seen_unix"]),
                "report_count": len(receipt_ids),
                "receipt_ids": ";".join(receipt_ids),
            }
        )
        observed_json.append(
            {
                "host": host,
                "port": port,
                "thumbprints": thumbprints,
                "first_seen_unix": relay["first_seen_unix"],
                "first_seen_utc": _utc_stamp(relay["first_seen_unix"]),
                "last_seen_unix": relay["last_seen_unix"],
                "last_seen_utc": _utc_stamp(relay["last_seen_unix"]),
                "report_count": len(receipt_ids),
                "receipt_ids": receipt_ids,
            }
        )
        summary_lines.append(label)
        summary_lines.append("  thumbprints: " + (", ".join(thumbprints) if thumbprints else "(none)"))
        summary_lines.append(
            "  first seen (UTC): %s   last seen (UTC): %s" % (_utc_stamp(relay["first_seen_unix"]), _utc_stamp(relay["last_seen_unix"]))
        )
        summary_lines.append("  report count: %d   receipt ids: %s" % (len(receipt_ids), ", ".join(receipt_ids)))
        summary_lines.append("")

    addresses_bytes = ("\n".join(address_lines) + "\n") if address_lines else ""

    csv_buffer = io.StringIO()
    writer = csv.DictWriter(
        csv_buffer,
        fieldnames=[
            "host",
            "port",
            "thumbprints",
            "first_seen_unix",
            "first_seen_utc",
            "last_seen_unix",
            "last_seen_utc",
            "report_count",
            "receipt_ids",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for row in csv_rows:
        writer.writerow(row)
    csv_bytes = csv_buffer.getvalue()

    payload: dict = {
        "schema_version": 1,
        "generated_unix": generated_unix,
        "generated_utc": generated_utc,
        "receipts_analyzed": receipts_analyzed,
        "receipts_total": receipts_total,
        "ignored_instances": ignored_instances,
        "observed": observed_json,
    }
    if external_source:
        payload["external_ioc_list"] = {
            "source": external_source,
            "entries": external_entries,
            "observed_matches": [
                _endpoint_label(relay["host"], relay["port"]) for relay in relays if _external_match_labels(relay, external_entries)
            ],
        }
    json_bytes = json.dumps(payload, indent=2, sort_keys=True) + "\n"

    if external_source:
        matches = [
            _endpoint_label(relay["host"], relay["port"]) for relay in relays if _external_match_labels(relay, external_entries)
        ]
        summary_lines.append("External IOC list intersection (never merged into observed data above):")
        summary_lines.append("  Source: " + _summary_source_label(external_source))
        summary_lines.append("  External entries: %d   Observed relays also listed: %d" % (len(external_entries), len(matches)))
        if matches:
            summary_lines.append("  " + ", ".join(matches))
        summary_lines.append("")

    return {
        "relay-addresses.txt": addresses_bytes,
        "screenconnect-relays.csv": csv_bytes,
        "connectwise-abuse-summary.txt": "\n".join(summary_lines) + "\n",
        "screenconnect-relays.json": json_bytes,
    }


def _write_output_files(output_dir: Path, contents: dict) -> None:
    """Write every output atomically; refuse to overwrite any existing file."""
    existing = [name for name in OUTPUT_FILE_NAMES if (output_dir / name).exists()]
    if existing:
        raise ValueError("refusing to overwrite existing output file(s): " + ", ".join(existing))
    written: list[Path] = []
    try:
        for name, content in contents.items():
            if not isinstance(content, str) or not content.isascii():
                raise ValueError("internal output rendering produced non-ASCII content for " + name)
            final_path = output_dir / name
            descriptor, temporary_name = tempfile.mkstemp(prefix=name + ".", suffix=".tmp", dir=str(output_dir))
            temporary_path = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "w", encoding="ascii", newline="") as handle:
                    handle.write(content)
                os.chmod(temporary_path, 0o600)
                os.replace(temporary_path, final_path)
                written.append(final_path)
            except BaseException:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass
                raise
    except BaseException:
        for path in written:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--storage-dir", default="/var/lib/screenconnect-report-relay/inbox")
    parser.add_argument("--identity-file", default="/etc/screenconnect-report-relay/age-key.txt")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--since-unix", type=int)
    parser.add_argument("--external-ioc-list")
    args = parser.parse_args()
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        parser.error("IOC export must run as root")
    summary = build_ioc_outputs(
        Path(args.storage_dir),
        Path(args.identity_file),
        Path(args.output_dir),
        since_unix=args.since_unix,
        external_ioc_list=Path(args.external_ioc_list) if args.external_ioc_list else None,
    )
    print("wrote %d observed relay(s) from %d receipt(s) to %s" % (summary["relays"], summary["receipts_analyzed"], args.output_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
