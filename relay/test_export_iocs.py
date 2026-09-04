import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from relay.export_iocs import build_ioc_outputs, _endpoint_label


def make_report_zip(report, extra_entries=None):
    """Return report ZIP bytes with connectwise-report.json plus extras."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("connectwise-report.json", json.dumps(report))
        for name, content in (extra_entries or {}).items():
            archive.writestr(name, content)
    return stream.getvalue()


def nested_report(instances):
    return {"SchemaVersion": 1, "ScreenConnect": {"Instances": instances, "ParseIssues": [], "Historical": []}}


def write_receipt(storage, receipt_id, zip_bytes, received_unix):
    (storage / (receipt_id + ".age")).write_bytes(zip_bytes)
    (storage / (receipt_id + ".json")).write_text(
        json.dumps(
            {
                "receipt_id": receipt_id,
                "sha256": hashlib.sha256(zip_bytes).hexdigest(),
                "received_unix": received_unix,
                "bytes": len(zip_bytes),
            }
        ),
        encoding="utf-8",
    )


class ExportIocsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="screenconnect-ioc-test-")
        self.storage = Path(self.temp.name) / "inbox"
        self.storage.mkdir()
        self.outputs = Path(self.temp.name) / "outputs"

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def fake_decrypt(source, destination, identity):
        Path(destination).write_bytes(Path(source).read_bytes())

    def run_export(self, output_dir=None):
        output_dir = Path(output_dir) if output_dir is not None else self.outputs
        return build_ioc_outputs(
            self.storage,
            Path("/unused/identity"),
            output_dir,
            decryptor=self.fake_decrypt,
        )

    def read_outputs(self, output_dir=None):
        output_dir = Path(output_dir) if output_dir is not None else self.outputs
        return {
            name: (output_dir / name).read_text(encoding="utf-8")
            for name in (
                "relay-addresses.txt",
                "screenconnect-relays.csv",
                "connectwise-abuse-summary.txt",
                "screenconnect-relays.json",
            )
        }

    def test_single_receipt_produces_four_ascii_outputs(self):
        instance = {
            "Identifier": "AABBCCDD0011",
            "RelayHost": "relay.evil.example",
            "RelayPort": "8041",
        }
        write_receipt(self.storage, "a" * 32, make_report_zip(nested_report([instance])), 1000)

        summary = self.run_export()
        self.assertEqual(summary["relays"], 1)
        self.assertEqual(summary["receipts_analyzed"], 1)

        outputs = self.read_outputs()
        self.assertTrue(all(text.isascii() for text in outputs.values()))
        self.assertEqual(outputs["relay-addresses.txt"], "relay.evil.example:8041\n")
        self.assertIn("relay.evil.example", outputs["screenconnect-relays.csv"])
        self.assertIn("report count: 1", outputs["connectwise-abuse-summary.txt"])
        payload = json.loads(outputs["screenconnect-relays.json"])
        self.assertEqual(payload["observed"][0]["host"], "relay.evil.example")
        self.assertEqual(payload["observed"][0]["port"], 8041)
        self.assertEqual(payload["observed"][0]["thumbprints"], ["aabbccdd0011"])
        self.assertEqual(payload["observed"][0]["report_count"], 1)
        self.assertEqual(payload["observed"][0]["receipt_ids"], ["a" * 32])
        self.assertEqual(payload["observed"][0]["first_seen_unix"], 1000)
        self.assertEqual(payload["observed"][0]["last_seen_unix"], 1000)

    def test_same_relay_across_receipts_is_deduplicated_with_thumbprint_associations(self):
        first = {
            "Identifier": "thumb-a",
            "RelayHost": "relay.evil.example",
            "RelayPort": 8041,
        }
        second_instance_same_relay = {
            "Identifier": "thumb-b",
            "RelayHost": "relay.evil.example",
            "RelayPort": 8041,
        }
        other = {
            "Identifier": "thumb-c",
            "RelayHost": "other.evil.example",
            "RelayPort": "443",
        }
        write_receipt(self.storage, "a" * 32, make_report_zip(nested_report([first])), 1000)
        write_receipt(self.storage, "b" * 32, make_report_zip(nested_report([second_instance_same_relay, other])), 2000)
        write_receipt(self.storage, "c" * 32, make_report_zip(nested_report([first])), 3000)

        summary = self.run_export()
        self.assertEqual(summary["relays"], 2)
        payload = json.loads(self.read_outputs()["screenconnect-relays.json"])
        by_host = {entry["host"]: entry for entry in payload["observed"]}
        self.assertEqual(set(by_host), {"relay.evil.example", "other.evil.example"})

        relay = by_host["relay.evil.example"]
        self.assertEqual(relay["thumbprints"], ["thumb-a", "thumb-b"])
        self.assertEqual(relay["report_count"], 3)
        self.assertEqual(relay["receipt_ids"], ["a" * 32, "b" * 32, "c" * 32])
        self.assertEqual(relay["first_seen_unix"], 1000)
        self.assertEqual(relay["last_seen_unix"], 3000)
        self.assertEqual(relay["first_seen_utc"], "1970-01-01T00:16:40Z")
        self.assertEqual(relay["last_seen_utc"], "1970-01-01T00:50:00Z")

        other_relay = by_host["other.evil.example"]
        self.assertEqual(other_relay["port"], 443)
        self.assertEqual(other_relay["report_count"], 1)

        addresses = self.read_outputs()["relay-addresses.txt"].splitlines()
        self.assertEqual(addresses, ["other.evil.example:443", "relay.evil.example:8041"])

    def test_embedded_port_host_and_flat_report_shape_are_accepted(self):
        flat_report = {
            "Instances": [
                {"Identifier": "tp-1", "RelayHost": "relay.evil.example:8041"},
                {"Identifier": "tp-2", "RelayHost": "bare.evil.example", "RelayPort": "443"},
            ]
        }
        write_receipt(self.storage, "a" * 32, make_report_zip(flat_report), 500)
        summary = self.run_export()
        self.assertEqual(summary["relays"], 2)
        payload = json.loads(self.read_outputs()["screenconnect-relays.json"])
        by_host = {entry["host"]: entry for entry in payload["observed"]}
        self.assertEqual(by_host["relay.evil.example"]["port"], 8041)
        self.assertEqual(by_host["bare.evil.example"]["port"], 443)

    def test_instances_without_relay_host_are_ignored_and_counted(self):
        good = {"Identifier": "tp-ok", "RelayHost": "relay.evil.example", "RelayPort": 8041}
        no_host = {"Identifier": "tp-orphan", "RelayPort": 8041}
        bad_host = {"Identifier": "tp-bad", "RelayHost": "https://relay.evil.example/path", "RelayPort": 8041}
        not_dict = "garbage"
        write_receipt(self.storage, "a" * 32, make_report_zip(nested_report([good, no_host, bad_host, not_dict])), 1000)

        summary = self.run_export()
        self.assertEqual(summary["relays"], 1)
        self.assertEqual(summary["ignored_instances"], 3)
        outputs = self.read_outputs()
        self.assertIn("Instances ignored (no usable relay host): 3", outputs["connectwise-abuse-summary.txt"])
        payload = json.loads(outputs["screenconnect-relays.json"])
        self.assertEqual(payload["ignored_instances"], 3)
        self.assertEqual([entry["thumbprints"] for entry in payload["observed"]], [["tp-ok"]])

    def test_only_connectwise_report_json_is_read(self):
        report = nested_report([{"Identifier": "tp-x", "RelayHost": "relay.evil.example", "RelayPort": 8041}])
        binary_evidence = bytes(range(256)) * 100
        write_receipt(
            self.storage,
            "a" * 32,
            make_report_zip(
                report,
                {
                    "raw-evidence.bin": binary_evidence,
                    "connectwise-report.txt": "human readable secret",
                    "package-manifest.json": json.dumps({"RawEvidenceIncluded": True}),
                    "nested/raw-config.json": json.dumps({"secret": "value"}),
                },
            ),
            1000,
        )
        self.run_export()
        outputs = self.read_outputs()
        for content in outputs.values():
            self.assertNotIn(binary_evidence.decode("latin-1"), content)
            self.assertNotIn("human readable secret", content)
            self.assertNotIn("RawEvidenceIncluded", content)
        self.assertIn("relay.evil.example", outputs["screenconnect-relays.csv"])

    def test_missing_connectwise_report_entry_fails_loudly(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("package-manifest.json", "{}")
        write_receipt(self.storage, "a" * 32, stream.getvalue(), 1000)
        with self.assertRaises(ValueError) as ctx:
            self.run_export()
        self.assertIn("no connectwise-report.json", str(ctx.exception))
        self.assertFalse(self.outputs.exists())

    def test_refuses_output_inside_storage_directory(self):
        write_receipt(self.storage, "a" * 32, make_report_zip(nested_report([])), 1000)
        inside = self.storage / "sub"
        with self.assertRaises(ValueError) as ctx:
            build_ioc_outputs(self.storage, Path("/unused/identity"), inside, decryptor=self.fake_decrypt)
        self.assertIn("inside the relay storage directory", str(ctx.exception))

    def test_refuses_existing_output_file(self):
        write_receipt(self.storage, "a" * 32, make_report_zip(nested_report([])), 1000)
        self.outputs.mkdir()
        (self.outputs / "screenconnect-relays.csv").write_text("stale", encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            self.run_export()
        self.assertIn("refusing to overwrite", str(ctx.exception))

    def test_no_receipts_still_writes_valid_empty_outputs(self):
        summary = self.run_export()
        self.assertEqual(summary["relays"], 0)
        outputs = self.read_outputs()
        self.assertEqual(outputs["relay-addresses.txt"], "")
        payload = json.loads(outputs["screenconnect-relays.json"])
        self.assertEqual(payload["observed"], [])
        self.assertIn("Distinct relay endpoints observed (host:port): 0", outputs["connectwise-abuse-summary.txt"])

    def test_since_unix_filters_older_receipts(self):
        write_receipt(self.storage, "a" * 32, make_report_zip(nested_report([{"Identifier": "x", "RelayHost": "old.example", "RelayPort": 1}])), 100)
        write_receipt(self.storage, "b" * 32, make_report_zip(nested_report([{"Identifier": "y", "RelayHost": "new.example", "RelayPort": 2}])), 200)
        summary = build_ioc_outputs(
            self.storage,
            Path("/unused/identity"),
            self.outputs,
            since_unix=150,
            decryptor=self.fake_decrypt,
        )
        self.assertEqual(summary["receipts_analyzed"], 1)
        payload = json.loads(self.read_outputs()["screenconnect-relays.json"])
        self.assertEqual([entry["host"] for entry in payload["observed"]], ["new.example"])

    def test_external_ioc_list_is_kept_separate_from_observed_data(self):
        write_receipt(self.storage, "a" * 32, make_report_zip(nested_report([{"Identifier": "tp-1", "RelayHost": "relay.evil.example", "RelayPort": 8041}])), 1000)
        external = Path(self.temp.name) / "external-iocs.txt"
        external.write_text(
            "# known abuse relays\nrelay.evil.example:8041\nnot-observed.evil.example\ntp-999\n", encoding="utf-8"
        )
        summary = build_ioc_outputs(
            self.storage,
            Path("/unused/identity"),
            self.outputs,
            external_ioc_list=external,
            decryptor=self.fake_decrypt,
        )
        self.assertEqual(summary["relays"], 1)
        outputs = self.read_outputs()
        # The observed-only outputs must never list the external-only relay.
        self.assertEqual(outputs["relay-addresses.txt"], "relay.evil.example:8041\n")
        self.assertNotIn("not-observed.evil.example", outputs["relay-addresses.txt"])
        self.assertNotIn("not-observed.evil.example", outputs["screenconnect-relays.csv"])

        payload = json.loads(outputs["screenconnect-relays.json"])
        self.assertEqual(len(payload["observed"]), 1)
        external_section = payload["external_ioc_list"]
        self.assertEqual(
            external_section["entries"],
            ["relay.evil.example:8041", "not-observed.evil.example", "tp-999"],
        )
        self.assertEqual(external_section["observed_matches"], ["relay.evil.example:8041"])
        self.assertIn("kept separate", outputs["connectwise-abuse-summary.txt"])

    def test_outputs_are_deterministic(self):
        write_receipt(self.storage, "a" * 32, make_report_zip(nested_report([{"Identifier": "tp-1", "RelayHost": "z.example", "RelayPort": 9}])), 3000)
        write_receipt(self.storage, "b" * 32, make_report_zip(nested_report([{"Identifier": "tp-2", "RelayHost": "a.example", "RelayPort": 1}])), 1000)
        first_dir = Path(self.temp.name) / "first"
        second_dir = Path(self.temp.name) / "second"
        self.run_export(first_dir)
        self.run_export(second_dir)
        first = {name: (first_dir / name).read_text(encoding="utf-8") for name in (
            "relay-addresses.txt", "screenconnect-relays.csv", "connectwise-abuse-summary.txt", "screenconnect-relays.json"
        )}
        second = {name: (second_dir / name).read_text(encoding="utf-8") for name in (
            "relay-addresses.txt", "screenconnect-relays.csv", "connectwise-abuse-summary.txt", "screenconnect-relays.json"
        )}
        # Generation timestamps legitimately differ when the two runs straddle a
        # clock second; every other byte must be identical.
        for name in ("relay-addresses.txt", "screenconnect-relays.csv"):
            self.assertEqual(first[name], second[name])
        self.assertEqual(
            [line for line in first["connectwise-abuse-summary.txt"].splitlines() if not line.startswith("Generated (UTC): ")],
            [line for line in second["connectwise-abuse-summary.txt"].splitlines() if not line.startswith("Generated (UTC): ")],
        )
        first_payload = json.loads(first["screenconnect-relays.json"])
        second_payload = json.loads(second["screenconnect-relays.json"])
        self.assertEqual(first_payload["observed"], second_payload["observed"])
        self.assertEqual(first_payload["receipts_analyzed"], second_payload["receipts_analyzed"])
        self.assertEqual([entry["host"] for entry in first_payload["observed"]], ["a.example", "z.example"])

    def test_capitalized_host_and_mixed_port_types_are_normalized(self):
        write_receipt(
            self.storage,
            "a" * 32,
            make_report_zip(nested_report([{"Identifier": "TP-1", "RelayHost": "Relay.Evil.Example", "RelayPort": "8041"}])),
            1000,
        )
        write_receipt(
            self.storage,
            "b" * 32,
            make_report_zip(nested_report([{"Identifier": "tp-1", "RelayHost": "relay.evil.example", "RelayPort": 8041}])),
            2000,
        )
        summary = self.run_export()
        self.assertEqual(summary["relays"], 1)
        payload = json.loads(self.read_outputs()["screenconnect-relays.json"])
        entry = payload["observed"][0]
        self.assertEqual(entry["host"], "relay.evil.example")
        self.assertEqual(entry["thumbprints"], ["tp-1"])
        self.assertEqual(entry["report_count"], 2)
        self.assertEqual(entry["receipt_ids"], ["a" * 32, "b" * 32])


if __name__ == "__main__":
    unittest.main()
