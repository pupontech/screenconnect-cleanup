import hashlib
import http.client
import io
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from relay.app import RelayConfig, cleanup_expired, make_server, sha256_token
from relay.export_reports import build_bulk_archive


class ReportRelayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="screenconnect-relay-test-")
        self.storage = Path(self.temp.name) / "inbox"

        def fake_encrypt(source, destination, recipient):
            destination.write_bytes(Path(source).read_bytes())

        self.config = RelayConfig(
            storage_dir=self.storage,
            token_digest=sha256_token("test-upload-token"),
            age_recipient="age1testrecipient",
            encryptor=fake_encrypt,
            max_upload_bytes=1024 * 1024,
            max_uncompressed_bytes=4 * 1024 * 1024,
        )
        self.server = make_server("127.0.0.1", 0, self.config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = "http://127.0.0.1:%d" % self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    @staticmethod
    def zip_bytes(name="connectwise-report.json", content=b"{}"):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(name, content)
        return stream.getvalue()

    @staticmethod
    def zip_bytes_with_entries(prefix, count):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            for index in range(count):
                archive.writestr("%s-%02d.json" % (prefix, index), b"{}")
        return stream.getvalue()

    def request(self, path, body=None, token="test-upload-token", content_type="application/zip", report_hash=None):
        headers = {"Content-Type": content_type}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if body is not None:
            headers["X-Report-Filename"] = "triage.zip"
        if report_hash is not None:
            headers["X-Report-SHA256"] = report_hash
        request = urllib.request.Request(self.base_url + path, data=body, headers=headers, method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read()

    def test_health_head_returns_200_without_a_body(self):
        request = urllib.request.Request(self.base_url + "/healthz", method="HEAD")
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b"")

        status, headers, body = self.request("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["ok"], True)
        self.assertEqual(headers["Cache-Control"], "no-store")

        status, _, _ = self.request("/v1/uploads", body=self.zip_bytes(), token=None)
        self.assertEqual(status, 401)
        self.assertEqual(list(self.storage.glob("*")), [])

    def test_authenticated_zip_is_stored_with_receipt_and_digest(self):
        body = self.zip_bytes(content=b'{"instance":"abc123"}')
        status, _, response_body = self.request("/v1/uploads", body=body)
        self.assertEqual(status, 201)
        response = json.loads(response_body)
        self.assertRegex(response["receipt_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(response["sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(response["bytes"], len(body))
        self.assertTrue((self.storage / (response["receipt_id"] + ".age")).is_file())
        self.assertTrue((self.storage / (response["receipt_id"] + ".json")).is_file())

        status, _, _ = self.request("/v1/uploads/" + response["receipt_id"])
        self.assertEqual(status, 404)

    def test_cleanup_expired_removes_only_relay_receipt_files(self):
        old_age = self.storage / ("a" * 32 + ".age")
        old_meta = self.storage / ("a" * 32 + ".json")
        unrelated = self.storage / "keep.txt"
        old_age.write_bytes(b"old")
        old_meta.write_text("{}", encoding="utf-8")
        unrelated.write_text("keep", encoding="utf-8")
        for path in (old_age, old_meta):
            os.utime(path, (89, 89))
        self.config.retention_seconds = 10
        removed = cleanup_expired(self.config, now=100)
        self.assertEqual(removed, 2)
        self.assertFalse(old_age.exists())
        self.assertFalse(old_meta.exists())
        self.assertTrue(unrelated.exists())

    def test_invalid_token_and_non_zip_are_rejected(self):
        status, _, _ = self.request("/v1/uploads", body=self.zip_bytes(), token="wrong")
        self.assertEqual(status, 401)
        status, _, _ = self.request("/v1/uploads", body=b"not a zip")
        self.assertEqual(status, 400)
        self.assertEqual(list(self.storage.glob("*")), [])

    def test_archive_paths_are_validated_without_extracting(self):
        status, _, _ = self.request("/v1/uploads", body=self.zip_bytes(name="../outside.txt"))
        self.assertEqual(status, 400)
        self.assertEqual(list(self.storage.glob("*")), [])

    def test_upload_size_is_bounded_before_storage(self):
        self.config.max_upload_bytes = 32
        status, _, _ = self.request("/v1/uploads", body=self.zip_bytes(content=b"x" * 128))
        self.assertEqual(status, 413)
        self.assertEqual(list(self.storage.glob("*")), [])
    def test_same_authenticated_digest_is_idempotent(self):
        body = self.zip_bytes(content=b"retry-safe")
        digest = hashlib.sha256(body).hexdigest()
        first_status, _, first_body = self.request("/v1/uploads", body=body, report_hash=digest)
        second_status, _, second_body = self.request("/v1/uploads", body=body, report_hash=digest)
        self.assertEqual(first_status, 201)
        self.assertEqual(second_status, 200)
        first = json.loads(first_body)
        second = json.loads(second_body)
        self.assertEqual(first["receipt_id"], second["receipt_id"])
        self.assertEqual(second["status"], "already_stored")
        self.assertEqual(len(list(self.storage.glob("*.age"))), 1)

        mismatch_status, _, _ = self.request("/v1/uploads", body=body, report_hash="0" * 64)
        self.assertEqual(mismatch_status, 400)

    def test_dedupe_is_based_on_received_body_not_the_hash_claim(self):
        first_body = self.zip_bytes(content=b"first-upload")
        other_body = self.zip_bytes(content=b"different-body")
        digest = hashlib.sha256(first_body).hexdigest()

        status, _, _ = self.request("/v1/uploads", body=first_body, report_hash=digest)
        self.assertEqual(status, 201)

        # Claiming an existing digest while actually sending different bytes
        # must not be acknowledged as already_stored: the claim has to match the
        # body that was really received.
        status, _, response_body = self.request("/v1/uploads", body=other_body, report_hash=digest)
        self.assertEqual(status, 400)
        self.assertIn("does not match", json.loads(response_body)["error"])
        self.assertEqual(len(list(self.storage.glob("*.age"))), 1)

        # A literal byte-for-byte re-upload without the header is still
        # deduplicated, keyed on the received body alone.
        status, _, response_body = self.request("/v1/uploads", body=first_body)
        self.assertEqual(status, 200)
        duplicate = json.loads(response_body)
        self.assertEqual(duplicate["status"], "already_stored")
        self.assertEqual(duplicate["sha256"], digest)
        self.assertEqual(len(list(self.storage.glob("*.age"))), 1)

        # And with a matching header the duplicate is still idempotent.
        status, _, response_body = self.request("/v1/uploads", body=first_body, report_hash=digest)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(response_body)["receipt_id"], duplicate["receipt_id"])
        self.assertEqual(len(list(self.storage.glob("*.age"))), 1)

    def test_zip_entry_count_is_bounded(self):
        self.config.max_zip_entries = 3
        status, _, _ = self.request("/v1/uploads", body=self.zip_bytes_with_entries("entry", 4))
        self.assertEqual(status, 400)
        self.assertEqual(list(self.storage.glob("*")), [])

        status, _, response_body = self.request("/v1/uploads", body=self.zip_bytes_with_entries("entry", 2))
        self.assertEqual(status, 201)
        self.assertEqual(len(list(self.storage.glob("*.age"))), 1)

    def test_bulk_export_decrypts_each_report_and_writes_manifest(self):
        first_body = self.zip_bytes(content=b"first")
        second_body = self.zip_bytes(content=b"second")
        first_id = "a" * 32
        second_id = "b" * 32
        (self.storage / (first_id + ".age")).write_bytes(first_body)
        (self.storage / (second_id + ".age")).write_bytes(second_body)
        (self.storage / (first_id + ".json")).write_text(
            json.dumps({"receipt_id": first_id, "sha256": hashlib.sha256(first_body).hexdigest(), "received_unix": 100}),
            encoding="utf-8",
        )
        (self.storage / (second_id + ".json")).write_text(
            json.dumps({"receipt_id": second_id, "sha256": hashlib.sha256(second_body).hexdigest(), "received_unix": 200}),
            encoding="utf-8",
        )
        output = Path(self.temp.name) / "bulk.zip"

        def fake_decrypt(source, destination, identity):
            Path(destination).write_bytes(Path(source).read_bytes())

        count = build_bulk_archive(self.storage, Path("/unused/identity"), output, decryptor=fake_decrypt)
        self.assertEqual(count, 2)
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(sorted(archive.namelist()), ["manifest.json", "reports/" + first_id + ".zip", "reports/" + second_id + ".zip"])
            manifest = json.loads(archive.read("manifest.json"))
        self.assertEqual([item["receipt_id"] for item in manifest["reports"]], [first_id, second_id])

    def test_bulk_export_refuses_orphaned_encrypted_report(self):
        orphan_id = "c" * 32
        (self.storage / (orphan_id + ".age")).write_bytes(self.zip_bytes())
        output = Path(self.temp.name) / "bulk.zip"
        with self.assertRaises(ValueError):
            build_bulk_archive(self.storage, Path("/unused/identity"), output, decryptor=lambda source, destination, identity: None)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
