"""Exercise the real builder in an isolated Git fixture; no release is modified."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile

REPO = Path(__file__).resolve().parent.parent


class BundleProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="scc-build-provenance-")
        self.base = Path(self.tmp.name)
        self.repo = self.base / "source"
        self.repo.mkdir()
        paths = subprocess.check_output(["git", "-C", str(REPO), "ls-files", "-z"]).split(b"\0")
        for raw in paths:
            if raw:
                relative = os.fsdecode(raw)
                source = REPO / relative
                target = self.repo / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("add", ".")
        self.git("commit", "-qm", "immutable fixture")
        self.sha = self.git("rev-parse", "HEAD").strip()
        self.version = (self.repo / "VERSION").read_text().strip()
        self.output = self.base / f"screenconnect-cleanup-v{self.version}.zip"

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], text=True)

    def build(self):
        return subprocess.run(["bash", str(self.repo / "make-deploy-bundle.sh")], cwd=self.repo,
                              capture_output=True, text=True, timeout=60)

    def test_dirty_tree_is_refused_without_replacing_existing_artifact(self):
        self.output.write_bytes(b"KEEP_EXISTING_ARTIFACT")
        with (self.repo / "preflight.ps1").open("a") as stream:
            stream.write("\n# uncommitted fixture change\n")
        result = self.build()
        self.assertNotEqual(result.returncode, 0, "builder stamped HEAD over dirty payload")
        self.assertIn("clean", (result.stdout + result.stderr).lower())
        self.assertEqual(self.output.read_bytes(), b"KEEP_EXISTING_ARTIFACT")

    def test_untracked_document_is_refused(self):
        (self.repo / "docs" / "uncommitted-fixture.md").write_text("not in HEAD")
        self.assertNotEqual(self.build().returncode, 0, "untracked docs entered a HEAD-stamped archive")
        self.assertFalse(self.output.exists())

    def test_ignored_document_never_enters_clean_ref_archive(self):
        ignored = self.repo / "docs" / "ignored-fixture.log"
        ignored.write_text("IGNORED_PAYLOAD_SENTINEL")
        self.assertEqual(self.git("status", "--porcelain"), "")
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(self.output) as archive:
            self.assertNotIn("screenconnect-cleanup/docs/ignored-fixture.log", archive.namelist())

    def test_clean_bundle_records_exact_ref_and_member_bytes(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(self.output) as archive:
            prefix = "screenconnect-cleanup/"
            self.assertIn("Source commit: " + self.sha, archive.read(prefix + "BUILD-INFO.txt").decode())
            for name in archive.namelist():
                relative = name[len(prefix):]
                if relative not in {"BUILD-INFO.txt", "SHA256SUMS.txt"}:
                    expected = subprocess.check_output(["git", "-C", str(self.repo), "show", self.sha + ":" + relative])
                    self.assertEqual(hashlib.sha256(archive.read(name)).digest(), hashlib.sha256(expected).digest(), relative)


if __name__ == "__main__":
    unittest.main(verbosity=2)
