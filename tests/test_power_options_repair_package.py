"""Exercise the deploy builder against a disposable scripts-only tree."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile


class PowerRepairPackageTests(unittest.TestCase):
    def test_deploy_includes_byte_identical_repair_dependencies(self):
        repo = Path(__file__).resolve().parents[1]
        scratch = Path(os.environ.get("TMPDIR", str(Path.home() / ".hermes/cache/scratch")))
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="scc-power-package-", dir=scratch) as tmp:
            source = Path(tmp) / "source"
            source.mkdir()
            # The builder copies root scripts/config and docs/tools only. Never copy
            # real scan artifacts, .git, GUI output, credentials or downloaded EXEs.
            for item in repo.iterdir():
                if item.is_file() and (item.suffix.lower() in {".ps1", ".psm1", ".bat", ".json", ".md"}
                                       or item.name in {"VERSION", "microbin-url.txt", "make-deploy-bundle.sh"}):
                    shutil.copyfile(item, source / item.name)
            (source / "tools").mkdir()
            for name in ("Get-ToolPack.ps1", "Get-AVTools.ps1", "Keep-Awake.ps1", "Confirm-OnBattery.ps1"):
                shutil.copyfile(repo / "tools" / name, source / "tools" / name)
            # The release builder requires genuine source provenance. Give the
            # isolated fixture its own commit rather than borrowing the real SHA.
            for command in (["git", "init", "-q"], ["git", "add", "."],
                            ["git", "-c", "user.name=Package fixture", "-c", "user.email=fixture@example.invalid",
                             "commit", "-qm", "fixture: isolated package inputs"]):
                subprocess.run(command, cwd=source, check=True, capture_output=True)
            result = subprocess.run(["bash", str(source / "make-deploy-bundle.sh")],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            archives = list(Path(tmp).glob("screenconnect-cleanup-v*.zip"))
            self.assertEqual(len(archives), 1)
            with zipfile.ZipFile(archives[0]) as archive:
                self.assertIsNone(archive.testzip())
                for name in ("Repair-PowerOptions.ps1", "PowerOptionsRepair.Core.psm1",
                             "PowerOptionsRepair.Windows.psm1"):
                    member = "screenconnect-cleanup/" + name
                    self.assertIn(member, archive.namelist(), f"Required repair dependency not packaged: {name}")
                    self.assertEqual(hashlib.sha256(archive.read(member)).digest(),
                                     hashlib.sha256((repo / name).read_bytes()).digest())
                self.assertFalse(any(name.lower().endswith((".exe", ".dll")) for name in archive.namelist()))


if __name__ == "__main__":
    unittest.main()
