"""Verify an immutable deploy ZIP; never execute packaged production code."""
import argparse
import hashlib
import re
import stat
import zipfile
from pathlib import PurePosixPath


def verify(path, version, commit):
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None, "ZIP integrity failed"
        names = archive.namelist()
        assert len(names) == len(set(names)), "duplicate ZIP entries"
        assert len(names) == len({name.casefold() for name in names}), "case-colliding entries"
        prefix = "screenconnect-cleanup/"
        members = {}
        for item in archive.infolist():
            name = item.filename
            relative = PurePosixPath(name)
            assert not relative.is_absolute() and ".." not in relative.parts, name
            assert "\\" not in name and ":" not in name, name
            assert name.startswith(prefix), name
            assert not stat.S_ISLNK(item.external_attr >> 16), name
            assert not item.is_dir(), "unexpected directory-only entry"
            short = name[len(prefix):]
            assert not any(part in (".git", ".hermes", "node_modules", "bin", "obj", "samples", "quarantine") for part in relative.parts), name
            assert not short.lower().endswith((".exe", ".dll", ".pdb", ".zip")), name
            members[short] = archive.read(name)
        required = {
            "VERSION", "BUILD-INFO.txt", "SHA256SUMS.txt", "START-HERE.bat",
            "sc-cleanup.ps1", "Invoke-PersistenceScan.ps1", "Invoke-PersistenceInventoryWorker.ps1",
            "Show-PersistenceReview.ps1",
            "Persistence.Inventory.psm1", "Persistence.Removal.psm1",
            "New-InvestigationReport.ps1", "Submit-ConnectWiseReport.ps1",
            "tools/Keep-Awake.ps1", "tools/Confirm-OnBattery.ps1",
            "README.md", "DEPLOY.md", "CHANGELOG.md", "docs/12-post-av-persistence.md",
        }
        assert required <= members.keys(), sorted(required - members.keys())
        assert members["VERSION"].decode("ascii").strip() == version
        assert re.fullmatch(r"[0-9a-f]{40}", commit), "full source SHA required"
        info = members["BUILD-INFO.txt"].decode("ascii")
        assert info.count("Source commit: " + commit) == 1 and "Source commit:" in info
        expected = {}
        for line in members["SHA256SUMS.txt"].decode("ascii").splitlines():
            digest, name = line.split("  ", 1)
            assert re.fullmatch(r"[0-9a-f]{64}", digest) and name not in expected, line
            expected[name] = digest
        actual = {name: hashlib.sha256(data).hexdigest() for name, data in members.items() if name != "SHA256SUMS.txt"}
        assert expected == actual, "manifest must cover all members exactly with matching bytes"
        for name, data in members.items():
            if name.endswith((".ps1", ".psm1", ".psd1", ".bat")):
                assert not data.startswith(b"\xef\xbb\xbf") and all(byte < 128 for byte in data), name
        batch = members["START-HERE.bat"]
        assert b"\n" not in batch.replace(b"\r\n", b""), "batch must have CRLF only"
        assert b"STEP 6d/9" in batch and b"Invoke-PersistenceScan.ps1" in batch
        assert b"-PersistenceInventory" in batch and b"-PersistenceResult" in batch
        assert b"Get-SccPersistenceInventory" in members["Persistence.Inventory.psm1"]
        assert b"Invoke-SccPersistenceReview" in members["Persistence.Removal.psm1"]
        assert b"Persistence" in members["Submit-ConnectWiseReport.ps1"]
        print(f"PASS deploy ZIP: {len(members)} members, exact manifest, version {version}, source {commit}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("zip")
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    verify(args.zip, args.version, args.commit)
