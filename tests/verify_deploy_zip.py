"""Verify an immutable deploy ZIP; never execute packaged production code.

Layout: screenconnect-cleanup/START-HERE-GUI.bat is the ONLY file at the top (a small
launcher, source packaging/START-HERE-GUI.bat); everything else - scripts, the other
launchers, gui/, tools/, docs, VERSION and the manifests - is under
screenconnect-cleanup/files/, in the same relative layout as the repository.
"""
import argparse
import hashlib
import json
import re
import stat
import subprocess
import zipfile
from pathlib import Path, PurePosixPath

PREFIX = "screenconnect-cleanup/"
FILES = "files/"
ROOT_LAUNCHER = "START-HERE-GUI.bat"
ROOT_LAUNCHER_SOURCE = "packaging/START-HERE-GUI.bat"


def verify(path, version, commit):
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None, "ZIP integrity failed"
        names = archive.namelist()
        assert len(names) == len(set(names)), "duplicate ZIP entries"
        assert len(names) == len({name.casefold() for name in names}), "case-colliding entries"
        package = {}
        for item in archive.infolist():
            name = item.filename
            relative = PurePosixPath(name)
            assert not relative.is_absolute() and ".." not in relative.parts, name
            assert "\\" not in name and ":" not in name, name
            assert name.startswith(PREFIX), name
            assert not stat.S_ISLNK(item.external_attr >> 16), name
            assert not item.is_dir(), "unexpected directory-only entry"
            short = name[len(PREFIX):]
            assert not any(part in (".git", ".hermes", "node_modules", "bin", "obj", "samples", "quarantine") for part in relative.parts), name
            assert not short.lower().endswith((".exe", ".dll", ".pdb", ".zip")), name
            package[short] = archive.read(name)

        # Only the GUI launcher sits at the top; everything else is inside files/.
        top = sorted(n for n in package if "/" not in n)
        assert top == [ROOT_LAUNCHER], "only START-HERE-GUI.bat may sit at the top of the package: " + repr(top)
        stray = sorted(n for n in package if n != ROOT_LAUNCHER and not n.startswith(FILES))
        assert not stray, "everything but the GUI launcher must be under files/: " + repr(stray)
        root_launcher = package[ROOT_LAUNCHER]
        members = {n[len(FILES):]: data for n, data in package.items() if n.startswith(FILES)}

        required = {
            "VERSION", "BUILD-INFO.txt", "SHA256SUMS.txt", "START-HERE.bat",
            "sc-cleanup.ps1", "Invoke-PersistenceScan.ps1", "Invoke-PersistenceInventoryWorker.ps1",
            "Show-PersistenceReview.ps1",
            "Persistence.Inventory.psm1", "Persistence.Removal.psm1",
            "SystemRestore.psm1",
            "Repair-PowerOptions.ps1", "PowerOptionsRepair.Core.psm1", "PowerOptionsRepair.Windows.psm1",
            "New-InvestigationReport.ps1", "Submit-ConnectWiseReport.ps1",
            "tools/Keep-Awake.ps1", "tools/Confirm-OnBattery.ps1",
            "START-HERE-OFFLINE.bat", "START-HERE-ONLINE.bat", "OFFLINE-ONLINE-SPLIT.md",
            "tools/Find-OfflineRun.ps1", "tools/Write-PhaseMarker.ps1", "tools/RunRootSecurity.psm1",
            "START-HERE-GUI.bat", "gui/Gui.Core.psm1", "gui/Start-CleanupGui.ps1", "gui/MainWindow.xaml", "gui/steps.json",
            "README.md", "DEPLOY.md", "CHANGELOG.md", "docs/12-post-av-persistence.md",
        }
        assert required <= members.keys(), sorted(required - members.keys())
        assert members["VERSION"].decode("ascii").strip() == version
        assert re.fullmatch(r"[0-9a-f]{40}", commit), "full source SHA required"
        info = members["BUILD-INFO.txt"].decode("ascii")
        assert info.count("Source commit: " + commit) == 1 and "Source commit:" in info

        # The manifest (files/SHA256SUMS.txt) lists every other file by its path in the package.
        expected = {}
        for line in members["SHA256SUMS.txt"].decode("ascii").splitlines():
            digest, name = line.split("  ", 1)
            assert re.fullmatch(r"[0-9a-f]{64}", digest) and name not in expected, line
            expected[name] = digest
        actual = {name: hashlib.sha256(data).hexdigest() for name, data in package.items() if name != FILES + "SHA256SUMS.txt"}
        assert expected == actual, "manifest must cover all members exactly with matching bytes"

        # A checkout can rewrite line endings even when its own hashes agree.
        # Compare raw payload bytes with the exact source commit, not normalized text.
        source_root = Path(__file__).resolve().parents[1]
        def source_bytes(repo_path):
            return subprocess.check_output(["git", "show", commit + ":" + repo_path], cwd=source_root)
        for name, data in members.items():
            if name in ("BUILD-INFO.txt", "SHA256SUMS.txt"):
                continue
            assert data == source_bytes(name), "source byte mismatch: files/" + name
        assert root_launcher == source_bytes(ROOT_LAUNCHER_SOURCE), "source byte mismatch: " + ROOT_LAUNCHER

        for name, data in list(members.items()) + [(ROOT_LAUNCHER, root_launcher)]:
            if name.endswith((".ps1", ".psm1", ".psd1", ".bat", ".xaml")) or name == "gui/steps.json":
                assert not data.startswith(b"\xef\xbb\xbf") and all(byte < 128 for byte in data), name

        # The top launcher only hands over to files\START-HERE-GUI.bat (which elevates once).
        assert b"\n" not in root_launcher.replace(b"\r\n", b""), "top launcher must have CRLF only"
        assert b"files\\START-HERE-GUI.bat" in root_launcher, "top launcher must start files\\START-HERE-GUI.bat"
        assert b"powershell" not in root_launcher.lower() and b"runas" not in root_launcher.lower(), "top launcher must not run anything itself"

        batch = members["START-HERE.bat"]
        assert b"\n" not in batch.replace(b"\r\n", b""), "batch must have CRLF only"
        assert b"STEP 6d/9" in batch and b"Invoke-PersistenceScan.ps1" in batch
        # Inside files/: the guided runner, its two halves and the GUI window launcher.
        launchers = sorted(n for n in members if n.endswith(".bat") and "/" not in n)
        assert launchers == ["Run-DetectRemoteAccess.bat", "START-HERE-GUI.bat", "START-HERE-OFFLINE.bat",
                             "START-HERE-ONLINE.bat", "START-HERE.bat"], launchers
        gui_batch = members["START-HERE-GUI.bat"]
        assert b"\n" not in gui_batch.replace(b"\r\n", b""), "GUI launcher must have CRLF only"
        assert b"gui\\Start-CleanupGui.ps1" in gui_batch and b"-STA" in gui_batch
        # The window is a third front end, never a third engine: no engine logic ships in gui/.
        assert b"Register-ObjectEvent" not in members["gui/Start-CleanupGui.ps1"]
        assert b"RunspaceFactory" not in members["gui/Start-CleanupGui.ps1"]
        json.loads(members["gui/steps.json"].decode("ascii"))
        assert b"-PersistenceInventory" in batch and b"-PersistenceResult" in batch
        assert b"Get-SccPersistenceInventory" in members["Persistence.Inventory.psm1"]
        assert b"Invoke-SccPersistenceReview" in members["Persistence.Removal.psm1"]
        # The pre-change restore point must ship with both entry points: the
        # helper enables System Restore, checkpoints and verifies a fresh point.
        restore_module = members["SystemRestore.psm1"]
        assert b"Invoke-SccRestorePoint" in restore_module
        assert b"Enable-ComputerRestore" in restore_module
        assert b"Get-ComputerRestorePoint" in restore_module
        assert b"Invoke-SccRestorePoint" in members["sc-cleanup.ps1"]
        assert b"Invoke-SccRestorePoint" in members["preflight.ps1"]
        assert b"Persistence" in members["Submit-ConnectWiseReport.ps1"]
        print(f"PASS deploy ZIP: {len(package)} members (START-HERE-GUI.bat on top, the rest in files/), exact manifest, version {version}, source {commit}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("zip")
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    verify(args.zip, args.version, args.commit)
