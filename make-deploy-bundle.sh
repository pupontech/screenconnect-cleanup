#!/usr/bin/env bash
# Build a clean deploy bundle: scripts + docs only, no Sysinternals binaries.
# Output: <parent>/screenconnect-cleanup-deploy.zip
#
# tools/Get-ToolPack.ps1 (Sysinternals) and tools/Get-AVTools.ps1 (AV scanner
# stager) are bundled when present; both are committed to the repo. Get-AVTools
# stages KVRT.exe and esetonlinescanner.exe from official vendor URLs; Malwarebytes
# is installed by the visible winget path at runtime.
set -euo pipefail
PYTHON="${PYTHON:-python3}"
SRC="$(cd "$(dirname "$0")" && pwd)"
OUT_BASE="$(dirname "$SRC")/screenconnect-cleanup"
# Version is read from the VERSION file (repo root). Fall back to 'dev' if absent.
VER="$(tr -d '[:space:]' < "$SRC/VERSION" 2>/dev/null || echo dev)"
OUT="${OUT_BASE}-v${VER}.zip"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
D="$STAGE/screenconnect-cleanup"
mkdir -p "$D/tools"

# Core scripts + docs (all required). Fail loudly if any are missing.
for f in sc-cleanup.ps1 preflight.ps1 collect-snapshot.ps1 diff-snapshots.ps1 \
         detect-remote-access.ps1 remove-screenconnect.ps1 install-latest.ps1 \
         Invoke-ReviewAndRemove.ps1 Invoke-GUIScanner.ps1 Get-ScannerFindings.ps1 Get-MalwarebytesDownloadDiagnostics.ps1 Invoke-AVUninstaller.ps1 Run-DetectRemoteAccess.bat START-HERE.bat \
         targets.json New-InvestigationReport.ps1 Submit-ConnectWiseReport.ps1 \
         Invoke-PersistenceScan.ps1 Invoke-PersistenceInventoryWorker.ps1 Show-PersistenceReview.ps1 Persistence.Inventory.psm1 Persistence.Removal.psm1 \
         microbin-url.txt DEPLOY.md; do
  cp "$SRC/$f" "$D/"
done
[ -f "$SRC/README.md" ] && cp "$SRC/README.md" "$D/"
[ -f "$SRC/CHANGELOG.md" ] && cp "$SRC/CHANGELOG.md" "$D/"
[ -d "$SRC/docs" ] && cp -r "$SRC/docs" "$D/docs"

# Keep-awake and battery-confirmation helpers are required by START-HERE.bat.
cp "$SRC/tools/Keep-Awake.ps1" "$D/tools/"
cp "$SRC/tools/Confirm-OnBattery.ps1" "$D/tools/"

# Optional tool-pack downloader/stager scripts. Copy when present, warn when not.
missing_tools=""
for f in Get-ToolPack.ps1 Get-AVTools.ps1; do
  if [ -f "$SRC/tools/$f" ]; then
    cp "$SRC/tools/$f" "$D/tools/"
  else
    missing_tools="$missing_tools $f"
  fi
done
if [ -n "$missing_tools" ]; then
  echo "WARNING: missing from repo, not bundled:$missing_tools" >&2
  echo "         (rebuild these downloaders from official vendor URLs before" >&2
  echo "          staging the tool pack / AV scanners on a client machine)" >&2
fi

# Stamp the version into the bundle so it is self-identifying even if the
# file is renamed. Do NOT overwrite an existing VERSION (keep the repo one).
if [ ! -f "$D/VERSION" ]; then
  cp "$SRC/VERSION" "$D/VERSION"
fi

"$PYTHON" - "$OUT" "$STAGE" "$SRC" "$VER" <<'PY'
import sys, zipfile, os, hashlib, subprocess
out, stage = sys.argv[1], sys.argv[2]
src, version = sys.argv[3], sys.argv[4]
bundle = os.path.join(stage, 'screenconnect-cleanup')
sha = subprocess.check_output(['git', '-C', src, 'rev-parse', 'HEAD'], text=True).strip()
if len(sha) != 40:
    raise SystemExit('A full source commit is required for package provenance.')
with open(os.path.join(bundle, 'BUILD-INFO.txt'), 'w', encoding='ascii', newline='\n') as f:
    f.write('ScreenConnect Cleanup ' + version + '\nSource commit: ' + sha + '\n')
    f.write('Owner live Windows acceptance required. See CHANGELOG.md and DEPLOY.md.\n')
members = []
for root, dirs, files in os.walk(bundle):
    dirs.sort()
    for name in sorted(files):
        p = os.path.join(root, name)
        relative = os.path.relpath(p, bundle).replace(os.sep, '/')
        with open(p, 'rb') as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        members.append((relative, digest))
with open(os.path.join(bundle, 'SHA256SUMS.txt'), 'w', encoding='ascii', newline='\n') as f:
    for relative, digest in sorted(members):
        f.write(digest + '  ' + relative + '\n')
if os.path.exists(out):
    os.remove(out)
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(stage):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(root, f)
            z.write(p, os.path.relpath(p, stage))
print('wrote', out)
PY

echo "Bundle: $(basename "$OUT")"
"$PYTHON" -c "import zipfile,sys; [print(i.filename, i.file_size) for i in zipfile.ZipFile(sys.argv[1]).infolist()]" "$OUT"
