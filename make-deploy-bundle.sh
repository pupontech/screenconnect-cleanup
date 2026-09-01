#!/usr/bin/env bash
# Build a clean deploy bundle: scripts + docs only, no Sysinternals binaries.
# Output: <parent>/screenconnect-cleanup-deploy.zip
#
# tools/Get-ToolPack.ps1 (Sysinternals) and tools/Get-AVTools.ps1 (AV scanner
# stager) are bundled when present; both are committed to the repo. Get-AVTools
# stages KVRT.exe and esetonlinescanner.exe from official vendor URLs; Malwarebytes
# is installed by the visible winget path at runtime.
set -euo pipefail
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
         Invoke-ReviewAndRemove.ps1 Invoke-GUIScanner.ps1 Get-MalwarebytesDownloadDiagnostics.ps1 Invoke-AVUninstaller.ps1 Run-DetectRemoteAccess.bat START-HERE.bat \
         targets.json New-InvestigationReport.ps1 DEPLOY.md; do
  cp "$SRC/$f" "$D/"
done
[ -f "$SRC/README.md" ] && cp "$SRC/README.md" "$D/"
[ -d "$SRC/docs" ] && cp -r "$SRC/docs" "$D/docs"

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

# GeneralFix - the owner's "Tikun HaKlali" general-fix batch tool - ships in
# the bundle. It is fully self-contained (no UNC paths, net use, or URLs; it
# only uses built-in Windows commands plus its embedded VBS/WSF jobs) and must
# NOT be staged from a network share at runtime. Copied as-is so the original
# name and byte layout (CRLF + cp1255) are preserved.
if [ -d "$SRC/tools/GeneralFix" ]; then
  cp -r "$SRC/tools/GeneralFix" "$D/tools/"
else
  echo "WARNING: tools/GeneralFix missing, not bundled (owner's tikun tool)" >&2
fi

# Stamp the version into the bundle so it is self-identifying even if the
# file is renamed. Do NOT overwrite an existing VERSION (keep the repo one).
if [ ! -f "$D/VERSION" ]; then
  cp "$SRC/VERSION" "$D/VERSION"
fi

python3 - "$OUT" "$STAGE" <<'PY'
import sys, zipfile, os
out, stage = sys.argv[1], sys.argv[2]
if os.path.exists(out):
    os.remove(out)
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk(stage):
        for f in files:
            p = os.path.join(root, f)
            z.write(p, os.path.relpath(p, stage))
print('wrote', out)
PY

echo "Bundle: $(basename "$OUT")"
python3 -c "import zipfile,sys; [print(i.filename, i.file_size) for i in zipfile.ZipFile('$OUT').infolist()]"
