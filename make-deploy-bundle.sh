#!/usr/bin/env bash
# Build a clean deploy bundle: scripts + docs only, no Sysinternals binaries.
# Output: <parent>/screenconnect-cleanup-deploy.zip
#
# NOTE: tools/Get-ToolPack.ps1 and tools/Get-AVTools.ps1 are referenced by
# sc-cleanup.ps1 / preflight.ps1 / START-HERE.bat but are NOT currently present
# in the repo (they were never committed; the downloader/stager scripts must be
# rebuilt from the official vendor URLs before a deploy bundle can stage the AV
# scanners). This script therefore copies them only when they exist and warns
# otherwise, so a bundle is still produced for the read-only half of the tool.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
OUT="$(dirname "$SRC")/screenconnect-cleanup-deploy.zip"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
D="$STAGE/screenconnect-cleanup"
mkdir -p "$D/scanners" "$D/tools"

# Core scripts + docs (all required). Fail loudly if any are missing.
for f in sc-cleanup.ps1 preflight.ps1 collect-snapshot.ps1 diff-snapshots.ps1 \
         detect-remote-access.ps1 remove-screenconnect.ps1 \
         Invoke-ReviewAndRemove.ps1 Run-DetectRemoteAccess.bat START-HERE.bat \
         targets.json New-InvestigationReport.ps1 DEPLOY.md; do
  cp "$SRC/$f" "$D/"
done
[ -f "$SRC/README.md" ] && cp "$SRC/README.md" "$D/"
cp "$SRC"/scanners/*.ps1 "$D/scanners/"
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

echo "--- bundle contents ---"
python3 -c "import zipfile,sys; [print(i.filename, i.file_size) for i in zipfile.ZipFile('$OUT').infolist()]"
