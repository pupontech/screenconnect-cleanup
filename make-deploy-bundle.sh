#!/usr/bin/env bash
# Build a clean deploy bundle: scripts + docs only, no Sysinternals binaries.
# Output: <parent>/screenconnect-cleanup-deploy.zip
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
OUT="$(dirname "$SRC")/screenconnect-cleanup-deploy.zip"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
D="$STAGE/screenconnect-cleanup"
mkdir -p "$D/scanners" "$D/tools"

cp "$SRC"/sc-cleanup.ps1 \
   "$SRC"/preflight.ps1 \
   "$SRC"/collect-snapshot.ps1 \
   "$SRC"/diff-snapshots.ps1 \
   "$SRC"/detect-remote-access.ps1 \
   "$SRC"/remove-screenconnect.ps1 \
   "$SRC"/Run-DetectRemoteAccess.bat \
   "$SRC"/START-HERE.bat \
   "$SRC"/targets.json \
   "$SRC"/New-InvestigationReport.ps1 \
   "$SRC"/DEPLOY.md "$D/"
[ -f "$SRC/README.md" ] && cp "$SRC/README.md" "$D/"
cp "$SRC"/scanners/*.ps1 "$D/scanners/"
cp "$SRC"/tools/Get-ToolPack.ps1 "$D/tools/"
[ -d "$SRC/docs" ] && cp -r "$SRC/docs" "$D/docs"

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
