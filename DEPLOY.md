# DEPLOY — how to package, copy and run this tool on a client machine

Audience: the technician carrying this folder to a Windows PC.
Everything in this repo was built and verified off-box (Linux + PowerShell 7);
**live Windows validation is still outstanding** — see "Before you trust it" below.

---

## 1. What to copy (and what not to)

Copy these, and only these:

```
sc-cleanup.ps1                  <- top-level runner; you only ever launch this
preflight.ps1
collect-snapshot.ps1
diff-snapshots.ps1
detect-remote-access.ps1
Run-DetectRemoteAccess.bat
targets.json
New-InvestigationReport.ps1
scanners\
  Invoke-DefenderScan.ps1
  Invoke-KVRTScan.ps1
  Invoke-ESETScan.ps1
tools\Get-ToolPack.ps1          <- downloader ONLY; do NOT copy tools\* exes
tools\Get-AVTools.ps1           <- KVRT / ESET Online Scanner / Malwarebytes stager
docs\                           <- optional but recommended (work log + roadmap)
DEPLOY.md                       <- this file
```

Do **not** copy:

- `tools\ProcessMonitor\`, `tools\Autoruns\`, `tools\TCPView\`, `tools\Sigcheck\`, `tools\AV\`
  — ~24 MB of Sysinternals binaries. `Get-ToolPack.ps1` rebuilds them from the
  official Microsoft download site on the target machine. Never use mirrors.
- any `*.output`, test artifacts, or old scan output folders.

A prebuilt zip with exactly the layout above is produced by
`make-deploy-bundle.sh` (Linux side) as `../screenconnect-cleanup-deploy.zip`.

## 2. First run on a Windows machine

Requirements: Windows 10/11 or Server 2016+, PowerShell 5.1 (built in),
local administrator, internet access for the tool pack and scanners.

```
1. Copy screenconnect-cleanup-deploy.zip to the machine (USB / secure share).
2. Right-click -> Properties -> Unblock (if downloaded), then extract,
   e.g. to C:\RIT-SCC\tool.
3. Open an elevated PowerShell in that folder.
4. Build the Sysinternals pack once:
      powershell -ExecutionPolicy Bypass -File .\tools\Get-ToolPack.ps1
   Verify it:  powershell -File .\tools\Get-ToolPack.ps1 -Verify
5. Dry-run the whole pipeline first (executes nothing):
      powershell -ExecutionPolicy Bypass -File .\sc-cleanup.ps1 -WhatIf
6. Real read-only investigation run:
      powershell -ExecutionPolicy Bypass -File .\sc-cleanup.ps1 -sr -sa `
        -TechName "Your Name" -ClientName "ClientID" [-IncidentDate yyyy-MM-dd]
   -sr skips removal (Stage 4 is a stub anyway) and -sa skips AV scanners,
   so this run touches nothing: snapshot, detect, after-snapshot, report.
7. Output lands under C:\RIT-SCC\<HOST>_<timestamp>\ — findings.json,
   HTML/tech report, raw\ evidence, before/after diff.
```

Standalone detection (no admin needed for partial results):

```
Run-DetectRemoteAccess.bat        (double-click)
powershell -File .\detect-remote-access.ps1 [-Target screenconnect,anydesk] [-All] [-SelfTest]
```

## 3. Common flags (sc-cleanup.ps1)

| Flag | Effect |
|---|---|
| `-sr` | skip removal stage (recommended until M0/M5 are validated) |
| `-sa` | skip antivirus scanner stage |
| `-np` | do not create a restore point |
| `-offline` | use pre-staged tool pack, no downloads |
| `-procmon` | opt in to Procmon respawn-tracing stage |
| `-IncidentDate yyyy-MM-dd` | anchor the incident window weighting |
| `-WhatIf` | show what would run; execute nothing |

## 4. Before you trust it — outstanding live validation

These were never run against real Windows content (agents had no Windows box;
owner tests live). In priority order:

1. **M0 key-map validation (top priority).** On any machine with a real
   ScreenConnect install run detect-remote-access.ps1, then check:
   does RELAY HOST / session type look right vs reality? Send back the
   `raw\` folder and any PARSE PROBLEMS section — that corrects the parser.
2. Run collect-snapshot.ps1 twice ~30s apart; diff must show only volatile
   sections (processes/connections), no ordering churn.
3. One smoke run of each scanner adapter (-WhatIf at minimum, then a real
   Defender quick scan).
4. Confirm Get-ToolPack downloads complete on the target's network.

Nothing destructive ships: Stage 4 (removal) is a stub behind the review gate.
Do not build/rely on removal until M0 confirms the key map.

## 5. House rules for anyone editing here

- PowerShell 5.1 compatible syntax, pure ASCII, no BOM (PS 5.1 reads BOM-less
  non-ASCII as Windows-1252).
- Verify by running, not claiming: parse check + ASCII check + execution.
- Do not invent CLI flags, URLs or APIs; cite vendor docs in comments.
