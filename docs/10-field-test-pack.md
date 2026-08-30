# Field-Test Pack (owner-run items 3-6, 2026-08-28)

Everything here runs on real Windows by the owner. Agents do not run these.
Each item says exactly what to do and what to send back. Run on a disposable
lab VM (or a test machine) - never a production client box for the removal
parts.

---

## 1. M0 - relay-key map validation (the last detection unknown)

Goal: confirm the launch-parameter key map the detector relies on (`h` =
relay host, `e` = session type, etc.). This is the ONLY remaining correctness
unknown in Stage 2 detection.

Setup (lab VM):
1. Create a free ScreenConnect (ConnectWise Control) cloud/test instance, or
   any relay server you control.
2. On the lab VM, install the ScreenConnect client from that instance
   (Access / unattended session type).
3. Also install a SECOND client from a DIFFERENT instance if possible - the
   point is to prove the tool can tell two relays apart.

Capture:
1. From the tool folder (latest release zip):

       powershell -NoProfile -ExecutionPolicy Bypass -File .\detect-remote-access.ps1 -All -NoPause -OutRoot C:\RIT-SCC-M0

2. Open the console output. Look for the PARSE PROBLEMS section - if the
   parser mis-mapped any key, it is listed there with the raw blob attached.
3. Send back the WHOLE output folder (zip it):

       C:\RIT-SCC-M0\<HOST>_<stamp>\   <- findings.json + raw\ + SUMMARY.txt

What the evidence must prove (answer each):
- [ ] RelayHost parsed matches the relay server you actually installed from
- [ ] SessionType says Access for an unattended install
- [ ] ServerKey / fingerprint present and identical for two clients from the
      SAME instance, different for the OTHER instance (Q1 server-key stability)
- [ ] ParamBlobSource recorded (service ImagePath / process command line /
      .config file) - this answers Q2
- [ ] No Unmapped keys, or the unmapped keys are explained

Belt-and-braces manual dump (if the parser disagrees with reality):
- Service ImagePath of the ScreenConnect service(s)
- `%ProgramFiles(x86)%\ScreenConnect Client (<id>)\*.config` contents
- HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
  entries for ScreenConnect (UninstallString presence answers Q3)

---

## 2. 3010 reboot-resume path (one lab run)

Goal: prove a vendor uninstaller that returns exit 3010 (reboot required)
correctly defers persistence cleanup to a post-reboot resume WITHOUT
re-running the uninstaller. See docs/09 section 7.2 for the full scenario;
short version:

1. Lab VM with a ScreenConnect install whose UninstallString is an MSI.
2. Run removal with a forced 3010 (e.g. `msiexec /x <code> /norestart`, or
   pre-seed the resume marker - see remove-screenconnect.ps1 resume-marker
   support).
3. Expected: manifest entry Result=Success with 3010 detail; NO manual
   surgery on this pass; status RebootPending (never Completed); a RunOnce
   resume key set under HKLM\...\RunOnce (SCCleanup_Resume_<id>).
4. Reboot. Expected: the RunOnce resume completes persistence cleanup
   WITHOUT re-running the vendor uninstaller; second manifest entry
   completes the instance.
5. Send back: removal-manifest.json + resume-marker.json + master.log.

## 3. ESET + Malwarebytes scanner confirmation (attended GUIs)

KVRT is confirmed. The same attended flow needs one live pass each:

1. Step 1 (stage tools), then Step 6b (ESET): a visible GUI must appear and
   the script must wait until you close it.
2. Step 6c (Malwarebytes): winget install runs in a visible console, then
   mbam.exe launches; script waits until you close it.
3. Expected console lines: "Launching GUI scanner: ..." then "Technician
   closed the scanner after Ns (exit code 0)".
4. If anything exits early, v1.7.19+ prints "SUSPICIOUS: ... exited Ns after
   launch ... ExitedEarly" - send that output verbatim.
5. Send back: scanner_results.json (written by sc-cleanup.ps1 runs) or the
   console output of the START-HERE.bat steps.

## 4. Full live-test matrix walk

Run docs/09-windows-live-test-matrix.md sections 1-8 in order on a lab VM
(sections 1-6 + 7b are non-destructive; section 7 is destructive - dedicated
lab VM only).
with Windows PowerShell 5.1. The release gate summary (section 8) is the
acceptance criterion. The highest-value items for THIS release (v1.7.21):

- Section 3.1: clean read-only run `-sr` exits 0
- Section 5.2/5.3/5.4: the three scanners (KVRT/ESET/Malwarebytes)
- Section 7.1: full removal on a real (lab) install with -ExecuteRemoval
- Section 7.2: the 3010 reboot case above
- NEW (v1.7.21): Stage 7 Procmon - run `sc-cleanup.ps1 -sr -procmon
  -ProcmonRuntime 60` and confirm a .pml appears under
  <WorkDir>\logs\Procmon\ and the stage reports its capture window
- NEW (v1.7.21): Amcache - after any snapshot, confirm snapshot JSON has an
  Amcache section (files + applications) and diff-snapshots.ps1 reports it
  as a stable section

## What to send back after any of these

A zip of the run's working directory (master.log + all JSON artifacts) plus
the console output. That is enough to close the item.
