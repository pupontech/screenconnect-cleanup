# Scc.Detection - DEVIATIONS.md

Notes on deviations from the authoritative contracts (ARCHITECTURE.md section 3.2,
AUDIT-02-detection.md) made while porting detect-remote-access.ps1. All deviations
are behavioral-preserving unless explicitly noted.

## Source behavior preserved exactly

- Blob extraction regex `(?i)(?:[a-z][a-z0-9]{0,3}=[^&\s"''<>\)]*&){2,}[a-z][a-z0-9]{0,3}=[^&\s"''<>\)]*`
  and the h=/e= preference logic (prefer a blob carrying h= or e=Access|Support|Meeting,
  else longest) are copied verbatim from legacy Find-ScParamBlob.
- ConvertFrom-ScParamBlob: leading `?`/`&` trim, empty-pair skip, first-`=`-only
  split (values containing `=` preserved), URL decode via
  `[System.Uri]::UnescapeDataString()` in a try/catch.
- Get-ScIdentifier regex `ScreenConnect Client \(([^)]+)\)`.
- Fingerprint = SHA-256(ServerPublicKey) truncated to 16 lowercase hex.
- Dedup by instance key (identifier, else `svc:`/`dir:`/`reg:`/`proc:` fallback).
- 7045 service-install events, max 400, matched to instances by identifier;
  historical instances reported for events with no live install.
- $ScKnownKeys hashtable kept verbatim with its "ASSUMED, NOT CONFIRMED" comment.
  Unknown keys preserved in UnknownParameters.
- Confidence: High >=3 distinct sources, Medium ==2, Low ==1 or any parse issue.

## Behavioral deviations / clarifications

1. **ParserWarnings is an internal array, not surfaced as a separate public
   field per instance.** ARCHITECTURE.md lists `ParserWarnings (array)` in the
   instance object. I kept an internal `ParserWarnings` ArrayList on each instance
   AND surface parse issues:
   - `ParseIssue` (string) is set when no blob is found or no relay host post-parse.
   - `ParserWarnings` is exposed as `@(...)` array on the public instance object
     (both the internal one and the post-ConvertFrom warning). It is not dropped.
   - `Invoke-SccDetection` also rolls all warnings/parse issues into the top-level
     `Warnings` array so the GUI/CI can see them without walking every instance.

2. **Malformed percent-encoding detection is deterministic.** Legacy relies on
   `[System.Uri]::UnescapeDataString()` throwing to catch `%zz`. In practice that
   method does NOT always throw on malformed input, so the warning could be
   missed. I added an explicit `Test-MalformedPercentEncoding` check: any `%`
   not followed by exactly two hex digits is flagged, the value is left raw, and a
   `ParserWarnings` entry is recorded. This is strictly more robust and preserves
   the "leave value as-is" legacy behavior.

3. **Get-SccTrustedRelays(-Config) signature.** ARCHITECTURE.md shows
   `Get-SccTrustedRelays [-Config]`. I implemented it as `Get-SccTrustedRelays
   [-Config <object>]` where `-Config` lets a caller pass relays inline (used by
   the orchestration functions so we only read the file once). When called with no
   `-Config`, it reads trusted-relays.json from the standard dirs
   (user -> machine -> new-tree config) and returns an empty array if none is
   found (standalone). `Test-SccTrustedRelay` accepts the same `-Config`.

4. **Trust verdict is Known/Unknown only**, never "Suspicious", matching the brief
   (D-ARCH-6). A relay-host match with a mismatched fingerprint yields Unknown
   (the mismatched entry is still captured in `Entry` for technician review, but
   `TrustMatch` stays Unknown).

5. **Get-SccRemoteAccess shape.** ARCHITECTURE.md lists `Product, DisplayName,
   DetectionType, Evidence, ...` for the generic finding. The audit's "presence-only
   hits" contract (the one called out in the task body) is the richer
   `{Product, Id, Hits:[{Kind,Name,Detail,Path,State}], Count, Enabled}` shape, so
   I used that as the per-target object. `Kind` uses `Service|Process|Directory|
   Uninstall` (the legacy `installed-program` kind is renamed to `Uninstall` for
   clarity and consistency with the contract; this is a label-only change).

6. **Embedded defaults live inside the module** (both targets and an empty trusted
   list) so it works standalone, exactly as required. The embedded targets mirror
   config/targets.json. Only targets with `enabled=true` are scanned unless
   `-Targets`/`-All` is supplied.

7. **Detection orchestration functions (Get-SccScreenConnect, Get-SccRemoteAccess,
   Invoke-SccDetection) call the inventory functions directly** (which perform the
   real CIM/registry/event-log reads). All those reads are isolated in
   Get-SccServiceInventory, Get-SccProcessInventory, Get-SccUninstallInventory,
   Get-SccServiceInstallEvents, Get-SccConnectionsForPids, Get-SccScDirs, so Pester
   can mock them. No real Windows calls occur in unit tests.

8. **No raw-config-file copies / CSV dumps / transcripts / zip** (per AUDIT-02
   section 7, REMOVE). Detection is strictly read-only and is the only contract
   honored here.

## Files
- src/Scc.Detection/Scc.Detection.psd1
- src/Scc.Detection/Scc.Detection.psm1
- tests/Unit/Scc.Detection.Tests.ps1
