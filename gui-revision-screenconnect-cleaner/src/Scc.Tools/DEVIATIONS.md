# Scc.Tools - Deviations and Design Notes

This file records the deliberate, documented choices made while porting the
legacy tool-staging scripts into the `Scc.Tools` module. Every deviation is
grounded in either the module contract (ARCHITECTURE.md section 3.5), a
house rule, or a limitation of the Linux/pwsh test environment.

## 1. MSERT has no legacy URL in Get-AVTools.ps1
`Get-AVTools.ps1` stages KVRT, AdwCleaner, ESET Online Scanner and Malwarebytes
only; it does not download MSERT. Because the catalog contract requires an
MSERT entry, its OfficialUrl is the Microsoft Safety Scanner 64-bit download
link published on vendor documentation, fetched 2026-08-26:
    learn.microsoft.com/defender-endpoint/safety-scanner-download (LinkId=212732)
    -> https://go.microsoft.com/fwlink/?LinkId=212732
MSERT is a self-expiring tool per that same page (valid ~10 days), so it has no
pinned MinVersion and no ExpectedSha256; the module validates it by the same
rules as every other tool (size, signature, version) and records the actual
hash in the cache manifest.

## 2. Redirect hop-count is not precisely counted
The official download records `DownloadUrl`, `FinalUrl` (the final URI the
HTTP client actually resolved to), and a `Redirects[]` list. Because
Invoke-WebRequest follows redirects internally, the module records the resolved
final URL as the single observed redirect target rather than enumerating every
intermediary hop in the chain. This still satisfies "record URL + final URL
(+ redirect hops)" within a redirect-following client; the exact chain is
recoverable from FinalUrl.

## 3. File facts are computed fresh, not via Scc.Core's cached Get-SccFileFacts
Scc.Core caches file facts per process (per-run hashes). Integrity validation
must always hash the exact bytes on disk so that a tampered file is caught on
re-check (the tamper-detection tests rewrite a cached build and expect the
mismatch). The module therefore uses its own private, uncached fact collector
(`Get-SccToolFacts`) built on Get-Item / Get-FileHash. Scc.Core is still used for
config and path resolution (Get-SccConfig / Get-SccPaths) when it is present.

## 4. NAS reachability uses Test-Path (no active network probe)
Get-SccToolStatus is required to make "no network calls" and make the NAS check
a fast Test-Path. Resolve-SccTool uses the same Test-Path to decide NAS
reachability and records a WARNING (never fatal) when the configured nas.path
is not present. The bounded Scc.Core Test-SccNas probe is deliberately not used
inside Resolve so acquisition stays synchronous and testable; reachability
failures surface as provenance warnings rather than exceptions.

## 5. Authenticode is enforced on Windows only
On non-Windows targets (pwsh on Linux/macOS) the Authenticode API is
unavailable, so the signature check reports SignatureStatus=NotChecked and is
accepted with an explicit note in the Test-SccToolIntegrity reasons and in the
provenance. On Windows (env:OS = Windows_NT) the real Get-AuthenticodeSignature
check runs and enforces that a Valid signature's publisher matches the catalog
Publisher. This is the documented, testable-on-Linux split.

### 5a. Unverified signature statuses are NEVER marked Verified (hardening B1)
The following `SignatureStatus` values cause `Test-SccToolIntegrity` to set
`Passed=$false` (mirroring the existing `Invalid`/`HashMismatch`/`NotSigned`
behavior): `NotTrusted` (chain does not reach a trusted root), `UnknownError`,
`NotSupported`, `Error` (including the catch -> Error path), and any unhandled
`default`. An unverified tool must never be cached or reported as Verified: the
distinction is enforced for these states. Only `Valid` and `NotChecked`
(non-Windows platform limitation) are accepted. Config may later downgrade a
specific status to a warning, but the module never silently marks such a binary
Verified.

## 6. Save-SccToolToCache returns bool rather than throwing
An invalid source makes the function warn and return `$false` (it does not
throw), so a caller can recover; a valid file is copied and the manifest is
updated. Resolve-SccTool ignores the bool after it has already validated the
candidate. Extra optional `-Source` and `-DownloadUrl` parameters let
Resolve-SccTool stamp the manifest entry with the acquisition tier and URL.

### 6a. No redundant hashing (hardening B3)
`Save-SccToolToCache` gains an optional `-Integrity` parameter. When the caller
already computed an integrity result (as `Resolve-SccTool` does for every
candidate it validates), it passes that result in and `Save-SccToolToCache` does
NOT re-run `Test-SccToolIntegrity` (and therefore does not re-hash the file).
This removes the double-hash observed when `Resolve-SccTool` validated a path
and then `Save-SccToolToCache` re-validated it on the same resolve. When
`-Integrity` is omitted the function validates the file itself, preserving the
original standalone behavior.

## 7. Version baselines
Only Malwarebytes carries a MinVersion ('5.0.0.0', MB5 - the live FileVersion
observed 2026-08-26 was 5.6.x). KVRT, MSERT, AdwCleaner and ESET Online Scanner
are deliberately fresh-every-run / self-expiring and have no upstream pinned
minimum to cite; Sysinternals EULAs do not publish a minimum. When MinVersion is
set the version is compared numerically via [version]; when it is not set the
version is recorded as actual data only.

### 7a. Empty FileVersion + MinVersion fails (hardening B2)
When `FileVersion` is empty but the catalog sets `MinVersion`, integrity now
FAILS unless a valid catalog `ExpectedSha256` baseline exists (a pinned,
hash-verified binary is trusted regardless of its embedded version resource).
This closes the gap where an unversioned binary with a required minimum was
accepted with only a note.

## 8. Cache manifest schema
The manifest file (userData/tools/tool-cache-manifest.json) is a JSON array of
entries: { Name, Version, SHA256, Size, Publisher, SignatureStatus, CachedUtc,
Source, DownloadUrl }. Source and DownloadUrl are populated by Resolve-SccTool
at cache time; a direct Save-SccToolToCache call that does not pass them stamps
Source='Cached'. The single-element / empty-array JSON traps are handled on
read (ConvertFrom-Json unwraps single-element arrays) by normalizing to a
guaranteed array.