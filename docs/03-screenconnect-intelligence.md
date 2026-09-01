# ScreenConnect intelligence

**Everything here is confidence-labelled. Respect the labels.** The single biggest risk
to this project is a future contributor treating an ASSUMED item as fact and building
removal logic on it.

- **[KNOWN]** — high confidence, consistent with widely documented behaviour. Still worth
  a spot-check.
- **[ASSUMED]** — our current working belief. Not verified. **This is what the PoC exists
  to test.**
- **[VERIFY]** — explicitly unknown. Do not state as fact, do not build on it.

---

## The core problem

A legitimate ScreenConnect install and a scammer's ScreenConnect install are **the same
signed commercial software**. Identical publisher, identical Authenticode signature,
identical product name, identical file names, frequently identical hashes.

Therefore: **signature checks, publisher checks, and hash blacklists cannot answer "is
this authorized."** They answer a different question — "has this binary been tampered
with or masqueraded" — which is a rarer and separate finding.

The discriminator is **instance identity**: which relay server the client calls home to.

---

## Client shape on Windows

**[KNOWN]** Installs as a Windows service named:

```
ScreenConnect Client (<instance-identifier>)
```

The parenthesized identifier differs per server instance. **This is why several instances
can coexist on one machine** — and why enumeration must never assume there is only one.

**[KNOWN]** Default install directory:

```
%ProgramFiles(x86)%\ScreenConnect Client (<instance-identifier>)\
```

**[KNOWN]** A matching uninstall entry exists under the standard `Uninstall` registry
keys, display name matching the service.

**[KNOWN]** Installers are downloaded with a long query string encoding the instance,
typically landing in Downloads or Temp. Recovering that file (and its
mark-of-the-web/originating URL) is strong provenance evidence.

**[KNOWN]** Cloud-hosted instances are subdomains of `screenconnect.com`.

**[KNOWN]** Binaries are Authenticode-signed by the vendor — legitimate and scam installs
alike.

**[VERIFY]** Exact process names and the full file/DLL manifest per version. Recollection
is that the service executable is `ScreenConnect.ClientService.exe`, with a user-session
UI process and a background/backstage process alongside it, but names drift between
versions. Confirm against a live install.

**[VERIFY]** Current Authenticode signer CN. This has changed with ownership and branding
churn (ScreenConnect -> ConnectWise Control -> ScreenConnect, plus a reported 2025
divestiture that has NOT been confirmed here). Do not hardcode a signer string.

**[VERIFY]** Whether the client writes to `HKLM\SOFTWARE\ScreenConnect` or equivalent.

**[VERIFY]** Client-side log file locations, format and retention. Potentially the best
source of "who connected, when" — worth investigating early.

**[VERIFY]** Whether the client registers an Event Log source and what it emits.

**[VERIFY]** The supported uninstall path (MSI product code? a documented client-side
uninstall switch? server-initiated only?) and what it deliberately leaves behind.

---

## The launch-parameter blob — THE critical assumption

**[ASSUMED]** The client's launch parameters are stored as a `key=value&key=value` query
string, found in one or more of:

1. The **service ImagePath** (as a quoted second argument) — cheapest source
2. A running process's **command line**
3. The service executable's **`.config` file** in the install directory

**[ASSUMED]** Key meanings:

| Key | Meaning | Notes |
|---|---|---|
| `e` | Session type | `Access` = persistent unattended, `Support` = one-shot, `Meeting`. **Access is materially more serious than Support.** |
| `y` | Role | typically `Guest` |
| `h` | **Relay host** | **THE decision key** |
| `p` | Relay port | default believed to be `8041`; `443` also seen |
| `s` | Session ID | GUID |
| `k` | Encoded server public key | corroborates the host; host alone is renameable |
| `c1`..`c8` | Custom properties | operator-set; **often literally names the company that deployed it** |

**[VERIFY] — the top open item in the entire project:** whether the `k` value is stable
per server. The whole "which server is this" model leans on it. If it is not stable,
relay host plus custom properties is the fallback, which is weaker.

**[KNOWN]** Values are URL-encoded and must be unescaped (`%20` -> space, `%3d` -> `=`).
Confirmed working in the PoC self-test.

### How the PoC hedges against this map being wrong

Because the map is ASSUMED, the detector deliberately does **not** hunt for keys it
expects. It:

- Finds parameter blobs with a **generic regex**: any run of 3+ `key=value&` pairs,
  preferring one containing `h=` or a recognisable session type
- **URL-decodes** every value
- Preserves any key **not** in the map under `UnknownParams`, printed as `Unmapped keys:`
- Records **which source** the blob came from (`ParamBlobSource`)
- Copies every `.config` file **verbatim** into `raw\` **even when parsing succeeds**
- Reports instances where extraction failed under a loud `PARSE PROBLEMS` heading with
  the raw sources attached

So a wrong map produces **recoverable diagnostic output**, not a silent wrong answer.

---

## Historical evidence

**[KNOWN]** **Event ID 7045** in the System log — "A service was installed in the system"
— records the service name and image path, and **survives the agent being uninstalled**.
This is how you find an instance that was installed and later removed, and when it
arrived. The detector already parses this and reports 7045 entries with no matching live
install as `Historical`.

Requires admin on most builds. The detector degrades gracefully and says so when it
cannot read the log.

**[STATUS v1.7.32]** Other retrospective execution artifacts exist and are far more useful than
live monitoring, because a technician always arrives after the fact: Prefetch, Amcache,
ShimCache, BAM/DAM, UserAssist, SRUM (which records per-application bytes sent/received,
quantifying how much data moved). Prefetch, Amcache, BAM/DAM, UserAssist, and SRUM inventory
are implemented in Stage 1. Amcache currently uses a temporary hive mount and needs live
cleanup validation; ShimCache is raw-metadata-only until its format-specific decoder is
validated against Windows 8.1/10/11 fixtures.

---

## Server-side context (not endpoint cleanup, but relevant)

**[KNOWN, low relevance]** ConnectWise ScreenConnect **server** had critical 2024
vulnerabilities (an authentication bypass and a path traversal) that were exploited to
deploy ransomware. This matters when threat-modelling a client's own on-premise
ScreenConnect server. It is **not** relevant to cleaning a client endpoint, and should
not be conflated with it.

---

## Things that must NOT be assumed

- That any ScreenConnect instance is malicious because it is ScreenConnect
- That any instance is benign because it is signed
- That an AV scanner will detect it (it will not — see `05`)
- That a clean AV scan means the machine is clean
- That removing the agent remediates the incident
- That file hashes are stable across instances — installers are customized per server,
  so hashes may legitimately differ
- That absence of persistence means absence of access (stolen session cookies need no
  persistence at all)
