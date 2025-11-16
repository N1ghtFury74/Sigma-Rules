# T1105 — Ingress Tool Transfer · LOLBin: mshta.exe (Microsoft HTML Application Host)
**Rules covered:**  
- CNC-E-2726320-172 — mshta Parent Process · URL in Command Line (Process Creation)  
- CNC-E-2726320-174 — mshta Network Connection (Sysmon EID 3)  
- CNC-E-2726320-173 — mshta FileCreate in Writable Paths & INetCache (Sysmon EID 11)  
**Last updated:** 2025-10-28 06:42 UTC

> `mshta.exe` executes HTML Applications (**.hta**) and can consume **remote content** (HTTP/HTTPS/WebDAV/UNC) or inline protocols
> (e.g., `javascript:`, `vbscript:`). Adversaries abuse it to **download and run** script content with full user context, enabling
> **Ingress Tool Transfer (T1105)** and follow‑on execution while leveraging a Microsoft‑signed binary.

---

## Playbook 1 — mshta Parent Process · URL in Command Line (Process Creation)

### Overview
Investigate **process creation** where `mshta.exe` is launched with a **URL/UNC/WebDAV** in the command line (e.g., `http(s)://…`, `\\host\share\x.hta`,
`\\host@SSL\DavWWWRoot\x.hta`). Parent process context is crucial: **non‑browser/Office/script‑host parents** often indicate delivery via phishing,
malicious documents, or script chains.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** with `Image`, full `CommandLine`, `ParentImage`, `User`, integrity level, working dir, timestamp.  
2. **Parse source:** Extract **scheme/host/port/path**. Classify **internal vs external**; flag **raw IPs** and **non‑standard ports**.  
3. **Secure artifacts:** If the URL likely wrote to cache/temp, capture relevant **INetCache**/**%TEMP%** files and compute **hashes** (avoid execution).

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path (`C:\\Windows\\System32\\mshta.exe` / `SysWOW64`) and signature.  
- Review **parent** for ingress vector: Outlook/Teams/browser (phish), Office (macro), `wscript/cscript/powershell/cmd`, or other LOLBins.  
- Note inline protocols (e.g., `mshta.exe javascript:...`) which may still cause **secondary network** fetches via script.

#### 2) Command‑Line Semantics
- Identify **query strings**, **encoded params**, or **redirects** on the URL.  
- For UNC/WebDAV (`DavWWWRoot`, `@SSL`), expect **WebClient** mediation rather than direct `mshta.exe` sockets.

#### 3) Network & DNS Corroboration
- Correlate **Sysmon EID 3** for outbound connections (may appear under `svchost.exe` WebClient for WebDAV).  
- Use **proxy** logs for HTTP(S) requests; **Sysmon EID 22** for DNS (or proxy FQDN under explicit proxy).

#### 4) Artifact & Content Analysis
- Inspect fetched/embedded content: MIME vs extension (`application/hta`, HTML, scriptlets).  
- Check **Zone.Identifier** ADS, **entropy**, and suspicious **strings/URLs**.  
- Identify any **child processes** spawned by the HTA (e.g., `powershell.exe`, `cmd.exe`, `rundll32.exe`, `regsvr32.exe`).

#### 5) Correlation & Fleet
- Pivot on **URL host**, **hashes** of cached HTA, and **parent process patterns** across the fleet.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Full `CommandLine` with URL and `ParentImage`.  
- **Sysmon EID 3 / Proxy:** Outbound HTTP(S) / WebDAV flows; **Sysmon EID 22** DNS lookups.  
- **Sysmon EID 11:** Writes into **INetCache**/**%TEMP%**.  
- **EDR timeline:** Child processes and module loads.

### Containment Actions
- **Block** destination, **quarantine** artifacts, **terminate** process chain; consider **host isolation** if code execution observed.

### Prevention Measures
- Disable or restrict `mshta.exe` via **AppLocker/WDAC** on endpoints.  
- Egress filtering and **domain allowlists**; block **WebClient** if unused.  
- Harden Office (macros from Internet) and mail defenses; alert on **rare process → mshta.exe** launches.

### Recovery
- Remove staged payloads/persistence; tune detections/allowlists; educate users/admins on HTA risks.

### False Positives
- Rare enterprise automations rendering local **.hta** from **trusted internal shares**. Validate and allowlist by path/domain.

---

## Playbook 2 — mshta Network Connection (Sysmon EID 3)

### Overview
This playbook covers **outbound connections** attributed to `mshta.exe`. Although HTAs can be local, **remote HTA URLs** or HTA‑hosted script activity
commonly produce egress to fetch secondary payloads/configs — a hallmark of **T1105** staging.

### Initial Response
1. **Capture records:** Export **EID 3** (dest IP/host/port/proto) and correlate with **EID 1/4688** for `mshta.exe`.  
2. **Classify destination:** Internal vs external; flag **raw IPs**, **new/rare domains**, **non‑standard ports**.  
3. **Scope user/asset:** Determine if HTA usage is expected; in most enterprises it is **not**.

### Investigation Steps
#### 1) Process & Command Context
- Retrieve full **command line** (was a URL present? inline JavaScript/VBScript?).  
- Validate **parent** process; check user session and time of day.

#### 2) Destination Validation
- Enrich domains/IPs (age/reputation); review **proxy** logs for method/status/bytes and content‑type.  
- For **WebDAV**, pivot to **WebClient** `svchost.exe` events (ports **80/443**); for **SMB**, validate **445** sessions.

#### 3) Artifact Discovery
- Search **EID 11** for created files (cache/temp) and compute **hashes**; inspect **Zone.Identifier** ADS.  
- Identify any **execution** of downloaded artifacts (PowerShell, rundll32, regsvr32, msiexec).

#### 4) Correlation & Fleet
- Pivot on **destination**, **hashes**, and **CLI** patterns across endpoints; cluster by **parent process** and **user** to assess spread.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\mshta.exe`, destination host/IP/port.  
- **Sysmon EID 1 / 4688:** Launch context and `CommandLine`.  
- **Sysmon EID 11:** File writes tied to the connection.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.

### Containment Actions
- **Block** endpoints; **quarantine** artifacts; **terminate** activity; consider **host isolation** if execution occurred.

### Prevention Measures
- Restrict/disable `mshta.exe`; enforce **egress controls**; monitor **rare process → network** pairs.  
- ASR rules and mail filtering to prevent HTML/HTA delivery from Internet.

### Recovery
- Remove artifacts/persistence; tune detections; update runbooks and allowlists.

### False Positives
- Limited internal admin tools using HTA UIs from **approved** shares; validate via owners and schedules.

---

## Playbook 3 — mshta FileCreate in Writable Paths & INetCache (Sysmon EID 11)

### Overview
Investigate **file creation** events where `mshta.exe` writes to **user‑writable** locations (e.g., `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, `Downloads`)
or **INetCache**. This commonly follows remote HTA execution and indicates local **staging** for subsequent execution (**T1105**).

### Initial Response
1. **Secure artifacts:** Copy and **hash** created files; preserve timestamps/ACLs; avoid execution.  
2. **Trace lineage:** Correlate with preceding `mshta.exe` **EID 1/4688** and adjacent **EID 3/22** activity.  
3. **Assess location & type:** Prioritize executable/script types (`.exe`, `.dll`, `.js`, `.vbs`, `.hta`, `.bat`, `.cmd`, `.ps1`, `.lnk`, archives).

### Investigation Steps
#### 1) Artifact Inspection
- Determine true file type (headers); check **extension↔MIME** mismatch and **entropy**; inspect **strings** for URLs/keys.  
- Review **Zone.Identifier** ADS to determine Internet origin.

#### 2) Process Context
- Retrieve original `mshta.exe` **command line** to understand the source (URL/UNC/inline).  
- Identify **child processes** that execute the created files within minutes.

#### 3) Network & DNS Corroboration
- Confirm downloads via **proxy** logs and **EID 3**; review **EID 22** DNS (or proxy FQDN for explicit proxy).

#### 4) Fleet & Follow‑On
- Pivot on file **hashes/paths** and **source URLs** across the fleet; check for lateral re‑use under other users/hosts.

### Key Artifacts
- **Sysmon EID 11:** `TargetFilename` written by `mshta.exe`.  
- **Sysmon EID 1 / 4688:** Prior process creation showing URL.  
- **Sysmon EID 3 & 22 / Proxy:** Corroborating network/DNS telemetry.  
- **EDR timeline:** Execution of the staged artifacts.

### Containment Actions
- **Quarantine** files; **block** related domains/IPs; **terminate** chains; consider **host isolation** if code execution confirmed.

### Prevention Measures
- Disable/restrict `mshta.exe`; enforce **application control** for execution from user‑writable paths.  
- Egress filtering and domain allowlists; monitor **INetCache** writes by script hosts/LOLbins.

### Recovery
- Remove artifacts/persistence; rotate credentials if exposure suspected; update detections/runbooks.

### False Positives
- Legacy enterprise HTA tools writing temporary artifacts in user profile paths from **trusted** intranet sources; validate and allowlist.