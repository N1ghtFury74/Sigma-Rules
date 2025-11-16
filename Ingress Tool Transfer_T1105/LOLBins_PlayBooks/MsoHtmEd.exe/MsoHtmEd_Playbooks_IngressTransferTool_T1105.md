# T1105 — Ingress Tool Transfer · LOLBin: MsoHtmEd.exe (Microsoft Office HTML Editor)
**Rules:**  
- CNC-E-2726320-201 — MsoHtmEd URL-on-CLI → INetCache Download (Process Creation)  
- CNC-E-2726320-202 — MsoHtmEd Outbound Network Activity (Sysmon EID 3)  
- CNC-E-2726320-203 — MsoHtmEd FileCreate in INetCache (Sysmon EID 11)  
**Last updated:** 2025-10-28 06:47 UTC

> `MsoHtmEd.exe` is an Office-signed HTML editor/renderer used by legacy Office components to view/edit HTML. When invoked directly with a
> **URL/UNC/WebDAV** path, it can fetch remote content and write artifacts under **INetCache** or user-writable temp paths. Adversaries may
> abuse it as a signed **fetcher/stager** to retrieve payloads or HTML/Script content (**T1105 — Ingress Tool Transfer**).

---

## Playbook 1 — URL-on-CLI → INetCache Download (Process Creation)

### Overview
Investigate `MsoHtmEd.exe` process creation events where the **command line contains a URL or UNC/WebDAV path** (e.g., `http(s)://…`,
`\\host\share\page.html`, `\\host@SSL\DavWWWRoot\x.html`). This indicates remote retrieval by a Microsoft-signed Office helper and
often precedes **INetCache** writes and potential follow-on execution via embedded scripts/objects.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** with `Image`, full `CommandLine`, `ParentImage`, `User`, integrity level, working dir, timestamp.  
2. **Parse source:** Extract **scheme/host/port/path**; distinguish **internal vs external**; flag **raw IPs**, **new domains**, **non-standard ports**.  
3. **Secure artifacts:** Snapshot **INetCache**/**%TEMP%** around the timestamp; copy & **hash** created files. Avoid opening in Office.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path/signature (Office install tree).  
- Inspect **parent** process for ingress vector (Outlook/Teams/browser → phish, Office app/macro, script hosts, scheduled tasks).  
- Note additional flags or hidden window execution hints.

#### 2) Source Semantics
- Confirm whether the path is **HTTP/HTTPS**, **WebDAV** (`DavWWWRoot`/`@SSL`), or **SMB UNC**.  
- Review URL query strings/redirectors; check if content points to **secondary payloads**.

#### 3) Network & DNS
- Correlate **Sysmon EID 3** (may be direct or proxied) and **proxy logs** (method/status/bytes, content-type).  
- Use **Sysmon EID 22** for DNS (or proxy FQDN in explicit proxy setups).  
- For **WebDAV**, expect egress via **WebClient** `svchost.exe` over **80/443**.

#### 4) Artifact Analysis
- Inspect **INetCache** writes: HTML/HTA/scriptlets, images with embedded content, archives.  
- Check **extension↔MIME** mismatches, **Zone.Identifier** ADS, **entropy**, and suspicious **strings/URLs**.  
- Identify any **child processes** spawned as a result (e.g., `mshta.exe`, `wscript.exe`, `rundll32.exe`, `powershell.exe`).

#### 5) Correlation & Fleet
- Pivot by **destination host**, **hashes** of cached files, and **CLI substrings** across endpoints to determine scope.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Command line with remote path and `ParentImage`.  
- **Sysmon EID 11:** INetCache / temp file writes.  
- **Sysmon EID 3 / Proxy:** HTTP(S)/WebDAV flows.  
- **Sysmon EID 22:** DNS lookups aligned with execution.  
- **EDR timeline:** Child processes and module loads.

### Containment Actions
- **Block** destination; **quarantine** artifacts; **terminate** activity; consider **host isolation** if execution occurred.

### Prevention Measures
- Egress filtering and **domain allowlists**; disable **WebClient** if unused.  
- AppLocker/WDAC to restrict direct invocation of Office helper binaries; alert on **rare process → URL** usage.

### Recovery
- Remove staged content/persistence; rotate credentials if exposed; tune detections; document deviations.

### False Positives
- Legacy intranet workflows where HTML content is legitimately opened from approved shares/portals via MsoHtmEd. Validate and allowlist.

---

## Playbook 2 — Outbound Network Activity (Sysmon EID 3)

### Overview
This playbook investigates **outbound connections** attributed to `MsoHtmEd.exe`. While local editing is expected, **direct egress** to **new/rare**
destinations, **raw IPs**, or **non-standard ports** is atypical and may indicate **T1105** staging or retrieval of remote HTML/script content.

### Initial Response
1. **Capture records:** Export **EID 3** (dest IP/host/port/proto) and correlate nearby **EID 1/4688** for `MsoHtmEd.exe`.  
2. **Classify destination:** Internal vs external; flag **raw IPs**, **recently observed** domains, **non-standard ports**.  
3. **Scope user/asset:** Determine whether the user normally uses this tool; often **not** expected in modern workflows.

### Investigation Steps
#### 1) Process & Command Context
- Retrieve full **command line** and **parent** to establish intent (phish/macro/script).  
- Check for **profile/working dir** pointing to temp or odd locations.

#### 2) Destination Validation
- Enrich domains/IPs (reputation/age); inspect **proxy** logs (method/status/bytes, content-type).  
- For WebDAV, pivot to **WebClient** telemetry; for SMB, validate **445** sessions and shares.

#### 3) Artifact Discovery
- Search for **EID 11** file writes in **INetCache**/temp; hash and classify.  
- Identify any **execution** of fetched artifacts by child processes.

#### 4) Correlation & Fleet
- Pivot on **destinations**, **hashes**, and **CLI** patterns; identify multi-host campaigns.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\MsoHtmEd.exe`, destination details.  
- **Sysmon EID 1 / 4688:** Process creation context.  
- **Sysmon EID 11:** File writes that follow the connection.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.

### Containment Actions
- **Block** suspicious endpoints; **quarantine** artifacts; **terminate** activity; consider **host isolation** on execution.

### Prevention Measures
- Restrict direct use of Office helpers; egress controls; monitor for **rare process → network** pairs.  
- Detect **Internet-zone** usage of legacy Office components.

### Recovery
- Remove artifacts/persistence; tune detections and allowlists; update runbooks.

### False Positives
- Approved enterprise systems rendering HTML from trusted internal portals with MsoHtmEd.

---

## Playbook 3 — FileCreate in INetCache (Sysmon EID 11)

### Overview
Investigate **file creations** where `MsoHtmEd.exe` writes under **INetCache** or **user‑writable** temp paths. This is commonly the result of
remote HTML/script retrieval and indicates **local staging** for subsequent use (**T1105**).

### Initial Response
1. **Secure artifacts:** Copy and **hash** created files; preserve timestamps/ACLs; avoid execution.  
2. **Trace lineage:** Correlate with `MsoHtmEd.exe` **EID 1/4688** and adjacent **EID 3/22** network activity.  
3. **Assess location & type:** Prioritize executable/script-like types (HTA/JS/VBS/CHM/PS1/LNK/EXE/DLL) and archives.

### Investigation Steps
#### 1) Artifact Inspection
- Determine true type (headers); check **extension↔MIME** mismatch and **entropy**; inspect **strings** for embedded URLs/keys.  
- Review **Zone.Identifier** ADS to confirm Internet origin and source URL if present.

#### 2) Process Context
- Retrieve original **command line** for the URL/UNC; analyze **parent** and user context.  
- Identify **child processes** that executed the created files within minutes.

#### 3) Network & DNS Corroboration
- Confirm downloads via **proxy** and **EID 3**; review **EID 22** DNS (or proxy FQDN in explicit proxies).

#### 4) Fleet & Follow‑On
- Pivot on **hashes/paths** and **source URLs** across endpoints; check for lateral re‑use.

### Key Artifacts
- **Sysmon EID 11:** `TargetFilename` written by `MsoHtmEd.exe` under **INetCache**/temp.  
- **Sysmon EID 1 / 4688:** Prior process creation with URL.  
- **Sysmon EID 3 & 22 / Proxy:** Corroborating network/DNS telemetry.  
- **EDR timeline:** Execution/use of staged artifacts.

### Containment Actions
- **Quarantine** files; **block** related domains/IPs; **terminate** process chains; consider **host isolation** if execution confirmed.

### Prevention Measures
- Application control for Office helpers; egress filtering; monitor **INetCache** writes by Office-signed utilities.  
- Disable **WebClient** when not required; enforce **ASR** rules for Office behaviors.

### Recovery
- Remove artifacts/persistence; rotate credentials if needed; tune detections/allowlists; update runbooks.

### False Positives
- Legacy intranet content rendering via MsoHtmEd from **approved** domains or shares; validate and allowlist.