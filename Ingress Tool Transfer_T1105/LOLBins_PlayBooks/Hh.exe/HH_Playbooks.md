# T1105 — Ingress Tool Transfer · LOLBin: Hh.exe (HTML Help)  
**Rules:**  
- CNC-E-2726320-156 — HH.exe Network Connection (Sysmon EID 3)  
- CNC-E-2726320-157 — HH.exe FileCreate (Sysmon EID 11)  
**Last updated:** 2025-10-28 05:55 UTC

> `Hh.exe` launches the Microsoft HTML Help viewer (`.chm`, `mk:@MSITStore:` URIs, and web URLs). Adversaries may abuse it to fetch remote
> content or invoke script/ActiveX inside CHM containers. This package focuses on **Ingress Tool Transfer (T1105)** indicators tied to **network activity**
> and **file creation** attributed to `hh.exe`.

---

## Playbook 1 — HH.exe Network Connection (Sysmon EID 3)

### Overview
Investigate cases where **`hh.exe`** establishes **outbound connections**. Normal help viewing often loads **local** CHM files; explicit **HTTP/HTTPS/WebDAV/UNC**
targets or unexpected egress from `hh.exe` can indicate **remote retrieval** of content/assets in support of **T1105**.

### Initial Response
1. **Capture records:** Export the **EID 3** event(s): destination IP/host/port/protocol and timestamps; correlate to nearby **process creation** (EID 1 / 4688).  
2. **Classify destination:** Internal vs external; treat **raw IPs**, **non‑standard ports**, and **new/rare domains** as high‑signal.  
3. **Scope user/asset:** Determine if the user/host is expected to open help content that requires network access (usually **rare** on workstations).

### Investigation Steps
#### 1) Process & Lineage
- Verify `Image` path (`C:\\Windows\\hh.exe`) and signer metadata.  
- Review `ParentImage` (e.g., Office, browser, script host, another LOLBin) and full `CommandLine`. Note patterns:  
  - `hh.exe <path>.chm` (local file)  
  - `hh.exe mk:@MSITStore:<path>.chm::/topic.htm`  
  - `hh.exe http(s)://host/...` or UNC/WebDAV `\\host\DavWWWRoot\...`
- Record working directory and integrity level.

#### 2) Destination Validation
- For **HTTP/HTTPS**, pivot to **proxy** logs (method, status, bytes, User‑Agent if available).  
- For **WebDAV UNC**, expect egress by **WebClient** `svchost.exe` on **80/443**; correlate with proxy telemetry.  
- For **SMB UNC**, corroborate with **SMB session** logs (port 445) and **logon type 3** events.  
- Enrich destination with reputation/age and compare to allowlists.

#### 3) Artifact Discovery
- Search for **file creation** (EID 11) temporally adjacent to the connection: cached HTML, scripts, images, or downloaded payloads.  
- Identify **CHM files** involved; compute **hashes** and extract/inspect content (look for embedded scripts/objects).

#### 4) Correlation & Follow‑On
- Hunt for **execution** of retrieved artifacts (e.g., `rundll32.exe`, `mshta.exe`, `wscript.exe`, `powershell.exe`) shortly after.  
- Run **fleet prevalence** for destination hosts, CHM hashes, and extracted file hashes.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\hh.exe`, destination host/IP/port.  
- **Sysmon EID 1 / 4688:** Launch context, `CommandLine`, parent, user.  
- **Sysmon EID 11:** Files written (cache, CHM copies, extracted content).  
- **Sysmon EID 22 / Proxy:** DNS lookups; HTTP details if proxied.  
- **AMSI/Script logs (if enabled):** Execution inside CHM hosting environments.

### Containment Actions
- **Block** suspicious destinations; **quarantine** CHM and any derived artifacts; **terminate** related processes.  
- Consider **host isolation** when execution/persistence is observed.

### Prevention Measures
- Disable **HTML Help** where not required or restrict CHM execution to **trusted paths**.  
- Egress filtering and **domain allowlists**; disable **WebClient** (WebDAV) if unused.  
- Application control (**AppLocker/WDAC**) to constrain `hh.exe` on non‑admin endpoints.

### Recovery
- Remove staged payloads; purge cached help content; rotate credentials if exposure suspected; update tuning and allowlists.

### False Positives
- Legitimate help systems that fetch **intranet** resources or vendor help from approved domains. Validate with owners/change tickets.

---

## Playbook 2 — HH.exe FileCreate (Sysmon EID 11)

### Overview
Investigate **file creations** where `hh.exe` is the actor. This may reflect **cached content**, **downloaded assets**, or **exported** data from CHM/web pages.
In malicious scenarios, adversaries may use `hh.exe` to **drop** payloads or supporting files as part of **T1105** workflows.

### Initial Response
1. **Secure artifacts:** Copy and **hash** created files; preserve timestamps and **owner**.  
2. **Link lineage:** Correlate with the initiating **process creation** (EID 1 / 4688) and any **network** events (EID 3).  
3. **Assess location:** Treat writes under **%TEMP%**, **%USERPROFILE%**, **Downloads**, **Public**, or app data as higher risk than system paths.

### Investigation Steps
#### 1) Artifact Inspection
- Determine **file type** (PE/script/archive/HTML) and check **extension ↔ MIME** consistency.  
- Inspect **strings**, **metadata**, and **entropy**; identify embedded **URLs**, **commands**, or **encoded blobs**.  
- If a **CHM** was involved, consider extracting its contents to review **HTML/JS/ActiveX** behavior.

#### 2) Process Context
- Retrieve `hh.exe` **command line** to identify the **source** (local CHM vs remote URL/UNC/WebDAV).  
- Confirm **ParentImage** and user context (interactive vs automated).  
- Identify whether the write was due to **save/export** actions, **cache**, or **scripted** behavior.

#### 3) Network & DNS Corroboration
- Check for **EID 3** involving `hh.exe` near the file creation time; for WebDAV, pivot to **WebClient** egress.  
- Review **EID 22** for destination lookups (or proxy FQDN in explicit‑proxy environments).  
- Examine **proxy** logs for HTTP transactions that could produce the file (content‑length/type).

#### 4) Follow‑On & Fleet
- Hunt for **execution** of the created file or downstream tool launches (PowerShell/mshta/wscript/rundll32).  
- Perform **fleet prevalence** on the file hash and source host to discover related activity.

### Key Artifacts
- **Sysmon EID 11:** `TargetFilename`, process image `hh.exe`.  
- **Sysmon EID 1 / 4688:** `CommandLine`, `ParentImage`, `User`.  
- **Sysmon EID 3 / 22:** Network/DNS corroboration for remote sources.  
- **EDR timeline:** Process graph and module loads referencing the new file.

### Containment Actions
- **Quarantine** created files and associated CHMs; **block** related destinations; **terminate** process chains.  
- Consider **host isolation** if execution/persistence follows.

### Prevention Measures
- Restrict CHM usage and **disable script/ActiveX** where possible; prefer **web‑based help** from approved domains.  
- Enforce **egress controls**, disable **WebClient** when not required, and apply **AppLocker/WDAC** policies.  
- Monitor for `hh.exe` writing into **user‑writable** locations and for **rare process → file‑write** patterns.

### Recovery
- Remove artifacts and persistence; clear cached help stores; update detections and allowlists; educate users on CHM risks.

### False Positives
- Vendor applications that legitimately render help and cache assets or export documentation to disk; validate by **ticket/owner** and **domain allowlist**.