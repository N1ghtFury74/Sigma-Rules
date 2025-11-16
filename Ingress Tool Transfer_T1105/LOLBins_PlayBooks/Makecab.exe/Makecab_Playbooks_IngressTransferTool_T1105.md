# T1105 — Ingress Tool Transfer · LOLBin: Makecab.exe  
**Rules:**  
- CNC-E-2726320-168 — Makecab Download and CAB Creation (Process Creation)  
- CNC-E-2726320-168 — Makecab Network Connection (Sysmon EID 3)  
**Last updated:** 2025-10-28 06:07 UTC

> `makecab.exe` (a.k.a. **Diantz**) is a Microsoft cabinet creation utility. Adversaries abuse it to **pull files from UNC/WebDAV/HTTP sources**
> (via command line or DDF input) and **package** them into a CAB for staging. This can masquerade as benign compression while enabling
> **Ingress Tool Transfer (T1105)** and follow-on execution from user‑writable locations.

---

## Playbook 1 — Makecab Download and CAB Creation (Process Creation)

### Overview
Investigate alerts where **`makecab.exe`** is launched with **remote inputs** (UNC/WebDAV/HTTP) and an **output CAB** destination (e.g., `payload.cab`).
Attackers may specify a **DDF** (Directive Definition File) that contains **.Set** and **Source** statements pointing to remote paths.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** for `makecab.exe` (image, full command line, parent, user, IL, working dir, timestamp).  
2. **Identify inputs/outputs:** Parse the **source file(s)** (direct on CLI or via **/f DDF**) and the **output CAB** (`/D CompressionType`, `/V` verbosity).  
3. **Collect artifacts:** Acquire the **CAB**, **DDF**, and any referenced **source files** if locally staged.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path (`C:\\Windows\\System32\\makecab.exe` or `SysWOW64`) and signer metadata.  
- Review `ParentImage` for suspicious chains (PowerShell, cmd, wscript, Office, other LOLBins).  
- Note arguments: `/f <DDF>`, explicit source → destination pairs (`makecab <src> <dst.cab>`), logging switches.

#### 2) Input Semantics
- Remote **source** patterns to flag:  
  - **SMB UNC:** `\\host\share\path\file`  
  - **WebDAV UNC:** `\\host\DavWWWRoot\...` or `\\host@SSL\DavWWWRoot\...`  
  - **HTTP/HTTPS:** sometimes via pre‑staging script; if present directly in DDF (`Source= http(s)://...`), treat as high‑risk.  
- Inspect **DDF** for `.Set CabinetNameTemplate`, `.Set DestinationDir`, and multiple **Source** lines (bulk staging).

#### 3) Artifact & Content Analysis
- Hash the **CAB**; list members (`expand -D` or forensic unpack) and determine file types (PE/script/archive/config).  
- Check for **extension ↔ MIME** mismatch and **entropy** anomalies indicating packed/encrypted payloads.

#### 4) Network & DNS Corroboration
- For **SMB**, correlate **port 445** sessions and **logon type 3** events.  
- For **WebDAV**, network may attribute to **WebClient** `svchost.exe` on **80/443**; pivot to **proxy** logs.  
- For **HTTP/HTTPS**, use **proxy** logs for method/status/bytes; **Sysmon EID 22** for DNS (or proxy FQDN with explicit proxy).

#### 5) Correlation & Follow‑On
- Hunt for **extraction** (`expand.exe`) and **execution** of CAB members (PowerShell, mshta, wscript, rundll32) within minutes.  
- Fleet‑wide, pivot on **CAB hash**, **DDF name**, and **destination host** to find related activity.

### Key Artifacts
- **Sysmon EID 1 / 4688:** `Image=...\\makecab.exe`, `CommandLine`, `ParentImage`, `User`.  
- **Sysmon EID 11:** Creation of the **.cab** output and any temporary files.  
- **Sysmon EID 3 / Proxy:** Connections for remote sources (SMB/WebDAV/HTTP).  
- **Sysmon EID 22:** DNS lookups aligned with execution.  
- **DDF content:** `.Set` directives and `Source` entries.

### Containment Actions
- **Quarantine** the CAB and extracted members; **block** remote sources; **terminate** related process chains.  
- Consider **host isolation** if execution of payloads occurred.

### Prevention Measures
- Egress filtering & domain allowlists; disable **WebClient** where unused.  
- Application control (**AppLocker/WDAC**) to restrict `makecab.exe` usage on workstations.  
- Monitor for **rare process → CAB creation** in **user‑writable** paths.

### Recovery
- Remove staged payloads/persistence; tune detections and allowlists; rotate exposed credentials if found in packaged configs.

### False Positives
- Legitimate **packaging** by IT teams using `makecab` with **local** sources for driver/hotfix distribution. Validate via change records and owners.

---

## Playbook 2 — Makecab Network Connection (Sysmon EID 3)

### Overview
This playbook covers alerts where **`makecab.exe`** exhibits **outbound network connections**. While `makecab` is typically local, remote **UNC/WebDAV**
sources (directly or via DDF) can drive **SMB/WebDAV/HTTP** egress — a sign of potential **T1105** staging.

### Initial Response
1. **Capture records:** Export **EID 3** (dest host/IP/port) and correlate to nearby **EID 1/4688** for `makecab.exe`.  
2. **Classify destination:** Internal vs external; prioritize **raw IPs**, **new domains**, and **non‑standard ports**.  
3. **Scope usage:** Determine whether `makecab` is expected on the asset and if remote packaging is standard (usually **no**).

### Investigation Steps
#### 1) Process & Command Context
- Verify `Image` path/signature; retrieve full `CommandLine` and **DDF** references.  
- Identify the **output CAB** path; check for writes under **%TEMP%**, **Downloads**, **Public**, **AppData**.

#### 2) Destination Validation
- **SMB UNC:** Validate **445** sessions and enumerate shares/paths accessed.  
- **WebDAV UNC:** Expect **WebClient** egress; pivot to **proxy** for HTTP details.  
- **HTTP/HTTPS:** Review proxy logs (method/status/bytes); enrich the destination reputation/age and compare with allowlists.

#### 3) Artifact Discovery
- Search for **file creations** (EID 11) including **CABs** and temp files; hash and unpack to identify staged content.  
- Look for follow‑on **extraction/execution** events (e.g., `expand.exe`, `powershell.exe`, `rundll32.exe`).

#### 4) Correlation & Fleet
- Pivot on **destination**, **CAB hash/name**, and **DDF** across endpoints to assess spread and operator TTPs.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\makecab.exe`, destination details.  
- **Sysmon EID 1 / 4688:** Launch context and `CommandLine`.  
- **Sysmon EID 11:** CAB/temporary file writes.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.  
- **DDF files:** Source directives indicating remote pulls.

### Containment Actions
- **Block** destination; **quarantine** CABs and extracted files; **terminate** related activity; consider **host isolation** on execution.

### Prevention Measures
- Enforce **egress controls**; disable **WebClient** when not needed; restrict `makecab.exe` via **application control**.  
- Monitor **rare process → network** pairs and **Internet‑zone** sourcing for packaging utilities.

### Recovery
- Remove artifacts/persistence; tune detections and allowlists; document deviations in runbooks.

### False Positives
- Approved internal packaging workflows that temporarily source files from **intranet shares**. Mitigate by allowlisting known hosts/paths.