# T1105 — Ingress Tool Transfer · LOLBin: Findstr.exe  
**Rules:**  
- CNC-E-2726320-148 — Findstr Remote File Download via UNC (Process Creation)  
- CNC-E-2726320-149 — Findstr Network Connection (Sysmon EID 3)  
**Last updated:** 2025-10-28 05:46 UTC

---

## Playbook 1 — Findstr Remote File Download via UNC (Process Creation)

### Overview
This playbook supports investigation of alerts where **`findstr.exe`** (the Windows search utility) is executed with **operands that read from a remote UNC path**
(e.g., `\\host\share\file`) and **redirect** output to a **local** path (e.g., `> out.bin`), effectively **copying** content using a trusted, ubiquitous binary.
Adversaries abuse this to perform **Ingress Tool Transfer (T1105)** while blending into admin/script noise.

### Initial Response
1. **Preserve context:** Export **process creation** (EID 1 / 4688) with `Image`, full `CommandLine`, `ParentImage`, `User`, integrity level, and timestamp.  
2. **Parse operands:** Identify the **remote input** (UNC/WebDAV) and **local output** (redirection `>` or `>>`).  
3. **Collect artifacts:** Acquire the **resulting local file** immediately (hash + copy) and preserve the **original remote path** details if accessible.  
4. **Baseline check:** Determine whether the device/user typically uses `findstr` in admin scripts; most endpoints **do not** read from UNC into local via redirection.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path (`C:\\Windows\\System32\\findstr.exe` or `SysWOW64`) and signer/metadata.  
- Review `ParentImage` for suspicious launch chains (script engines, Office, other LOLBins).  
- Note switches like `/R`, `/S`, `/N`, and confirm **operand order** indicating **read from remote → write local**.

#### 2) Command‑Line Semantics
- Confirm **remote operand** patterns:  
  - **SMB UNC:** `\\host\share\path\file`  
  - **WebDAV UNC:** `\\host\DavWWWRoot\...` or `\\host@SSL\DavWWWRoot\...` (HTTP/S under the hood)  
- Identify **redirection** targets and **write locations** (Temp/Public/Downloads/desktop). Treat **user‑writable** targets as high‑risk.

#### 3) File & Content Analysis
- Compute **hash** of the output file, determine **type** (PE/script/text/archive), and check **entropy** and **header** consistency.  
- Inspect for **encoded** blobs or **partial transfers** (zero‑byte or small files can indicate staging attempts).

#### 4) Network & DNS Corroboration
- For **SMB**, correlate **network logon (type 3)** and **SMB sessions** to the remote host (port 445).  
- For **WebDAV**, expect egress by **`svchost.exe`** (WebClient) over **80/443**; pivot to **proxy** logs for HTTP details.  
- **DNS (EID 22):** Queries for the remote host (or proxy FQDN in explicit‑proxy environments).

#### 5) Correlation & Follow‑On
- Search for **execution** of the downloaded file or adjacent tools (PowerShell, mshta, wscript, rundll32) within minutes.  
- Fleet‑wide, look for similar **UNC patterns** and **output file names** to scope the campaign.

### Key Artifacts
- **Sysmon EID 1 / 4688:** `Image=...\\findstr.exe`, full `CommandLine`, `ParentImage`, `User`.  
- **Sysmon EID 11:** Creation of the redirected **output file**.  
- **Sysmon EID 3 / Proxy:** Connections to the remote share (SMB) or WebDAV backend.  
- **Sysmon EID 22:** DNS queries related to the remote endpoint or proxy.

### Containment Actions
- **Quarantine** the output file; **block** the remote host; **terminate** the process chain; consider **host isolation** if execution occurred.

### Prevention Measures
- Disable **WebClient** where not required; enforce **egress filtering** and **domain allowlists**.  
- Apply **application control** to constrain LOLBin misuse; restrict execution from **user‑writable** paths.  
- Monitor for **rare process → UNC** pairs (e.g., `findstr.exe` reading from UNC).

### Recovery
- Remove staged payloads; clean up share mappings; rotate any exposed credentials; refine allowlists/tuning.

### False Positives
- Legitimate **admin scripts** that grep logs directly from internal SMB shares and redirect output for reporting. Validate via **tickets/owners**.

---

## Playbook 2 — Findstr Network Connection (Sysmon EID 3)

### Overview
This playbook addresses alerts where **`findstr.exe`** shows **network connections** (**Sysmon EID 3**), which is atypical for a simple text search tool.
When used with **UNC/WebDAV** operands, network I/O may be attributed to `findstr.exe` (for SMB) or to **WebClient `svchost.exe`** (for WebDAV),
indicating potential **Ingress Tool Transfer** activity.

### Initial Response
1. **Capture records:** Export **EID 3** for `findstr.exe` and correlate to **process creation** (EID 1/4688).  
2. **Classify destination:** Internal vs external; **raw IPs**, **non‑standard ports**, and **new domains** are high‑signal.  
3. **Scope usage:** Determine whether UNC/WebDAV reads by `findstr.exe` are expected for this user/device.

### Investigation Steps
#### 1) Process & Lineage
- Verify `Image` path/signature; review `ParentImage` and command line for **UNC/WebDAV** indicators and **redirection**.  
- Confirm working directory and **write target** (if redirection occurred).

#### 2) Destination Validation
- For **SMB**, corroborate **port 445** sessions and **logon type 3** events; enumerate share and path accessed.  
- For **WebDAV**, pivot to **WebClient svchost.exe** egress and **proxy** telemetry; confirm **HTTP method**, **status**, **size**.  
- Enrich the destination and compare to **allowlists**.

#### 3) Artifact Discovery
- Locate **local files** created around the connection time (redirection outputs); hash and analyze (type/entropy/strings).  
- Check for **execution** of outputs or subsequent tool launches.

#### 4) Correlation & Follow‑On
- Hunt for sibling LOLBins/interpreters invoked soon after (PowerShell, mshta, wscript, rundll32).  
- Run **fleet prevalence** on destination hosts and file hashes to find other affected endpoints.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\findstr.exe`, destination details.  
- **Sysmon EID 1 / 4688:** Launch context and command line (UNC/WebDAV indicators).  
- **Sysmon EID 11:** File writes caused by redirection.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.

### Containment Actions
- **Block** destination; **quarantine** artifacts; **terminate** related processes; consider **host isolation** if execution seen.

### Prevention Measures
- Egress filtering & **domain allowlists**; restrict rare utilities via **AppLocker/WDAC**.  
- Disable **WebClient** where not needed; baseline **SMB shares** and alert on new/rare share access by `findstr.exe`.

### Recovery
- Remove payloads and persistence; tune detections and allowlists; document deviations.

### False Positives
- Admin/reporting workflows that read large logs from internal UNC shares during maintenance windows.  
- Mitigate by allowlisting **approved shares/domains** and validating **change records**.