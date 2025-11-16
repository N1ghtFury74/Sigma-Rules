# T1105 — Ingress Tool Transfer · LOLBin: Esentutl.exe  
**Rules:**  
- CNC-E-2726320-145 — Esentutl UNC-to-UNC Connection (Sysmon EID 3)  
- CNC-E-2726320-144 — Esentutl UNC-to-UNC File Copy (Process Creation · Very Noisy)  
**Last updated:** 2025-10-28 05:43 UTC

---

## Playbook 1 — Esentutl UNC-to-UNC Connection (Sysmon EID 3)

### Overview
This playbook supports investigation of alerts where **`esentutl.exe`** is associated with **outbound network connections** (**Sysmon EID 3**),
particularly when the binary participates in **UNC-to-UNC** copy/stream operations. While `esentutl.exe` is a legitimate database utility
(ESENT), adversaries have abused it to **copy** files across **UNC paths** (SMB/WebDAV), enabling **Ingress Tool Transfer (T1105)** without
dropping custom tools.

### Initial Response
1. **Preserve context:** Export the **EID 3** record (dest IP/host/port, protocol) and link it to nearby **process creation** (EID 1 / 4688) for `esentutl.exe`.  
2. **Extract destination:** Classify the remote endpoint as **internal** vs **external**; flag **raw IPs**, **new domains**, and **non‑standard ports**.  
3. **Assess asset role:** Determine if the host/user is expected to run ESENT maintenance; most endpoints should **not** do UNC-to-UNC copies via `esentutl.exe`.

### Investigation Steps
#### 1) Process & Lineage
- Confirm `Image` path (typically `C:\\Windows\\System32\\esentutl.exe`) and signer metadata.  
- Review `ParentImage` and `CommandLine` for **streaming/copy semantics** between two paths.  
- Inspect working directory and any **redirections** (e.g., `>`/`>>`).

#### 2) Destination Validation
- For **SMB UNC** (`\\\\host\\share\\...`), corroborate **SMB sessions** and **Security logon type 3** events.  
- For **WebDAV UNC** (`\\\\host\\DavWWWRoot\\...`, `\\\\host@SSL\\DavWWWRoot\\...`), expect egress via **WebClient** `svchost.exe` over **80/443** and pivot to proxy logs.  
- Enrich host reputation and compare with **allowlists**.

#### 3) Artifact Discovery
- Enumerate **file writes** or **reads** adjacent to the connection window; identify **source/destination** pairs if possible.  
- Hash and inspect any **resultant files**; determine **file types** and **risk**.

#### 4) Correlation & Follow‑On
- Search for subsequent execution of transferred content (child of `esentutl.exe` or launched shortly after).  
- Pivot to sibling LOLBins (`powershell.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`) within minutes of the transfer.  
- Perform **fleet prevalence** for the UNC endpoints and any hashes involved.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\esentutl.exe`, `DestinationIp`, `DestinationPort`, `Protocol`.  
- **Sysmon EID 1 / Security 4688:** `Image`, full `CommandLine`, `ParentImage`, `User`.  
- **Sysmon EID 11:** File creations attributable to `esentutl.exe`.  
- **Sysmon EID 22 / Proxy:** DNS queries, proxy FQDN, HTTP(S) details for WebDAV flows.  
- **SMB telemetry:** Session/mapping evidence for UNC usage.

### Containment Actions
- **Block** suspicious destinations; **terminate** the transfer job; **quarantine** transferred artifacts; consider **host isolation** on execution.  

### Prevention Measures
- Restrict **WebClient** (WebDAV) where unnecessary; enforce **egress filtering**.  
- Apply **application control** (AppLocker/WDAC) to limit LOLBin abuse; monitor for **UNC-to-UNC** patterns.  
- Harden **SMB** access; restrict write to high‑risk, user‑writable paths.

### Recovery
- Remove staged payloads; clean up mappings; rotate credentials used; update allowlists and tuning.

### False Positives
- Rare **admin maintenance** that legitimately copies via UNC using `esentutl.exe`. Validate **tickets**, **owners**, and **approved shares**.

---

## Playbook 2 — Esentutl UNC-to-UNC File Copy (Process Creation · Very Noisy)

### Overview
This playbook covers alerts where **`esentutl.exe`** launches with **command lines** indicating **file copy between two UNC paths**
(e.g., `esentutl.exe /y \\\\src\\share\\file /d \\\\dst\\share\\file`). This method can be noisy but is a known **living‑off‑the‑land**
technique to move content through SMB/WebDAV in support of **T1105**.

### Initial Response
1. **Capture records:** Export **process creation** (EID 1 / 4688) for `esentutl.exe` and any **file creation** (EID 11) on the destination path.  
2. **Collect artifacts:** Acquire the **destination file** and compute **hashes**; preserve timestamps and **access patterns**.  
3. **Classify endpoints:** Determine whether **source** and **destination** UNC shares are **internal, approved** locations.

### Investigation Steps
#### 1) Command‑Line Semantics
- Parse for `/y` (copy from), `/d` (destination), `/o` or other switches (`/v`, `/t`, `/r`) as defined by usage; confirm **direction** and **operands**.  
- Validate that **both operands are UNC**; note any **DavWWWRoot/@SSL** WebDAV indicators.  
- Record **user**, **integrity level**, and **working directory**.

#### 2) File & Path Analysis
- Inspect the **destination** artifact: type (PE/script/text), size, entropy, extension mismatch, and strings.  
- Assess write location (Temp/Downloads/Public/user profile); higher risk if **user‑writable**.  
- Identify **subsequent reads/executes** of the new file.

#### 3) Network & DNS Corroboration
- Review **SMB telemetry** (port 445) for both **source** and **destination** servers; confirm **logon type 3** events.  
- If WebDAV, correlate **WebClient svchost.exe** egress on **80/443** and **proxy** logs for host/path/status.  
- **DNS (EID 22):** Queries to involved hosts (or proxy FQDN in explicit‑proxy environments).

#### 4) Correlation & Follow‑On
- Look for downstream tools (PowerShell, mshta, wscript, rundll32) executing the transferred file.  
- Pivot on **fleet prevalence** for the UNC paths and the file hash; identify additional affected systems.

### Key Artifacts
- **Sysmon EID 1 / 4688:** `Image=...\\esentutl.exe`, `CommandLine` with **UNC-to-UNC** operands.  
- **Sysmon EID 11:** Destination file write.  
- **Sysmon EID 3 / SMB logs:** Connections involving the source/destination hosts.  
- **Sysmon EID 22 / Proxy:** DNS queries and HTTP(S) details for WebDAV.

### Containment Actions
- **Quarantine** the destination file; **block** the UNC/WebDAV endpoints; terminate process chain; consider **host isolation** on execution.

### Prevention Measures
- Disable **WebClient** where not needed; enforce **egress filtering**; restrict execution from **user‑writable** paths.  
- Monitor for **UNC-to-UNC** operations by rare binaries (like `esentutl.exe`) and require admin-only usage.

### Recovery
- Remove staged payloads and any persistence; clean up share mappings; reset compromised credentials.  
- Update detection tuning and allowlists based on approved workflows.

### False Positives
- Legitimate **data migration** or **backup** procedures using `esentutl.exe` between trusted internal shares. Validate with **change records** and **owners**.