# T1105 — Ingress Tool Transfer · LOLBin: Extrac32.exe  
**Rules:**  
- CNC-E-2726320-146 — Extrac32 UNC Copy or Extraction (Process Creation)  
- CNC-E-2726320-147 — Extrac32 Network Connection (Sysmon EID 3)  
**Last updated:** 2025-10-28 05:45 UTC

---

## Playbook 1 — Extrac32 UNC Copy or Extraction (Process Creation)

### Overview
This playbook supports investigation of alerts where **`extrac32.exe`** (Windows CAB extraction utility) is launched with command‑line
indicators of **copying/extracting from or to UNC/WebDAV paths**. Adversaries may leverage `extrac32.exe` to **stage** or **unpack**
payloads retrieved from remote locations, enabling **Ingress Tool Transfer (T1105)** and immediate **execution** of extracted content.

### Initial Response
1. **Preserve context:** Export the **process creation** (EID 1 / 4688) for `extrac32.exe` (image, command line, parent, user, IL, timestamp).  
2. **Parse operands:** Identify the **source CAB** and **destination path**. Note UNC/WebDAV patterns:  
   - SMB UNC: `\\host\share\...`  
   - WebDAV UNC: `\\host\DavWWWRoot\...` or `\\host@SSL\DavWWWRoot\...`  
3. **Collect artifacts:** Acquire the **CAB** and **extracted files** immediately (hashes + copies).  
4. **Baseline check:** Determine whether this endpoint/user normally performs CAB operations.

### Investigation Steps
#### 1) Process & Lineage
- Verify `Image` path (e.g., `C:\\Windows\\System32\\extrac32.exe`) and signer/metadata.  
- Review `ParentImage` for suspicious launch chains (script engines, Office, other LOLBins).  
- Record **switches** (e.g., `/Y` overwrite), redirections, and working directory.

#### 2) Command‑Line Semantics
- Confirm **source** (CAB or compressed file) and **destination** (folder or file).  
- Flag **user‑writable** destinations (`%TEMP%`, `%PUBLIC%`, `Downloads`, Desktop).  
- Elevate priority for **raw IPs**, **non‑standard ports** embedded via UNC/WebDAV endpoints.

#### 3) File & Content Analysis
- Compute **hashes** for the CAB and extracted files; enumerate contents (file names, types, sizes).  
- Look for **executable/script** content, **extension mismatch**, **high entropy**, or **uncommon DLL/EXE names**.  
- Identify any **auto‑execution** patterns post‑extraction (e.g., MSI install chains, DLL side‑loads).

#### 4) Network & DNS Corroboration
- If **UNC/WebDAV** involved, corroborate:  
  - **SMB telemetry** (port 445) and **Logon Type 3** for SMB shares.  
  - **WebClient svchost.exe** egress on **80/443** and **proxy** logs for WebDAV (host/path/status/size).  
- **DNS (EID 22):** Queries to involved hosts (or proxy FQDN in explicit‑proxy environments).

#### 5) Correlation & Follow‑On
- Hunt for **execution** of extracted files (child of `extrac32.exe` or shortly after).  
- Pivot to sibling LOLBins: `powershell.exe`, `rundll32.exe`, `regsvr32.exe`, `mshta.exe`.  
- Perform **fleet prevalence** for destination hosts and extracted file hashes.

### Key Artifacts
- **Sysmon EID 1 / 4688:** `Image=...\\extrac32.exe`, full `CommandLine`, `ParentImage`, `User`.  
- **Sysmon EID 11:** Extracted file writes and resulting paths.  
- **Sysmon EID 3 / Proxy:** Network connections for UNC/WebDAV sources/destinations.  
- **Sysmon EID 22:** DNS queries associated with remote endpoints.  
- **EDR timeline:** Process lineage and module loads tied to extracted content.

### Containment Actions
- **Quarantine** the CAB and extracted files; **block** the remote host; **terminate** related processes; consider **host isolation** if execution occurred.

### Prevention Measures
- Disable **WebClient** where not required; enforce **egress filtering** and **domain allowlists**.  
- Apply **application control** (AppLocker/WDAC) to restrict CAB tools on non‑admin endpoints.  
- Prevent execution from **user‑writable** paths; monitor **rare process → UNC** patterns.

### Recovery
- Remove staged payloads and persistence; clean up share mappings; rotate any exposed credentials.  
- Update tuning (approved shares/hosts) and IR runbooks.

### False Positives
- Legitimate deployment/driver servicing that extracts CABs from **approved internal** shares. Validate with **tickets** and **owners**.

---

## Playbook 2 — Extrac32 Network Connection (Sysmon EID 3)

### Overview
This playbook addresses alerts where **`extrac32.exe`** shows **network connections** (**Sysmon EID 3**), indicating remote source or destination
interaction during extraction/copy. Since `extrac32.exe` normally operates on local files, **process‑attributed** network activity is notable and
potentially indicative of **T1105** workflows using **SMB** or **WebDAV** backends.

### Initial Response
1. **Capture records:** Export the **EID 3** (dest IP/host/port) and link to **process creation** (EID 1/4688).  
2. **Classify destination:** Internal vs external; **new domains**, **raw IPs**, **non‑standard ports** are high‑signal.  
3. **Scope:** Determine if the endpoint/user is expected to interact with remote CAB sources.

### Investigation Steps
#### 1) Process & Lineage
- Confirm `Image` path/signature; review `ParentImage` and `CommandLine` for **UNC/WebDAV** indicators.  
- Note working directory and any **output** targets.

#### 2) Destination Validation
- For **SMB UNC**, corroborate **SMB sessions** and **type 3 logons**; identify the **share paths**.  
- For **WebDAV**, pivot to **WebClient svchost.exe** egress and **proxy** logs; confirm **HTTP method**, **status**, **response size**.  
- Enrich domains/IPs and compare to **allowlists**.

#### 3) Artifact Discovery
- Locate **extracted files** (EID 11) near the connection time; hash and analyze (type/entropy/strings).  
- Check for **execution** of outputs (child processes or shortly after extraction).

#### 4) Correlation & Follow‑On
- Search for adjacent LOLBins or interpreters executing the extracted content.  
- Run **fleet prevalence** for destination hosts and file hashes; identify other impacted systems.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\extrac32.exe`, destination details.  
- **Sysmon EID 1 / 4688:** Launch context and command line.  
- **Sysmon EID 11:** File writes due to extraction.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.

### Containment Actions
- **Block** destination; **quarantine** artifacts; **terminate** related processes; consider **host isolation** if execution is confirmed.

### Prevention Measures
- Egress filtering and **domain allowlists**; restrict rare utilities via **AppLocker/WDAC**.  
- Monitor for **WebDAV** usage and disable **WebClient** where not required; baseline approved SMB shares.

### Recovery
- Remove payloads and persistence; tune detections and allowlists; document deviations.

### False Positives
- Authorized operations reading CABs from internal repositories over SMB/WebDAV during **approved** windows.