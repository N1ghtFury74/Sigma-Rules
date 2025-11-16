# T1105 — Ingress Tool Transfer · LOLBin: ECMangen.exe  
**Rules:**  
- CNC-E-2726320-174 — ECMangen URL in Command Line (Process Creation)  
- CNC-E-2726320-175 — ECMangen Outbound Network Connection (Sysmon EID 3)  
- CNC-E-2726320-176 — ECMangen DNS Activity (Sysmon EID 22)  
**Last updated:** 2025-10-28 04:33 UTC

---

## Playbook 1 — ECMangen URL in Command Line (Process Creation)

### Overview
This playbook supports investigation of alerts where **`ECMangen.exe`** is executed with a **URL embedded in the command line**.  
Although `ECMangen.exe` is a signed Microsoft utility that is **rarely used on typical endpoints**, adversaries can abuse it as a
**living‑off‑the‑land** downloader to **fetch** or **interact** with remote resources, enabling **Ingress Tool Transfer (T1105)**.

### Initial Response
1. **Preserve context:** Export the full **process creation** event (`Image`, `CommandLine`, `ParentImage`, `User`, timestamp, integrity level).  
2. **Extract destination:** Parse **scheme/host/port/path** from the URL; note **raw IPs**, **non‑standard ports**, or **new domains**.  
3. **Collect artifacts:** Identify any **output files** or inferred write locations; acquire immediately (hash + copy).  
4. **Baseline check:** Determine whether `ECMangen.exe` is expected on this device/user (generally **no** for most workstations).

### Investigation Steps
#### 1) Process & Image Analysis
- Verify `Image` path and signer/metadata; ensure it is the Microsoft binary (detect renames or LOLBIN proxying).  
- Review `ParentImage` for suspicious launch chains (e.g., script engines, Office, other LOLBins).  
- Document **all switches/operands** and working directory.

#### 2) Command‑Line Semantics
- Confirm whether the URL implies **download** (HTTP/HTTPS) or **WebDAV UNC** usage (which routes through **WebClient**).  
- Record **output paths**, redirections, or temp locations; flag **user‑writable** destinations (Temp/Downloads/Public).

#### 3) Network & DNS Corroboration
- **DNS (EID 22):** Lookups for the destination host (or **proxy FQDN** in explicit‑proxy setups).  
- **Network (EID 3 / Proxy):** Egress tied to `ECMangen.exe`; if WebDAV UNC, expect traffic from **`svchost.exe` (WebClient)**.  
- Confirm **method** (GET/POST), **status**, and **response size** via proxy logs if available.

#### 4) Correlation & Follow‑On
- Hunt for **file creation** (EID 11) near the time of the process event; inspect artifacts (type, entropy, strings).  
- Search for **follow‑on execution** of retrieved files (e.g., `powershell.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`).  
- Perform **fleet prevalence** on the URL/domain/IP and any hashes identified.

### Key Artifacts
- **Process Creation (EID 1 / 4688):** `Image=...\ECMangen.exe`, full `CommandLine`, `ParentImage`, `User`.  
- **File Creation (EID 11):** `TargetFilename` written by `ECMangen.exe` or subsequent tools.  
- **DNS (EID 22):** `QueryName` to destination (or proxy FQDN).  
- **Network (EID 3 / Proxy):** Destination IP/host/port and HTTP details.

### Containment Actions
- **Quarantine** staged files; **block** destination domain/IP; **terminate** related processes.  
- Consider **host isolation** if follow‑on execution or persistence is observed.

### Prevention Measures
- Enforce **egress filtering** and **domain allowlists**; restrict seldom‑used Windows utilities via **AppLocker/WDAC**.  
- Prevent execution from **user‑writable** paths; enable **AMSI/script** telemetry for downstream tools.

### Recovery
- Remove retrieved payloads and any persistence; update allowlists and detection tuning; document deviations.

### False Positives
- Uncommon: internal engineering/diagnostics invoking `ECMangen.exe` with URLs under change‑controlled windows. Validate with owners/tickets.

---

## Playbook 2 — ECMangen Outbound Network Connection (Sysmon EID 3)

### Overview
This playbook covers alerts where **`ECMangen.exe`** establishes **outbound connections** (Sysmon **EID 3**).  
While the binary is not typically network‑chatty in normal enterprise use, adversaries can repurpose it to reach remote hosts as part of **T1105**.

### Initial Response
1. **Capture records:** Export the **EID 3** event (dest host/IP/port) and link to nearby **process creation** (EID 1/4688).  
2. **Classify destination:** Internal vs external; **new domains**, **raw IPs**, **non‑standard ports** are high‑signal.  
3. **Scope:** Identify whether the host/user has legitimate reasons to run `ECMangen.exe`.

### Investigation Steps
#### 1) Process & Lineage
- Confirm `Image` path/signature; review `ParentImage` and command line for **URL/UNC** indicators.  
- Check working directory and potential **output** or **input** operands.

#### 2) Destination Validation
- Enrich domain/IP reputation and age; compare against **allowlists**.  
- If **WebDAV UNC** suspected, pivot to **WebClient** `svchost.exe` egress and proxy telemetry.

#### 3) Artifact Discovery
- Search for **file creations** around the connection window (Temp/Downloads/Public).  
- Hash and analyze any new artifacts; assess content type and potential execution.

#### 4) Correlation & Follow‑On
- Look for **subsequent executions** of new files; pivot to sibling LOLBins (PowerShell, mshta, wscript).  
- Run **fleet prevalence** for destination and hashes.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\ECMangen.exe`, destination fields.  
- **Sysmon EID 1 / 4688:** Launch context and command line.  
- **Sysmon EID 11:** File writes attributed to `ECMangen.exe`.  
- **Sysmon EID 22 / Proxy:** DNS queries and HTTP(S) details if available.

### Containment Actions
- **Block** destination; **terminate** related processes; quarantine artifacts; consider **isolation** on execution.

### Prevention Measures
- Egress filtering and **domain allowlists**; restrict rare utilities with **AppLocker/WDAC**.  
- Monitor for **WebDAV** usage and disable **WebClient** where not required.

### Recovery
- Remove payloads and persistence; update tuning and runbooks; re‑baseline allowlists.

### False Positives
- Rare admin/engineering workflows performing remote interactions; validate with tickets/owners and approved domains.

---

## Playbook 3 — ECMangen DNS Activity (Sysmon EID 22)

### Overview
This playbook supports alerts where **`ECMangen.exe`** issues **DNS lookups** (**EID 22**).  
Process‑attributed DNS for this binary is unusual on typical endpoints and may indicate **remote fetch attempts** consistent with **T1105**.

### Initial Response
1. **Record details:** Export the DNS query (`QueryName`, response IPs) and correlate to nearby **process creation** and **network** events.  
2. **Assess destination:** Determine whether the queried host is **approved**, **newly seen**, or a **raw IP** string in other logs.  
3. **Scope usage:** Validate whether `ECMangen.exe` is expected on the device/user.

### Investigation Steps
#### 1) Process Linkage
- Associate **EID 22** with a recent `ECMangen.exe` **EID 1/4688**. Inspect command line for **URL**/remote indicators.  
- If an explicit proxy is configured, the client may only resolve the **proxy FQDN**; pivot to proxy logs for the **ultimate** destination.

#### 2) Destination Intelligence
- Enrich domain (WHOIS, age, category); check **fleet prevalence** and **new‑domain** heuristics.  
- Flag domains with **non‑enterprise TLDs**, **DDNS**, or **brand look‑alikes**.

#### 3) Artifact & Activity Correlation
- Search for **file creation** (EID 11) and **network connections** (EID 3) shortly after the DNS query.  
- Hunt for **follow‑on execution** of any retrieved files.

### Key Artifacts
- **Sysmon EID 22:** Process‑attributed DNS queries (`Image=...\ECMangen.exe`).  
- **Sysmon EID 1 / 4688:** Launch context and command line.  
- **Sysmon EID 3 / Proxy:** Egress details to resolved IP/host.  
- **Sysmon EID 11:** Files fetched or created adjacent to the query.

### Containment Actions
- **Sinkhole/block** the destination; quarantine artifacts; **terminate** related activity; consider **host isolation** if needed.

### Prevention Measures
- Maintain **allowlists** for trusted domains; alert on **rare process → DNS** pairs (like ECMangen).  
- Enforce **application control** and review **proxy exceptions** to prevent misuse.

### Recovery
- Remove staged payloads; tune detections; update allowlists and IR documentation.

### False Positives
- Very uncommon: internal engineering tools leveraging ECMangen in lab environments. Validate with owners and change records.