# T1105 — Ingress Tool Transfer · LOLBin: CMDL32.exe  
**Rules:**  
- CNC-E-2726320-136 — CMDL32 VPN/LAN Switches (Process Creation)  
- CNC-E-2726320-137 — CMDL32 FileCreate in %TMP% as `VPN_*.tmp` (File Creation)  
**Last updated:** 2025-10-28 04:24 UTC

---

## Playbook 1 — CMDL32 VPN/LAN Switches (Process Creation)

### Overview
This playbook supports investigation of alerts where **`cmdl32.exe`** is launched with **VPN/LAN mode switches**. 
In adversarial hands, Connection Manager–style tooling can be abused to **pull remote configuration**, establish **network tunnels**, 
or **stage small artifacts** over enterprise egress paths, providing a foothold for **Ingress Tool Transfer (T1105)** and command-and-control setup.

### Attack Context
- **Technique:** T1105 — Ingress Tool Transfer  
- **Binary:** `cmdl32.exe` (built-in Windows component)  
- **Behavioral cues (indicative, rule-driven):** Presence of **VPN/LAN switching arguments** on the command line; 
  immediate follow-on file writes under **temporary paths**; subsequent connections to external infrastructure.

### Initial Response
1. **Preserve context:** Export the full **process creation** record (image, command line, parent, user, integrity level, timestamps).  
2. **Extract intent:** Identify the **mode switches** (VPN vs LAN) and any embedded **paths, URLs, or profile references**.  
3. **Contain risk:** If an unexpected tunnel/profile is implied, coordinate with **network** and **VPN** owners to check live sessions.

### Investigation Steps

#### 1) Process and Image Analysis
- Validate `Image` path (e.g., `C:\Windows\System32\cmdl32.exe`) and **OriginalFileName** if available.  
- Review **`ParentImage`** for suspicious launch chains (script hosts, Office apps, other LOLBins).  
- Record **command-line switches** and any **file/profile** parameters; note **user context** (interactive vs service).

#### 2) File & Path Analysis
- Enumerate files created/modified around the time of execution in **%TEMP%**, **%ProgramData%**, user profile dirs.  
- Look for **connection/profile artifacts**, logs, or **temporary files** written by `cmdl32.exe`.

#### 3) Network & DNS Corroboration
- Check per-process **DNS** (endpoint EID 22) and **network** (EID 3 / proxy) activity correlating to the execution time.  
- If a **VPN** session is suspected, confirm whether a new **interface/session** was created (host telemetry, RAS/VPN logs).  
- Identify **destination domains/IPs**, **non-standard ports**, or **raw IP** usage.

#### 4) Correlation & Follow‑On Activity
- Search for **subsequent tool launches** (e.g., PowerShell, wscript, mshta) that may use downloaded/staged data.  
- Review **fleet prevalence** for the same command line, destination, or artifacts; identify additional impacted systems.

### Key Artifacts
- **Process Creation (EID 1 / 4688):** `Image=...\cmdl32.exe`, full `CommandLine`, `ParentImage`, `User`.  
- **File Creation (EID 11):** New files written by `cmdl32.exe` in temp/profile locations.  
- **DNS (EID 22):** Queries to the implicated host(s).  
- **Network (EID 3 / Proxy/VPN logs):** Connections and any newly established VPN sessions or adapters.  
- **EDR timeline:** Parent/child graph showing follow-on execution.

### Containment Actions
- Terminate the **cmdl32.exe** process chain; **revoke** or **disconnect** any unauthorized VPN sessions.  
- **Quarantine** downloaded/staged files and **block** external destinations.

### Prevention Measures
- Restrict use of **connection-manager components** on endpoints that do not need them (AppLocker/WDAC).  
- Apply **egress filtering** and DNS controls; baseline approved **VPN endpoints**.  
- Monitor for **unexpected adapter creation** and **mode switches** launched by non-admin users.

### Recovery
- Remove staged payloads; remediate unauthorized profiles/adapters; rotate credentials used by the session.  
- Update allowlists/tuning and add targeted hunts for the observed switches and destinations.

### False Positives
- Legitimate enterprise **VPN onboarding**, troubleshooting, or deployment workflows invoking `cmdl32.exe`.  
- Automated provisioning scripts in approved maintenance windows. Validate with **tickets** and **owners**.

---

## Playbook 2 — CMDL32 FileCreate in %TMP% as `VPN_*.tmp` (File Creation)

### Overview
This playbook guides investigation of **file creation** events where **`cmdl32.exe`** writes **temporary files** matching the pattern 
`VPN_*.tmp` in the user’s **%TMP%** directory. Such artifacts can represent **session state**, **downloaded configuration**, or **staged payloads** 
related to a connection attempt—potentially linked to **Ingress Tool Transfer (T1105)** if content is fetched from external hosts.

### Attack Context
- **Technique:** T1105 — Ingress Tool Transfer  
- **Binary:** `cmdl32.exe` (writer)  
- **Behavioral cue:** Creation of `VPN_*.tmp` in **%TMP%** shortly after a **cmdl32.exe** process event, often followed by other tooling.

### Initial Response
1. **Secure the artifact:** Copy and **hash** the `VPN_*.tmp` file(s); preserve **timestamps** and **owner**.  
2. **Trace lineage:** Retrieve the **linked process** event to capture command-line switches and possible destination info.  
3. **Scope blast radius:** Identify whether similar `VPN_*.tmp` files appear on other hosts/users.

### Investigation Steps

#### 1) Artifact Inspection
- Determine **file type** (text/script/binary/archive); extract **strings** and look for **URLs**, **IPs**, credentials, or profile markers.  
- Assess **entropy**/size and check for **obfuscation** or embedded payloads.  
- Confirm **write location** (user temp vs system temp) and evaluate risk based on **writability**.

#### 2) Process & Command-Line Context
- Link the **FileCreate (EID 11)** to the preceding **cmdl32.exe** process (EID 1/4688).  
- Review **parent process**, **user context**, and any **mode switches** used.  
- Check if the file was **read/renamed/executed** shortly after creation.

#### 3) Network & DNS Corroboration
- Correlate **DNS** and **network** telemetry with process timing; identify external hosts contacted.  
- In proxy environments, retrieve **HTTP(S)** logs for destination **host/path** and **response sizes** if available.

#### 4) Fleet & Follow‑On
- Search across the fleet for `VPN_*.tmp` created by `cmdl32.exe`; pivot on **hash** and **strings**.  
- Look for follow-on execution (PowerShell, wscript, mshta, rundll32) consuming the temp file content.

### Key Artifacts
- **File Creation (EID 11):** `TargetFilename` = `%TMP%\VPN_*.tmp`, `Image=...\cmdl32.exe`.  
- **Process Creation (EID 1 / 4688):** Preceding `cmdl32.exe` invocation with VPN/LAN switches.  
- **DNS (EID 22):** Queries to destination hosts linked to the session.  
- **Network (EID 3 / Proxy/VPN):** Egress records and potential VPN session evidence.  
- **EDR timeline:** Reads/executions of the newly created temp file.

### Containment Actions
- Quarantine the `VPN_*.tmp` file(s); **block** discovered external hosts; terminate suspicious sessions.  
- If sensitive data is found in the temp file, initiate **credential rotation** and **data protection** procedures.

### Prevention Measures
- Limit `cmdl32.exe` usage with **application control**; allow only sanctioned VPN workflows.  
- Harden **temp directory execution** policies; restrict interpreter execution from user-writable paths.  
- Enforce **egress and DNS allowlists** for VPN-related communications.

### Recovery
- Delete malicious artifacts; remove rogue connection profiles/adapters; document and tune detections.  
- Re-baseline approved VPN endpoints and provisioning procedures.

### False Positives
- Benign connection-manager operations that store transient temp files during **legitimate** VPN setup/troubleshooting.  
- Enterprise deployment tools generating VPN temp files under controlled change windows.