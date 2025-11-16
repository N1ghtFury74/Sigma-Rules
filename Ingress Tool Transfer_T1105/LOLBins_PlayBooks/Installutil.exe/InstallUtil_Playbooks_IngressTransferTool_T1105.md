# T1105 — Ingress Tool Transfer · LOLBin: InstallUtil.exe  
**Rules:**  
- CNC-E-2726320-163 — InstallUtil URL in Command Line (Process Creation)  
- CNC-E-2726320-164 — InstallUtil Network Connection (Sysmon EID 3)  
**Last updated:** 2025-10-28 06:02 UTC

> `InstallUtil.exe` is the .NET Installer utility that executes installer components in managed assemblies. Adversaries abuse it to
> **fetch and execute** remote assemblies (or local ones previously downloaded) using a **Microsoft‑signed** host, enabling **Ingress Tool Transfer (T1105)**
> and defense evasion.

---

## Playbook 1 — InstallUtil URL in Command Line (Process Creation)

### Overview
Investigate alerts where **`installutil.exe`** is launched with a **URL/UNC/WebDAV path** in the command line (e.g., `http(s)://`, `\\host\share`,
`\\host@SSL\DavWWWRoot\...`, or `file://`). This suggests **remote source** execution of a managed assembly, a common LOLBin abuse pattern.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** with `Image`, full `CommandLine`, `ParentImage`, `User`, integrity level, working dir, timestamp.  
2. **Parse source:** Extract **scheme/host/port/path**; treat **raw IPs**, **non‑standard ports**, and **new domains** as high‑signal.  
3. **Collect artifacts:** If a **local file** is referenced (after prior download), immediately **acquire** the assembly and any side files/configs.

### Investigation Steps
#### 1) Process & Lineage
- Verify `Image` path (`C:\\Windows\\Microsoft.NET\\Framework(64)\\v*\\InstallUtil.exe`) and signer metadata.  
- Review `ParentImage` (Office, browser, script host, another LOLBin) and build the **launch chain**.  
- Identify **parameters** (e.g., `/u` for uninstall) and whether execution is **silent** or **interactive**.

#### 2) Command‑Line Semantics
- Recognize remote‑source patterns:  
  - `installutil.exe http(s)://host/app.exe` (managed PE over HTTP/S)  
  - `installutil.exe \\host\share\app.exe` (SMB UNC)  
  - `installutil.exe \\host@SSL\DavWWWRoot\path\app.exe` or `file://\\host\DavWWWRoot\...` (WebDAV)  
- Note any **extra args** passed to the target assembly’s entry points.

#### 3) Artifact & Execution Analysis
- Locate **file creations** (Sysmon **EID 11**) if the assembly was first downloaded; hash and analyze (check **CLR** headers).  
- Inspect **module loads** for CLR (`mscoree.dll`, `clr.dll`).  
- Hunt for **child processes** started by the managed code (PowerShell, rundll32, mshta, cmd), and registry/task writes.

#### 4) Network & DNS Corroboration
- **HTTP/HTTPS:** Review **proxy** logs (method, status, size, SNI/Host).  
- **WebDAV:** Expect egress via **WebClient** `svchost.exe` on **80/443**; attribute connections accordingly.  
- **SMB:** Corroborate **port 445** sessions and **logon type 3** events.  
- **DNS (EID 22):** Lookups for the destination (or proxy FQDN in explicit‑proxy setups).

### Key Artifacts
- **Sysmon EID 1 / 4688:** `Image=...\\InstallUtil.exe`, full `CommandLine`, parent, user.  
- **Sysmon EID 11:** Downloaded/staged assemblies and configs.  
- **Sysmon EID 3 / Proxy:** Outbound connections for remote sources.  
- **Sysmon EID 22:** DNS queries aligned with execution.  
- **EDR timeline:** CLR loads, child processes, registry/scheduled task modifications.

### Containment Actions
- **Terminate** the process chain; **quarantine** retrieved assemblies; **block** destination hosts; consider **host isolation** on follow‑on exec.  

### Prevention Measures
- **AppLocker/WDAC** to restrict `InstallUtil.exe` (allow only on admin jump boxes).  
- Enforce **egress filtering** and **domain allowlists**; disable **WebClient** if unused.  
- Monitor for **rare process → URL/UNC** usage and execution from **user‑writable** paths.

### Recovery
- Remove payloads/persistence; rotate compromised credentials; tune allowlists/detections; document deviations.

### False Positives
- Legacy **deployment/installer** workflows invoking managed installers from **approved internal** shares. Validate via owners/change records.

---

## Playbook 2 — InstallUtil Network Connection (Sysmon EID 3)

### Overview
This playbook covers alerts where **`installutil.exe`** exhibits **network connections** (Sysmon **EID 3**). Native behavior is typically **local**;
process‑attributed egress to **Internet hosts**, **raw IPs**, or **non‑standard ports** is suspicious and consistent with **T1105**.

### Initial Response
1. **Capture records:** Export **EID 3** (dest IP/host/port) and correlate to nearby **EID 1/4688** for `InstallUtil.exe`.  
2. **Destination triage:** Internal vs external; enrich with reputation/age; examine **SNI/URL** in proxy logs when available.  
3. **Scope role:** Determine if the device/user legitimately uses managed installers from remote locations.

### Investigation Steps
#### 1) Process & Lineage
- Confirm `Image` path/signature; review `ParentImage` and **command line** for URL/UNC indicators.  
- Identify working directory and any **referenced local outputs** (configs, logs, downloaded payloads).

#### 2) Destination Validation
- **HTTP/HTTPS:** Pivot to **proxy** details (method, status, bytes).  
- **WebDAV:** Egress commonly attributed to **WebClient `svchost.exe`**; correlate with proxy and SMB/WebDAV logs.  
- **SMB UNC:** Validate **port 445** sessions and **logon type 3** events; enumerate share/path.

#### 3) Artifact Discovery
- Search for **file creations** (EID 11) around the connection (assemblies/configs/drops).  
- Hash/analyze content; confirm **managed PE** characteristics where applicable.

#### 4) Correlation & Follow‑On
- Hunt for **child process** execution after the connection; pivot destination host and file hashes across fleet.  

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\InstallUtil.exe`, destination details.  
- **Sysmon EID 1 / 4688:** Launch context and `CommandLine`.  
- **Sysmon EID 11:** File writes tied to remote retrieval.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.

### Containment Actions
- **Block** destination; **terminate** activity; **quarantine** artifacts; consider **host isolation** on execution.

### Prevention Measures
- Egress filtering/allowlists; disable **WebClient** where not required; restrict `InstallUtil.exe` via **application control**.  
- Monitor **rare process → network** pairs and **Internet‑zone** usage.

### Recovery
- Remove payloads/persistence; tune detections; update runbooks and allowlists.

### False Positives
- Intranet deployment operations legitimately fetching installers from **approved** servers; validate via change tickets and owners.