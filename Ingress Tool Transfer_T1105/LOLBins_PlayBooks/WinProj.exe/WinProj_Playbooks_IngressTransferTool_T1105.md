# T1105 — Ingress Tool Transfer · LOLBin: WinProj.exe (Microsoft Project)
**Rules Covered:**  
- CNC-E-2726320-302 — WinProj Unusual Network Connection (Sysmon EID 3)  
- CNC-E-2726320-302 — WinProj URL on Command Line (Process Creation)  
**Last updated:** 2025-10-28 17:37 UTC

> `WinProj.exe` is a Microsoft Project binary primarily used to open and manage project files. When invoked with a **URL** or **UNC/WebDAV path**,
> the binary may initiate a **fetch** from remote locations. This can be exploited for **T1105 — Ingress Tool Transfer**, where an adversary stages
> payloads or fetches remote artifacts from web or SMB shares using a trusted Microsoft utility.

---

## Playbook 1 — URL on Command Line (Process Creation)

### Overview
Investigate **process creation** where `WinProj.exe` is invoked with a **remote URL** or **UNC/WebDAV path** in its command line:
- `http(s)://host/path` (flag **raw IPs**, **non‑standard ports**, **shortened URLs**)  
- `\\server\share\file` (SMB UNC)  
- `\\host@SSL\DavWWWRoot\path\file` (WebDAV over HTTPS)

Such usage indicates a **remote source** for the opened project, which could involve **downloading content** under a trusted binary.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** showing full `CommandLine`, `ParentImage`, `User`, and `IntegrityLevel`.  
2. **Parse target:** Identify **source URL/UNC** and classify **internal vs external**; flag **raw IPs** and **non‑standard ports**.  
3. **Secure artifacts:** Snapshot **INetCache**, `%TEMP%`, and other directories; capture **hashes** of any files created/modified by this process.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path/signature (`C:\\Windows\\System32\\winproj.exe`).  
- Review **parent process** (e.g., `msbuild.exe`, `devenv.exe`, `powershell.exe`), and confirm **user context** (elevated or interactive).  
- Check whether the **execution time** was during expected hours for project work.

#### 2) Command‑Line Semantics
- Confirm **remote paths** and **URLs** being used by the command, e.g., `-url`, `-file`, or `-project` switches.  
- Check for **exploitation flags**, such as `-nosplash`, `-f` (force execution), or missing file integrity options.

#### 3) Network & DNS
- Correlate **Sysmon EID 3** for egress network traffic attributed to `WinProj.exe` or **downstream handlers** (e.g., **WebClient**, `svchost.exe`).  
- Use **Sysmon EID 22** for DNS queries; look for **non‑enterprise DNS queries** (e.g., raw IPs, unexpected TLDs).  
- Investigate **proxy** logs for URL, method/status, bytes, and SNI anomalies.

#### 4) Artifact & Execution
- Review **Sysmon EID 11** for created/modified files in **INetCache** or `%TEMP%` directories, especially with **WebDAV/UNC path**.  
- Check for **child processes** like `mshta.exe`, `rundll32.exe`, or `powershell.exe` that could have been triggered to download and execute payloads.

#### 5) Fleet Correlation
- Pivot on **source IP/UNC path**, **hashes of files** created, and **CLI fragments** (e.g., `DavWWWRoot`, `@SSL`) across endpoints to identify other instances of this behavior.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Full process creation context and command line.  
- **Sysmon EID 3 / Proxy:** Network connections initiated by `WinProj.exe`.  
- **Sysmon EID 22:** DNS queries for non‑enterprise hosts.  
- **Sysmon EID 11:** File creation and modification in **INetCache**/**%TEMP%**.

### Containment Actions
- **Block** the external or suspicious destination, **quarantine** downloaded files, and **terminate** any associated processes.  
- Consider **host isolation** if confirmed malicious execution.

### Prevention Measures
- Restrict `WinProj.exe` execution to **development environments** or **trusted project sources** using **AppLocker/WDAC**.  
- Enable **DNS filtering** to block malicious or unauthorized domains and SMB shares.  
- Monitor for **network egress to non‑Microsoft destinations**.

### Recovery
- **Restore files** from backup, remove any rogue payloads, and update **detection rules**.  
- Tune allowlist for **trusted development domains** or **file paths** to reduce detection noise.

### False Positives
- Legitimate **project fetching** via **intranet WebDAV** or **internal file shares**; validate via ticketing systems, change logs, or project files.

---

## Playbook 2 — Unusual Network Connection (Sysmon EID 3 / DNS EID 22)

### Overview
This playbook investigates **network or DNS activity** tied to `WinProj.exe`. If `WinProj.exe` triggers egress to **non‑internal resources** via **SMB** or **WebDAV**, this can indicate **suspicious behavior**.

### Initial Response
1. **Capture records:** Export **Sysmon EID 3** (dest IP/host/port/proto) and **Sysmon EID 22** (DNS queries) for the same time window, correlating with **EID 1/4688**.  
2. **Classify destination:** Internal vs external; flag **raw IPs**, **new/rare domains**, **non‑standard ports**.  
3. **Scope usage:** Determine if the asset is **developer-focused**, or if the host should typically not make outbound SMB/WebDAV connections.

### Investigation Steps
#### 1) Process & Command Context
- Retrieve full **command line** for `WinProj.exe`; confirm presence of **remote path/URL** in the arguments.  
- Check **parent process** and **user context**.

#### 2) Destination Validation
- Enrich destination host/domain (reputation, ASN); validate **proxy** logs (method/status/bytes).  
- For **SMB**, confirm internal **445** access for file shares; for **WebDAV**, pivot to **WebClient** for connection tracking.

#### 3) Artifact Discovery
- Inspect **Sysmon EID 11** for **new files** created in **INetCache** or `%TEMP%`.  
- Review **follow‑on processes** that interact with these files (script hosts, PowerShell, `mshta.exe`).

#### 4) Correlation & Fleet
- Pivot by **destination FQDN/IP**, **hashes** of downloaded artifacts, **CLI fragments**, and **parent processes** across endpoints.

### Key Artifacts
- **Sysmon EID 3 / 22:** Network and DNS activity.  
- **Sysmon EID 1 / 4688:** Process creation with **remote URLs**.  
- **Sysmon EID 11:** Files written to **INetCache** or `%TEMP%`.  
- **EDR timeline:** Follow‑on activity from downloaded content.

### Containment Actions
- **Block** destinations, **quarantine** files, **terminate** processes, and **isolate** endpoints exhibiting suspicious behavior.

### Prevention Measures
- Apply **network segmentation** and **DNS filtering**; restrict use of `WinProj.exe` to development environments.  
- Use **AppLocker/WDAC** to constrain processes and **allowlists** to reduce noise.

### Recovery
- Purge any downloaded artifacts, **restore files**, and ensure all relevant systems are **patched** and monitored.

### False Positives
- Legitimate **internal project file fetching**; validate based on **intranet shares** and **in-house protocols**.