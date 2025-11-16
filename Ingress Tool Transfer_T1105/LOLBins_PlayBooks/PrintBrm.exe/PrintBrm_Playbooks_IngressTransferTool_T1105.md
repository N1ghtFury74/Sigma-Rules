# T1105 — Ingress Tool Transfer · LOLBin: PrintBrm.exe (Printer Backup and Restore Utility)
**Rules:**  
- CNC-E-2726320-184 — PrintBrm UNC/WebDAV Process Creation  
- CNC-E-2726320-185 — PrintBrm Network Connection (Sysmon EID 3)  
**Last updated:** 2025-10-28 16:21 UTC

> `PrintBrm.exe` (Printer Backup and Restore Manager) is a signed Windows binary that exports and imports printer configurations.  
> When abused with **UNC** or **WebDAV** paths, it can **fetch printer configuration files** or payloads from remote servers — effectively enabling **Ingress Tool Transfer (T1105)** under a trusted binary context.  
> This makes it a valuable tool for adversaries to move data or load malicious content via allowed administrative binaries.

---

## Playbook 1 — UNC/WebDAV Process Creation

### Overview
This rule detects execution of `PrintBrm.exe` with **UNC paths** (`\\server\share`) or **WebDAV endpoints** (`@SSL\DavWWWRoot`) in its command line.  
Such behavior is suspicious when not part of an administrative print backup/restore workflow, as it implies remote file access.

### Initial Response
1. Collect **Sysmon EID 1 / Security 4688** for `PrintBrm.exe` showing full command line, user, and parent process.  
2. Identify **whether UNC/WebDAV paths** target internal print servers or **external domains**.  
3. Preserve **contextual artifacts** — job files, `.dat` packages, logs under `C:\Windows\System32\spool\tools`.

### Investigation Steps
#### 1) Process Lineage and Intent
- Confirm **parent process** (e.g., PowerShell, cmd.exe, or service host).  
- Look for **CLI parameters** like `/b`, `/r`, or `/s` followed by remote paths.  
- Determine **user role** — printing admin or unexpected service account.

#### 2) Network and Host Behavior
- Correlate with **Sysmon EID 3** for SMB/WebDAV egress to remote host.  
- Validate that connection is expected (domain-joined printer or enterprise share).  
- Investigate **file writes** (EID 11) — backup files or payload drops in `%TEMP%` or spool directories.

#### 3) Wider Context
- Review **recent `PrintBrm.exe` usage** across hosts; unusual clusters may indicate coordinated staging.  
- Check **scheduled tasks** or RMM agents possibly invoking the command.

### Key Artifacts
- **Sysmon EID 1 / 4688:** `Image=...\PrintBrm.exe`, `CommandLine` with UNC/WebDAV reference.  
- **Sysmon EID 3:** Destination IP/port for SMB (445) or WebDAV (80/443).  
- **Sysmon EID 11:** File creation from import/export operations.

### Containment Actions
- Block external destinations and isolate host if artifacts indicate malicious origin.  
- Revoke credentials if compromised; remove rogue backups or imports.

### Prevention Measures
- Restrict `PrintBrm.exe` execution to **print administrators** only.  
- Disable WebClient service if not required.  
- Enforce SMB signing and allowlists for print configuration shares.

### Recovery
- Purge suspicious `.dat` or `.cab` printer packages.  
- Restore system to known-safe state; log and tune detection baselines.

### False Positives
- Legitimate printer export/import tasks by administrators using domain file shares.  
- Allowlist known infrastructure and internal print management scripts.

---

## Playbook 2 — Network Connection (Sysmon EID 3)

### Overview
This rule detects **network egress** from `PrintBrm.exe`, which is highly unusual outside legitimate printer replication scenarios.  
Outbound SMB or WebDAV connections can indicate data exfiltration or tool staging.

### Initial Response
1. Review **EID 3** for destination host/IP, protocol, and port.  
2. Correlate with **EID 1 / 4688** for process command line to confirm context.  
3. Check **EID 22** (DNS) and **proxy logs** for remote domains or unexpected IPs.

### Investigation Steps
#### 1) Command Context
- Examine whether the `CommandLine` includes backup or restore flags with external paths.  
- Validate **user identity** and **execution time** (service hours vs off-hours).

#### 2) Destination Review
- Internal print servers typically use SMB (445) within local ranges.  
- External IPs or WebDAV endpoints over HTTP/HTTPS indicate staging/exfiltration.

#### 3) Artifact Inspection
- Review **Sysmon EID 11** for temporary CAB/DAT creations; **hash and detonate** if unknown.  
- Check **spooler service** logs for unexpected import/export actions.

#### 4) Fleet Correlation
- Pivot by **destination host**, **CLI**, and **hash** to identify pattern reuse.

### Key Artifacts
- **Sysmon EID 3:** Egress details from `PrintBrm.exe`.  
- **Sysmon EID 1 / 4688:** Process creation metadata.  
- **Sysmon EID 11:** File write events for print packages.

### Containment Actions
- Block and isolate endpoints connecting to non-corporate SMB/WebDAV hosts.  
- Remove rogue backups; disable print replication where abused.

### Prevention Measures
- Apply **AppLocker/WDAC** policies for `PrintBrm.exe`.  
- Limit print service to **approved servers**.  
- Monitor for **rare process → external network** correlations.

### Recovery
- Remove any downloaded artifacts; audit print queues; restore approved configurations.

### False Positives
- Rare but possible for authorized IT operations syncing printers between trusted networks.