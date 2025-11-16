# T1105 — Ingress Tool Transfer · LOLBin: OneDriveStandaloneUpdater.exe
**Rules Covered:**  
- CNC-E-2726320-179 — OneDriveStandaloneUpdater Registry URL Set via CLI (Process Creation)  
- CNC-E-2726320-177 — OneDriveStandaloneUpdater Registry‑Driven Download (Sysmon EID 13)  
**Last updated:** 2025-10-28 07:12 UTC

> `OneDriveStandaloneUpdater.exe` is the Microsoft OneDrive **self‑updater**. It honors **registry‑controlled** configuration (channel/ring and **update URL**)
> to locate packages. Adversaries can modify those registry values so that a **Microsoft‑signed updater fetches content from attacker‑controlled endpoints**,
> providing a stealthy **Ingress Tool Transfer (T1105)** path and potential proxy evasion via enterprise allowlists.

---

## Playbook 1 — Registry URL Set via CLI (Process Creation)

### Overview
This playbook investigates **process creation** events where a process (e.g., `reg.exe`, `powershell.exe`, `cmd.exe`, installers, scripts) **sets OneDrive updater registry values**
that control **where the updater downloads from**. Typical suspicious values include an **Update/Download URL** or **ring/channel** under user or machine hives.

Common key patterns to verify (exact key/value names should be taken from the alert payload):
- `HKCU\Software\Microsoft\OneDrive\*` (e.g., **UpdateUrl**, **DownloadUrl**, **Ring/Channel**)
- `HKLM\Software\Microsoft\OneDrive\*` (enterprise‑wide overrides)
- 32‑bit counterparts under `...\WOW6432Node\...`

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** for the **setter process** with full `CommandLine`, `ParentImage`, `User`, IL, CWD, timestamp.  
2. **Snapshot registry:** Export the **exact keys/values** referenced in the alert for both **HKCU** and **HKLM** to confirm final state.  
3. **Scope account/host:** Identify the **user SID** impacted (HKCU) or **machine‑wide** scope (HKLM).

### Investigation Steps
#### 1) Process & Lineage
- Validate the **setter** (`reg.exe`, `powershell Set-ItemProperty/New-ItemProperty`, `reg add`, installer MSI custom actions).  
- Review **parent** (Office/script hosts, RMM/PSExec, scheduled tasks) and execution context (user vs elevated).

#### 2) Intent & Provenance
- Inspect `CommandLine` for the **target value** (URL/host) and **ring/channel**. Flag **raw IPs**, **non‑standard ports**, or **non‑Microsoft** domains.  
- Confirm whether changes align with **legitimate servicing** (change tickets, update rollout).

#### 3) Follow‑On Correlation
- Hunt for **OneDriveStandaloneUpdater.exe** launches shortly after (EID 1/4688) and correlate **EID 3**/**proxy** for downloads to the set URL.  
- Check **EID 11** for package writes in `%LOCALAPPDATA%\Microsoft\OneDrive\*` or update cache paths.

#### 4) Fleet‑Wide Pivot
- Search for additional endpoints where the **same URL** or **same registry value** is set; cluster by **parent tool** and **user**.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Setter process creation details; later `OneDriveStandaloneUpdater.exe` executions.  
- **Sysmon EID 13:** Registry **value set** records (name, data, hive, process).  
- **Sysmon EID 3 / Proxy:** Network to the configured URL/domain after update invocation.  
- **Sysmon EID 11:** File writes for downloaded packages or temp content.

### Containment Actions
- **Revert** registry values to approved configuration; **block** malicious domains/IPs; **terminate** pending updater runs; consider **host isolation** if payloads executed.

### Prevention Measures
- Harden with **registry ACLs** for OneDrive updater keys (admins only); monitor for **non‑approved setters**.  
- Egress allowlists for Microsoft update CDNs; deny **raw IP** or unknown domains for updater processes.  
- Application control to **restrict updater invocation** by untrusted parents.

### Recovery
- Remove any fetched payloads/persistence; restore policy‑managed OneDrive configuration; tune detections/allowlists; document deviations.

### False Positives
- **Legitimate enterprise servicing** or pilot rings that point to **internal mirrors**/CDNs. Validate via change tickets and allowlist approved domains/paths.

---

## Playbook 2 — Registry‑Driven Download (Sysmon EID 13)

### Overview
This playbook investigates **registry value set** events (Sysmon **EID 13**) for OneDrive updater configuration that **would cause network downloads** on the next updater run.
Adversaries set these values to **redirect the updater** to attacker infrastructure. The EID 13 alert provides the **key path**, **value name**, and **data** (URL/host/ring).

### Initial Response
1. **Validate change:** Confirm the **final value** on disk and whether it affects **HKCU** (current user) or **HKLM** (all users).  
2. **Identify initiator:** From the EID 13 details, retrieve the **ProcessGUID/Image** responsible; pull matching **EID 1/4688** event for full CLI and parent.  
3. **Trigger window:** Determine if `OneDriveStandaloneUpdater.exe` executed **after** the change (scheduled/automatic runs, user logon, task scheduler).

### Investigation Steps
#### 1) Destination Risk
- Parse the configured **URL/host**; flag **raw IPs**, **recent domains**, **non‑Microsoft** endpoints, **non‑standard ports**, or **self‑signed TLS** observed in proxy logs.

#### 2) Corroborating Activity
- Correlate **EID 3**/**proxy** with downloads initiated by `OneDriveStandaloneUpdater.exe` soon after the registry change.  
- Inspect **EID 11** for package or payload writes in OneDrive update/cache paths.

#### 3) Post‑Download Behavior
- Look for **child processes** spawned from updated/staged binaries (e.g., `rundll32`, `powershell`, unknown EXEs) and **module loads**.  
- Verify **Zone.Identifier** ADS or file metadata indicating Internet zone.

#### 4) Blast‑Radius Assessment
- Pivot fleet‑wide by the **same registry value data** (URL/domain) and by the **setter process hash/command line**.

### Key Artifacts
- **Sysmon EID 13:** Registry value set (hive, key, value, data, process).  
- **Sysmon EID 1 / 4688:** Setter process; later `OneDriveStandaloneUpdater.exe` executions.  
- **Sysmon EID 3 / Proxy:** Network downloads attributed to updater.  
- **Sysmon EID 11:** Downloaded package/artifact writes in user profile or program data.

### Containment Actions
- **Lock down** updater keys; **revert** malicious values; **block** destination endpoints; **quarantine** downloaded artifacts; consider **host isolation** if execution occurred.

### Prevention Measures
- Manage OneDrive settings via **Group Policy/MDM**; enforce **registry protection**.  
- Strict **egress allowlists** for updater traffic; monitor for **non‑Microsoft** destinations.  
- Alert when updater is **invoked by untrusted parents** or outside maintenance windows.

### Recovery
- Remove staged payloads/persistence; reset OneDrive updater to defaults; tune detections and allowlists; communicate with owners.

### False Positives
- **Pilot/testing** configurations pointing to **internal staging** servers or alternate rings; validate via documented change windows and owners.