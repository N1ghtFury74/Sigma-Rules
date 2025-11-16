# BITS-based Ingress Tool Transfer (LOLBin: bitsadmin.exe & PowerShell BITS) — Investigation Playbooks
_Last updated: 2025-10-25 14:34 UTC_

This document contains three investigation playbooks aligned to MITRE ATT&CK **T1105 (Ingress Tool Transfer)** and **T1197 (BITS Jobs)** for the following detections:
1) **BITS-based ingress via bitsadmin.exe or PowerShell BITS cmdlets (process-creation intent)**
2) **BITS Client Operational logs: Process Path is not svchost.exe (userland-created jobs)**
3) **BITS Client Operational logs: Suspicious or unapproved URL in job events**

---

## Playbook 1 — T1105/T1197 · BITS-Based Ingress via bitsadmin.exe or PowerShell BITS Cmdlets (Process Creation)

### Overview
This analytic detects **process intent** to use **Background Intelligent Transfer Service (BITS)** for file ingress, by watching for either **`bitsadmin.exe`** with download-related switches (e.g., `/transfer`, `/addfile`, `/setnotifycmdline`, `/resume`) or **PowerShell BITS cmdlets** such as **`Start-BitsTransfer`** with remote **`-Source`** URLs. **BITS** provides an asynchronous downloader that adversaries frequently abuse for **Ingress Tool Transfer** and **persistence** (T1197). Although **bitsadmin.exe is deprecated**, it remains present on many systems; Microsoft recommends the PowerShell BITS cmdlets, which attackers also leverage.

### Attack Context
- **MITRE ATT&CK:**  
  - **T1105 – Ingress Tool Transfer:** Using BITS to fetch payloads from HTTP(S)/SMB endpoints.  
  - **T1197 – BITS Jobs:** Abusing BITS jobs for download/execution/persistence and cleanup.  
- **LOLBin(s):** `bitsadmin.exe` (deprecated but functional), PowerShell **BITS** cmdlets (`Start-BitsTransfer`, `Add-BitsFile`, `Complete-BitsTransfer`).
- **Tradecraft highlights:**  
  - BITS job created by a userland tool (bitsadmin/PowerShell) then **transfers under the BITS service (`svchost.exe -k netsvcs -s BITS`)** in the background.  
  - BITS Client Operational log shows **job create/start/stop/complete** sequence: **EID 3 → 59 → 60 → 4**.  
  - Event 59/60 often expose the **URL** used for transfer; Event 3 includes **Process Path** (creator).

### Initial Response
- **Confirm process intent:** Retrieve **`CommandLine`** of `bitsadmin.exe` or PowerShell showing BITS parameters/URL.  
- **Scope user/host:** Determine whether this is expected admin tooling or an end-user host.  
- **Snapshot BITS state:** Enumerate active jobs (`bitsadmin /list /verbose` or `Get-BitsTransfer -AllUsers`).

### Investigation Steps
1. **Process & Image Analysis**
   - **Sysmon EID 1 / Security 4688:** Identify `bitsadmin.exe` or PowerShell with **`Start-BitsTransfer`** / **`Add-BitsFile`** and **remote URLs** (`http(s)://`, `ftp://`, UNC).  
   - Confirm parent chain (script host, Office macro, LOLBin). Capture user/token info.
2. **BITS Job & Log Analysis**
   - **Microsoft-Windows-Bits-Client/Operational:** Correlate **EID 3 (Created)** → **EID 59 (Started)** → **EID 60 (Stopped)** → **EID 4 (Completed)** for the same **Job ID**.  
   - From **EID 3**, record **Process Path** (creator): PowerShell vs `bitsadmin.exe`.  
   - From **EID 59/60**, extract the **URL** and **status code** (0x0 success; errors show HRESULT).
3. **Network & DNS**
   - **Sysmon EID 3 (Network):** If enabled, link sockets to creator process at creation time (expect egress by **svchost.exe (BITS)** later).  
   - **Sysmon EID 22 (DNS):** Lookups for the destination host (proxy- and DO-aware).
4. **Correlation & Context**
   - If **persistence** flags are present (`/SetNotifyCmdLine`, scheduled/long-lived jobs), pivot to T1197 playbooks.  
   - Verify **file write locations**, hash new artifacts, and check for **follow-on execution**.

### Key Artifacts
- **Process creation:** Sysmon **EID 1** / Security **4688** for `bitsadmin.exe` and PowerShell with BITS cmdlets/URLs.  
- **BITS logs:** `Microsoft-Windows-Bits-Client/Operational` **EID 3, 59, 60, 4**, including **Process Path**, **URL**, **Job ID**, **Status Code**.  
- **File I/O:** New files at **destination paths** specified in the job.  
- **Network/DNS:** Sysmon **EID 3/22** and proxy logs.

### Containment Actions
- **Cancel or complete** suspicious BITS jobs (`bitsadmin /cancel <id>` or `Get-BitsTransfer -AllUsers | Remove-BitsTransfer`).  
- Quarantine downloaded payloads; block **unapproved domains/IPs**.  
- Consider **host isolation** if follow-on execution observed.

### Prevention Measures
- **Audit & restrict** use of `bitsadmin.exe`; prefer **PowerShell BITS** with constrained language mode and script code signing.  
- Baseline **approved package domains/UNCs**; alert on **new or unapproved** destinations.  
- Enable and centrally collect **BITS Client Operational** logs.  
- Harden **proxy/SSL inspection** and **AppLocker/WDAC** where feasible.

### Recovery
- Remove malicious content; clean up lingering BITS jobs; review persistence artifacts (notify cmd-lines).  
- Update allow/deny lists; document lessons learned in detection content.

### False Positives
- Legitimate **software distribution** (WSUS/ConfigMgr), **Windows/Defender updates**, or **enterprise updaters** using BITS. Validate **URL**, **job owner**, and **change window**.

---

## Playbook 2 — T1105/T1197 · BITS Logs: Process Path Is Not svchost.exe (Userland-Created Jobs)

### Overview
This analytic focuses on **BITS Client Operational** events where **`Process Path` ≠ `C:\Windows\System32\svchost.exe`**, surfacing BITS jobs **created by userland tooling** (e.g., `bitsadmin.exe` or PowerShell BITS). Since transfers execute under the BITS service, **svchost.exe** will own the network I/O, but **Event ID 3 (Created)** captures the **creator process path**, which is a strong pivot to **malicious initiation**.

### Attack Context
- **MITRE ATT&CK:** **T1105** (Ingress Tool Transfer), **T1197** (BITS Jobs).  
- **Why this matters:** Many benign system components use BITS via services; **malicious use** often originates from **interactive tools** (PowerShell/bitsadmin), reflected in **EID 3 Process Path**.

### Initial Response
- Pull **EID 3** record(s) and confirm the **Process Path** (e.g., `powershell.exe`/`bitsadmin.exe`).  
- Identify **user**, **parent process**, and **command-line** for the creator.

### Investigation Steps
1. **Creator Attribution**
   - Map **Process Path** to **EID 1/4688** for the same timestamp to capture the full command line (URLs, switches).  
   - If PowerShell, review **ScriptBlock logs/Module logs** for BITS cmdlets.
2. **Job Lifecycle & URL Extraction**
   - For the same **Job ID**, collect **EID 59/60** (start/stop) and **EID 4** (complete).  
   - Record **URL**, **status**, **bytes transferred** where available.
3. **File & Network Traces**
   - Validate **destination paths** were written; hash outputs.  
   - Confirm **egress** under `svchost.exe` (BITS) and **DNS** lookups to destination host(s).  
   - If explicit proxy or Delivery Optimization is used, pivot to **proxy** and **DoSvc** telemetry.

### Key Artifacts
- **BITS Client Operational:** **EID 3** (Created, **Process Path**), **EID 59/60/4** (URL, status, completion).  
- **Sysmon/Security:** Process creation **EID 1/4688** for the **creator** process; optional **EID 22** DNS.  
- **Filesystem:** Destination file(s) created/modified.

### Containment Actions
- Cancel suspicious jobs; block offending domains; quarantine staged files.

### Prevention Measures
- Alert on **non-svchost** creators in BITS logs; approve known admin tools and signed scripts.  
- Employ **PowerShell logging** (Module, ScriptBlock), **AMSI**, and **EDR** prevention for BITS abuse patterns.

### Recovery
- Remove transferred payloads; clear orphaned BITS jobs; update detections.

### False Positives
- Admin automation or software deployment scripts using BITS intentionally—validate **change tickets**, **signed scripts**, and **approved repositories**.

---

## Playbook 3 — T1105/T1197 · BITS Logs: Suspicious/Unapproved URL in Job Events

### Overview
This analytic monitors **BITS Client Operational** events (notably **EID 59/60**) for **URLs** associated with BITS transfer jobs. It flags **external/unapproved** domains, **raw IPs**, uncommon TLDs, or non-corporate **UNC** paths used for **Ingress Tool Transfer**. Event **EID 59 (Started)** and **EID 60 (Stopped)** often record the **URL**; Event **EID 4 (Completed)** confirms success.

### Attack Context
- **MITRE ATT&CK:** **T1105** (Ingress Tool Transfer), **T1197** (BITS Jobs).  
- **Relevance:** Adversaries frequently stage payloads on throwaway infrastructure; BITS will dutifully fetch them and log the **URL**.

### Initial Response
- Extract the **URL** (domain/IP/UNC) and **Job ID** from **EID 59/60**; enrich with **WHOIS/reputation** and **fleet prevalence**.  
- Identify the **job owner** and the **creator process** via **EID 3 Process Path**.

### Investigation Steps
1. **URL & Reputation**
   - Categorize the domain/TLD; check **allowlists** for corporate repos.  
   - Flag **raw IPs**, **newly seen domains**, or **non-standard ports**.
2. **End-to-End Correlation**
   - Tie the URL-bearing **EID 59/60** to **EID 3** (creator) and **EID 4** (completion), verifying **bytes transferred**.  
   - Confirm **destination file path(s)** and hash artifacts.
3. **Network/DNS & Proxy**
   - Validate **DNS lookups** (EID 22) and **egress** (EID 3) timing.  
   - In explicit proxy environments, pivot to **proxy logs** for the actual destination (client may only resolve proxy FQDN).  
   - If **Delivery Optimization (DoSvc)** is in play, include **svchost.exe (DoSvc)** activity in the pivot.

### Key Artifacts
- **BITS Client Operational:** **EID 59/60** (URL, status), **EID 3** (creator Process Path), **EID 4** (completion).  
- **Sysmon:** **EID 22** (DNS), **EID 3** (Network), **EID 1** (creator process).  
- **Filesystem:** Destination writes contemporaneous with the job.

### Containment Actions
- Block/unresolve the domain/IP; cancel the job; quarantine downloaded content; consider host isolation if execution observed.

### Prevention Measures
- Maintain **domain allowlists** for sanctioned repos; alert on **new or unapproved** destinations.  
- Enforce **PowerShell logging**, **AMSI**, and **AppLocker/WDAC** policies; educate admins on safer transfer methods.  
- Collect and retain **BITS Client Operational** logs centrally.

### Recovery
- Remove malicious payloads; clean up BITS jobs; update detection content and allow/deny lists.

### False Positives
- Legitimate **WSUS/ConfigMgr** or enterprise software distribution using external vendor CDNs; validate **business context** and **change windows**.

--