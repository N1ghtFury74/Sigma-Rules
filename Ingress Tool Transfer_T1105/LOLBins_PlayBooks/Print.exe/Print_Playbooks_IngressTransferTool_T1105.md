# T1105 — Ingress Tool Transfer · LOLBin: Print.exe (Windows Print Job Submitter)
**Rules:**  
- CNC-E-2726320-182 — Print.exe Remote Source via UNC/WebDAV (Process Creation)  
- CNC-E-2726320-183 — Print.exe Network Egress (Sysmon EID 3)  
**Last updated:** 2025-10-28 07:18 UTC

> `Print.exe` is a legacy **print‑job submission** utility that can accept **remote document paths** (e.g., UNC shares and WebDAV) and submit
> them to a target printer/queue. When pointed at **Internet/Intranet resources**, it can trigger **network fetches** and **local spooling**
> under a Microsoft‑signed binary, making it an unusual but viable helper in **T1105 — Ingress Tool Transfer** chains (staging/validation of
> remote content and creating side‑effects under `C:\\Windows\\System32\\spool\\PRINTERS`).

---

## Playbook 1 — Remote Source via UNC/WebDAV (Process Creation)

### Overview
Investigate **process creation** of `Print.exe` where the **command line contains a remote path** to the input document or a remote printer path:
- Input: `\\server\share\file.pdf`, `\\host@SSL\DavWWWRoot\docs\file.xps` (WebDAV over HTTPS)  
- Printer: `\\printserver\queue`  
Such usage causes `Print.exe` (or broker services) to **access remote content**, producing **SMB/WebDAV** egress and local **spool** file writes.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** for `Print.exe` with full `CommandLine`, `ParentImage`, `User`, IL, CWD, timestamp.  
2. **Classify targets:** Parse **input** and **printer** paths; determine **internal vs external** and detect **raw IPs** / **non‑standard ports**.  
3. **Secure artifacts:** Snapshot `C:\\Windows\\System32\\spool\\PRINTERS` and user **INetCache/%TEMP%** for new `.SPL/.SHD` entries; copy & **hash**.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path/signature (`C:\\Windows\\System32\\print.exe`).  
- Inspect **parent** (script host, Office, RMM, scheduled task) and execution context (user/elevated).  
- Confirm whether invocation is **interactive** vs background/automation.

#### 2) Command‑Line Semantics
- Identify remote **document path** vs remote **printer path**; either can cause egress.  
- Flag **UNC** using `@SSL`/`DavWWWRoot` (WebDAV) or **raw IPs**. Check for **odd types** (e.g., `.exe/.dll/.hta` submitted for “print”).

#### 3) Network & DNS
- Correlate **Sysmon EID 3** for SMB (445) or WebDAV (80/443 via **WebClient** `svchost.exe`) to the specified host.  
- Use **Sysmon EID 22** for DNS (proxy FQDN only in explicit‑proxy designs).  
- Review **proxy** logs for HTTP(S) requests (method/status/bytes, content-type).

#### 4) Spooler Side‑Effects & Follow‑On
- Inspect **spool** files `.SPL/.SHD` timestamps aligned with execution; verify **owner** and **size**.  
- Look for **child processes** spawned shortly after (rare but check for follow‑on LOLBins).  
- Examine **Zone.Identifier** ADS on any intermediate cache artifacts.

#### 5) Fleet Correlation
- Pivot by **remote host/share**, **file names**, and **parent process** across endpoints to detect broader staging attempts.

### Key Artifacts
- **Sysmon EID 1 / 4688:** `Image=...\\print.exe`, full CLI, parent, user.  
- **Sysmon EID 3 / Proxy:** SMB/WebDAV egress to the specified host.  
- **Sysmon EID 22:** DNS queries preceding access.  
- **Sysmon EID 11:** Spool or cache file writes (spool path, INetCache/%TEMP%).  
- **Windows Print logs:** Operational channel if enabled for job metadata.

### Containment Actions
- **Block** destination hosts; **disable queue access** if malicious printer paths; **quarantine** artifacts; consider **host isolation** if code execution indicators appear.

### Prevention Measures
- Egress filtering; restrict **WebClient** service if unneeded; limit printing to **approved print servers**.  
- App control to restrict `print.exe` invocation by **untrusted parents**; baseline normal printing workflows per OU/role.

### Recovery
- Remove staged artifacts; review **spooler** integrity; tune detections and allowlists; document legitimate remote print flows.

### False Positives
- **Legitimate printing** of documents from **approved** network shares/SharePoint/WebDAV portals; allowlist internal hosts/queues and trusted file types.

---

## Playbook 2 — Network Egress (Sysmon EID 3)

### Overview
This playbook investigates **outbound connections** attributed to `Print.exe`. While local printing is common, **network egress** to **non‑print servers**, **raw IPs**, or **Internet‑zone WebDAV**
is unusual and can reflect **T1105** staging or fetching of content under a signed binary.

### Initial Response
1. **Capture records:** Export **EID 3** (dest IP/host/port/proto) and correlate to **EID 1/4688** for `Print.exe`.  
2. **Classify destination:** Internal print infra vs **external**; flag **raw IPs**, **new/rare domains**, **non‑standard ports**.  
3. **Scope user/asset:** Determine whether the user/endpoint typically prints from remote locations.

### Investigation Steps
#### 1) Process & Command Context
- Retrieve full **command line** and **parent**; identify remote input/printer paths.  
- Confirm the **document type** that was “printed”; flag binary/script file types.

#### 2) Destination Validation
- For **SMB**, validate **445** sessions and enumerate share paths accessed.  
- For **WebDAV**, pivot to **WebClient** telemetry (ports **80/443**) and **proxy** logs (URL, method/status/bytes).

#### 3) Artifact Discovery
- Search for **EID 11** writes in **spool** and cache dirs; **hash** and analyze.  
- Identify any **child process** execution linked to downloaded/staged content (rare, but check timeline).

#### 4) Correlation & Fleet
- Pivot on **destinations**, **file names**, and **parent** processes across hosts to uncover coordinated activity.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\print.exe`, destination host/IP/port.  
- **Sysmon EID 1 / 4688:** Process creation and CLI context.  
- **Sysmon EID 11:** Spool/cache writes aligned with the connection.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.

### Containment Actions
- **Block** endpoints; **disable** suspicious remote queues; **quarantine** artifacts; consider **host isolation** if further execution is found.

### Prevention Measures
- Restrict remote printing to sanctioned servers; enforce **egress controls**; monitor **rare process → network** pairs.  
- Disable **WebClient** where not required; enable print auditing/operational logs on servers.

### Recovery
- Remove artifacts; validate spooler config; tune detections and allowlists; update runbooks.

### False Positives
- Business workflows printing from approved **intranet** shares or vendor WebDAV portals; verify change tickets and allowlist where appropriate.