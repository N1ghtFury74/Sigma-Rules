# T1105 — Ingress Tool Transfer · LOLBin: MSAccess.exe (Microsoft Access)
**Rules:**  
- CNC-E-2726320-201 — MSAccess URL on Command Line (Process Creation)  
- CNC-E-2726320-202 — MSAccess Network Connection (Sysmon EID 3)  
- CNC-E-2726320-203 — MSAccess DNS Queries (Sysmon EID 22)  
**Last updated:** 2025-10-28 06:33 UTC

> `MSAccess.exe` launches **Microsoft Access**. Beyond local databases, Access can open content from **UNC/WebDAV/HTTP(S)** paths, pull linked
> tables/attachments, and execute **VBA/AutoExec macros**. Adversaries can abuse this to **fetch and stage** payloads or supporting files via a
> Microsoft‑signed Office binary, aligning with **T1105 — Ingress Tool Transfer**.

---

## Playbook 1 — MSAccess URL on Command Line (Process Creation)

### Overview
Investigate **process creation** of `MSAccess.exe` where the **command line includes a URL or UNC/WebDAV path** (e.g., `http(s)://…`, `\\host\share\db.accdb`,
`\\host@SSL\DavWWWRoot\…`). This indicates a **remote source** Access database or content and often precedes **network/cache writes** or **macro execution**.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688**: `Image`, full `CommandLine`, `ParentImage`, `User`, integrity level, working dir, timestamp.  
2. **Parse source:** Extract **scheme/host/port/path**; classify **internal vs external**; flag **raw IPs** and **non‑standard ports**.  
3. **Secure artifacts:** If a local copy was created, **hash** the database and any adjacent files (LDB/LOG/Temp). Avoid opening in Office.

### Investigation Steps
#### 1) Process & Lineage
- Verify `Image` path (e.g., `C:\\Program Files\\Microsoft Office\\root\\Office*\\MSACCESS.EXE`) and signature.  
- Review `ParentImage` (Outlook, Teams, browser, script host) to identify the ingress vector.  
- Note Access **switches**: `/runtime`, `/x <macro>`, `/cmd <args>`, `/embedded`—these can drive **automation**.

#### 2) Source Semantics
- URL/UNC patterns:  
  - `MSAccess.exe https://host/path/db.accdb` (WebDAV/HTTP fetch)  
  - `MSAccess.exe \\host\share\db.mdb` (SMB UNC)  
  - `MSAccess.exe \\host@SSL\DavWWWRoot\path\db.accdb` (HTTPS WebDAV)  
- Check Trust Center settings and **macro** auto‑execution (`AutoExec`, startup forms, add‑ins).

#### 3) Artifact & Content Analysis
- Examine created **LACCDB/LDB**, **INetCache**, `%TEMP%` files.  
- If permitted, **parse** the DB offline (forensic tools) to list **macros**, **VBA modules**, **linked tables** (external paths), and **embedded files**.

#### 4) Network & DNS Corroboration
- Correlate with **EID 3** and **proxy** logs for the download; **EID 22** DNS for destination (or proxy FQDN in explicit proxies).  
- For WebDAV, expect egress via **WebClient** `svchost.exe` over **80/443** rather than `MSAccess.exe` directly.

#### 5) Correlation & Follow‑On
- Hunt for **child processes** spawned by Access/macros (PowerShell, cmd, wscript, rundll32, mshta).  
- Pivot fleet‑wide on the **URL/host**, DB **hash**, and **command‑line** pattern.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Full launch details and command line.  
- **Sysmon EID 11:** Any file writes (cache, temp, attachments).  
- **Sysmon EID 3 / Proxy:** Network requests for the remote DB/content.  
- **Sysmon EID 22:** DNS queries aligned with execution.  
- **EDR timeline:** Parentage, child processes, module loads (VBE/VBA).

### Containment Actions
- **Quarantine** retrieved DBs and artifacts; **block** destination hosts; **terminate** related processes; consider **host isolation** if execution seen.

### Prevention Measures
- Tighten **Office Trust Center** (block macros from Internet), leverage **Attack Surface Reduction** rules.  
- Enforce **egress filtering** and **domain allowlists**; disable **WebClient** when not needed.  
- Application control to **restrict MSAccess.exe** usage on non‑developer endpoints.

### Recovery
- Remove staged payloads/persistence; rotate credentials as needed; tune allowlists/detections; update runbooks.

### False Positives
- Legitimate **intranet** Access apps opened from approved shares/WebDAV locations for business workflows. Validate via ticket/owner.

---

## Playbook 2 — MSAccess Network Connection (Sysmon EID 3)

### Overview
This playbook covers `MSAccess.exe` exhibiting **outbound connections**. While Access can use local files, **UNC/WebDAV/HTTP** sources drive
network I/O that is **atypical** for many users and can reflect **T1105** staging.

### Initial Response
1. **Capture records:** Export **EID 3** (dest IP/host/port/protocol) and correlate to **EID 1/4688** for `MSAccess.exe`.  
2. **Classify destination:** Internal vs external; flag **raw IPs**, **new/rare domains**, **non‑std ports**.  
3. **Scope user/asset:** Determine if the user legitimately uses Access apps backed by remote data sources.

### Investigation Steps
#### 1) Process & Command Context
- Confirm `Image` path/signature; retrieve **command line** to identify URL/UNC inputs or startup macros.  
- Identify any **recent files**/MRU pointing to remote paths.

#### 2) Destination Validation
- **SMB UNC:** Validate **port 445** sessions and **logon type 3** events; enumerate share/path.  
- **WebDAV:** Expect egress via **WebClient** `svchost.exe`; use **proxy** logs for HTTP(S) details; check **DavWWWRoot** patterns.  
- **HTTP/HTTPS:** Review proxy metadata (method/status/bytes); compare to allowlists and reputation.

#### 3) Artifact Discovery
- Search for **file creations** (EID 11) around the connection (cache/temp/attachments).  
- Hash/analyze any artifacts; check for **extension↔MIME** mismatch and suspicious **strings/URLs**.

#### 4) Correlation & Follow‑On
- Hunt for **child process** execution driven by macros/add‑ins; pivot on **destination** and **hashes** across fleet.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\MSACCESS.EXE`, destination details.  
- **Sysmon EID 1 / 4688:** Launch context and `CommandLine`.  
- **Sysmon EID 11:** File writes tied to remote retrieval.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.

### Containment Actions
- **Block** destination; **terminate** activity; **quarantine** artifacts; consider **host isolation** if execution follows.

### Prevention Measures
- Egress filtering/allowlists; disable **WebClient** if not required; restrict `MSAccess.exe` via **application control**.  
- Monitor **rare process → network** pairs and **Internet‑zone** sourcing of Access content.

### Recovery
- Remove artifacts/persistence; tune detections; update runbooks/allowlists.

### False Positives
- Approved intranet apps that source Access DBs from trusted shares or portals.

---

## Playbook 3 — MSAccess DNS Queries (Sysmon EID 22)

### Overview
Investigate **DNS lookups** temporally tied to `MSAccess.exe` execution. In **explicit proxy** environments, EID 22 may show only the **proxy FQDN**;
the real destination resolves on the proxy. Still, **new/rare** domains proxied via Access are suspicious for **T1105**.

### Initial Response
1. **Capture records:** Export **EID 22** entries with process attribution; correlate to **EID 1/4688**.  
2. **Classify FQDNs:** Internal vs external; flag **DGA‑like** names, **raw‑IP URLs** in command line, and **recently registered** domains (if TI available).  
3. **Proxy context:** If a proxy is in use, pull **proxy logs** to map FQDN → upstream destination hostnames and URLs.

### Investigation Steps
#### 1) Process & Command Context
- Confirm `MSAccess.exe` launch details and **remote** inputs in the command line/MRUs/startup switches.  
- Review **user** and **parent** process to determine intent and legitimacy.

#### 2) Destination Enrichment
- Enrich FQDNs (age, reputation, WHOIS hints).  
- Map proxy FQDN to upstream destinations using **proxy telemetry** (Host header/SNI).

#### 3) Artifact & Network Corroboration
- Check for **EID 3** egress and **EID 11** file writes aligned in time.  
- Hash/analyze any resultant artifacts; look for **child process** execution.

#### 4) Fleet & Follow‑On
- Pivot on **FQDN**, destination, and artifact hashes across the fleet to discover related activity.

### Key Artifacts
- **Sysmon EID 22:** DNS queries attributed to `MSAccess.exe` (or proxy FQDN).  
- **Sysmon EID 1 / 4688:** Process creation context.  
- **Sysmon EID 3 / Proxy:** Network flows for the same time window.  
- **Sysmon EID 11:** File creation side effects.

### Containment Actions
- **Block** suspicious domains; **quarantine** related artifacts; **terminate** process chains; consider **host isolation** if execution observed.

### Prevention Measures
- Domain allowlists; restrict **Office** fetching from Internet; disable **WebClient** where not needed.  
- App control to limit `MSAccess.exe` usage; ASR rules for Office behavior.

### Recovery
- Remove staged content/persistence; rotate credentials if exposure suspected; update detections/runbooks.

### False Positives
- Access apps legitimately connecting to **internal** data sources or vendor portals; validate via owners/change tickets and allowlist.