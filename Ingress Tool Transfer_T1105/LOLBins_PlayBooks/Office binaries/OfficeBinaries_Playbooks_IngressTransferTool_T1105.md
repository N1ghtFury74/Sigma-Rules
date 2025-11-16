# T1105 — Ingress Tool Transfer · LOLBins: Microsoft Office Binaries (WinWord/Excel/PowerPnt/Visio/Publisher/OneNote/etc.)
**Rules Covered:**  
- CNC-E-2726320-176 — Office Binaries URL Fetch via CLI (Process Creation)  
- CNC-E-2726320-177 — Office Apps → Non‑Microsoft IP (Sysmon EID 3)  
- CNC-E-2726320-174 — Office Apps DNS to Non‑Microsoft Domains (Sysmon EID 22)  
**Last updated:** 2025-10-28 07:09 UTC

> Numerous **Office‑signed binaries** can be invoked directly with **remote inputs** (HTTP/HTTPS, UNC, WebDAV) or can fetch linked/OLE content at open time.
> Adversaries abuse these trusted processes for **Ingress Tool Transfer (T1105)** to stage payloads or scripts while evading basic allowlists.

---

## Playbook 1 — Office Binaries URL Fetch via CLI (Process Creation)

### Overview
Investigate **process creation** for Office apps (e.g., `WINWORD.EXE`, `EXCEL.EXE`, `POWERPNT.EXE`, `MSPUB.EXE`, `VISIO.EXE`, `ONENOTE.EXE`) where the **command line contains a URL or UNC/WebDAV path**.
Examples:  
- `http(s)://host/path.docm`  
- `\\server\share\file.xlsx`  
- `\\host@SSL\DavWWWRoot\payload.html`  
This indicates **remote sourcing** of a document/template or linked content, often followed by **INetCache/temp** writes and potential execution of embedded objects/macros.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** with `Image`, full `CommandLine`, `ParentImage`, `User`, integrity level, CWD, timestamp.  
2. **Parse source:** Extract **scheme/host/port/path**; classify **internal vs external**; flag **raw IPs**, **CDN shorteners**, **non‑standard ports**.  
3. **Secure artifacts:** Snapshot **INetCache**/**%TEMP%** around event; copy & **hash** retrieved files and opened documents (avoid opening in Office).

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path/signature under Office install tree.  
- Review **parent** (Outlook/Teams/browser → delivery, script hosts, scheduled tasks).  
- Note automation switches (e.g., `/embedding`, `/m <macro>`, `/safe` absent, `/dde` scenarios).

#### 2) Content & Links
- Offline parse the document (if permitted) for **external links/OLE/IncludeText/Template** URIs and macro code.  
- Identify **secondary URLs** that may fetch payloads at open time or after user prompts.

#### 3) Network & DNS
- Correlate **Sysmon EID 3** egress (may be via Office process or helper services) and **proxy** logs (Host/SNI, method/status/bytes).  
- Check **Sysmon EID 22** DNS for destination FQDNs (note: in explicit proxy, EID 22 might show only the **proxy FQDN**).  
- For **WebDAV UNC** (`DavWWWRoot`, `@SSL`), egress is typically via the **WebClient** service (`svchost.exe`) over **80/443**.

#### 4) Artifact Analysis
- Inspect cached **HTML/JS/HTA/LNK/ZIP/EXE/DLL**; verify **extension↔MIME** and **Zone.Identifier** ADS.  
- Look for **child processes** (`mshta.exe`, `wscript.exe`, `rundll32.exe`, `regsvr32.exe`, `powershell.exe`).

#### 5) Fleet & Follow‑On
- Pivot by **destination host**, **hashes** of cache artifacts, and **CLI substrings** across endpoints; identify multi‑host campaigns.

### Key Artifacts
- **Sysmon EID 1 / 4688:** CLI with remote input; `ParentImage`.  
- **Sysmon EID 11:** INetCache/temp writes.  
- **Sysmon EID 3 / Proxy:** HTTP(S)/WebDAV flows.  
- **Sysmon EID 22:** DNS aligned with execution.  
- **EDR timeline:** Child processes and module loads.

### Containment Actions
- **Block** destination; **quarantine** artifacts; **terminate** the process chain; consider **host isolation** if execution occurred.

### Prevention Measures
- Egress filtering and **domain allowlists**; disable **WebClient** where unneeded.  
- App control (AppLocker/WDAC) to constrain **Office → Internet** behaviors and **document from Internet** execution.  
- Harden Office (macro/ActiveX from Internet), enforce Protected View, ASR rules for Office child process creation.

### Recovery
- Remove staged content/persistence; rotate credentials if exposed; tune detections and allowlists.

### False Positives
- Legitimate enterprise workflows opening docs from approved **SharePoint/intranet/SMB** locations. Validate by owner/ticket and allowlist.

---

## Playbook 2 — Office Apps → Non‑Microsoft IP (Sysmon EID 3)

### Overview
This playbook investigates **outbound connections** attributed to Office binaries targeting **non‑Microsoft IPs**. While Office does perform network I/O (templates, cloud services),
unsolicited egress to **raw IPs**, **new/rare domains**, or **non‑standard ports** is suspicious for **T1105** staging or remote template fetch.

### Initial Response
1. **Capture records:** Export **EID 3** (dest IP/host/port/proto) and correlate with **EID 1/4688** for the Office process.  
2. **Classify destination:** Internal vs external; highlight **raw IPs** and endpoints outside known **Microsoft/enterprise** ranges.  
3. **Scope role:** Determine user activity and whether opening remote docs is expected on the asset.

### Investigation Steps
#### 1) Process & Command Context
- Retrieve full **command line** and **parent**; identify remote paths/URLs or template arguments.  
- Check recent MRUs/recent files for remote sources.

#### 2) Destination Validation
- Enrich IP ownership/ASN; consult **proxy** logs for URL/SNI, method/status/bytes.  
- For **WebDAV**, pivot to **WebClient** telemetry; for SMB, validate **445** sessions and shares.

#### 3) Artifact Discovery
- Search **EID 11** for new files in **INetCache**/**%TEMP%**; hash and classify (executable/script indicators).  
- Identify **child processes** spawned after the connection (script hosts/LOLBins).

#### 4) Correlation & Fleet
- Pivot on **destinations**, **hashes**, and **CLI** patterns; cluster by **parent** and **user** across the fleet.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\(OfficeApp).exe`, destination details.  
- **Sysmon EID 1 / 4688:** Process creation context.  
- **Sysmon EID 11:** File writes following the connection.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.

### Containment Actions
- **Block** endpoints; **quarantine** artifacts; **terminate** activity; consider **host isolation** on execution.

### Prevention Measures
- Maintain **allowlists** for Microsoft cloud and sanctioned SaaS; enforce **egress filtering**.  
- Alert on **Office → raw IP** or **non‑standard port** egress; baseline normal Office destinations.  
- Reduce attack surface via **ASR** rules and disabling legacy web features.

### Recovery
- Remove artifacts/persistence; tune detections; update runbooks.

### False Positives
- Approved business workflows that fetch content from internal vendor IPs or private CDNs; validate and allowlist by IP range/ASN.

---

## Playbook 3 — Office Apps DNS to Non‑Microsoft Domains (Sysmon EID 22)

### Overview
Investigate **DNS queries** attributed to Office processes for **non‑Microsoft** domains. In **explicit proxy** environments, EID 22 may only show the **proxy FQDN**;
map to upstream hosts via proxy telemetry. **New/rare** domains or **suspicious TLDs** during Office launches often point to remote templates or payload staging (**T1105**).

### Initial Response
1. **Capture records:** Export **EID 22** with process attribution; correlate with **EID 1/4688** launch events.  
2. **Classify FQDNs:** Internal vs external; flag **recently registered** domains, **doppelgänger** look‑alikes, and **raw‑IP URLs** seen in CLI.  
3. **Proxy context:** Pull **proxy** logs (Host, URL, status/bytes) to identify actual destinations when a proxy is used.

### Investigation Steps
#### 1) Process & Command Context
- Confirm Office **command line/MRUs** reference remote inputs (URL/UNC/WebDAV) or templates.  
- Review **parent** process and user actions (phish, attachment open).

#### 2) Destination Enrichment
- Enrich domains (age/reputation/hosting); check overlaps with recent campaigns.  
- Look for **multiple Office apps** resolving the same domain across hosts (campaign signal).

#### 3) Artifact & Network Corroboration
- Check for **EID 3** egress and **EID 11** file writes aligned in time; hash/analyze artifacts.  
- Identify **child process** execution of downloaded content.

#### 4) Fleet & Follow‑On
- Pivot on **FQDNs**, **hashes**, and **CLI** across endpoints; measure **blast radius**.

### Key Artifacts
- **Sysmon EID 22:** DNS queries by Office processes (or proxy FQDN).  
- **Sysmon EID 1 / 4688:** Process creation context.  
- **Sysmon EID 3 / Proxy:** Network flows during the time window.  
- **Sysmon EID 11:** File creation side effects in cache/temp.

### Containment Actions
- **Block** suspicious domains; **quarantine** artifacts; **terminate** processes; consider **host isolation** if execution observed.

### Prevention Measures
- Domain allowlists and **egress controls** for Office; disable **WebClient** where unneeded.  
- App control to limit Office invoking from **Internet‑origin** documents/templates; ASR policies.

### Recovery
- Remove staged content/persistence; rotate credentials if needed; tune detections and allowlists.

### False Positives
- Legitimate connections to trusted intranet or sanctioned vendor domains; validate via owners and allowlist when appropriate.