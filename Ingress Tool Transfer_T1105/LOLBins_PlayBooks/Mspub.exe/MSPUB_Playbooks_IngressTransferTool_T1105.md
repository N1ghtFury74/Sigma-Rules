# T1105 — Ingress Tool Transfer · LOLBin: MSPUB.EXE (Microsoft Publisher)
**Rules:**  
- CNC-E-2726320-201 — MSPUB URL on Command Line (Process Creation)  
- CNC-E-2726320-202 — MSPUB Outbound Network Connection (Sysmon EID 3)  
- CNC-E-2726320-203 — MSPUB DNS Queries (Sysmon EID 22)  
**Last updated:** 2025-10-28 06:54 UTC

> `MSPUB.EXE` launches **Microsoft Publisher**. Publisher files can reference external content (links, images, OLE objects) hosted over **UNC/WebDAV/HTTP(S)**.
> When invoked directly with a remote path/URL, Publisher (or underlying components) may **fetch and cache** content to **INetCache**/**temp**. Adversaries
> can abuse this signed Office binary to **pull payloads or supporting files** as part of **T1105 — Ingress Tool Transfer** prior to execution via other LOLBins.

---

## Playbook 1 — MSPUB URL on Command Line (Process Creation)

### Overview
Investigate **process creation** of `MSPUB.EXE` where the **command line contains a URL or UNC/WebDAV path** (e.g., `http(s)://…`,
`\\host\share\doc.pub`, `\\host@SSL\DavWWWRoot\path\doc.pub`). This suggests **remote sourcing** of a Publisher document or linked content.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** with `Image`, full `CommandLine`, `ParentImage`, `User`, integrity level, working dir, timestamp.  
2. **Parse source:** Extract **scheme/host/port/path**; classify **internal vs external**; flag **raw IPs** and **non‑standard ports**.  
3. **Secure artifacts:** Snapshot **INetCache**/**%TEMP%** around the event; copy & **hash** any cached downloads and the opened `.pub`/assets.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path/signature (Office install tree).  
- Review **parent** (Outlook/Teams/browser → phish, Office macro, script hosts, scheduled tasks).  
- Note Publisher switches (`/o <file>`, `/embedding`) indicating automation/embedding scenarios.

#### 2) Source & Content Semantics
- Identify external **links/OLE** within the Publisher file (forensic parse offline if permitted).  
- Look for **secondary URLs** that may fetch payloads, templates, or scripts on open.

#### 3) Network & DNS
- Correlate **Sysmon EID 3** (direct or brokered via WebClient) and **proxy** logs (method/status/bytes, content-type).  
- Check **Sysmon EID 22** DNS for destination (or proxy FQDN if explicit proxy is used).

#### 4) Artifact Analysis
- Inspect files created under **INetCache**/**%TEMP%** (HTML/JS/VBS/HTA/EXE/ZIP/LNK).  
- Verify **extension↔MIME** consistency, **Zone.Identifier** ADS, **entropy/obfuscation**, and suspicious **strings/URLs**.  
- Identify **child processes** (e.g., `mshta.exe`, `wscript.exe`, `rundll32.exe`, `powershell.exe`).

#### 5) Fleet & Follow‑On
- Pivot by **URL host**, hashes of cached files, and **CLI substrings** across endpoints.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Command line with remote path and `ParentImage`.  
- **Sysmon EID 11:** Writes to **INetCache**/**temp**.  
- **Sysmon EID 3 / Proxy:** HTTP(S)/WebDAV flows.  
- **Sysmon EID 22:** DNS aligned with execution.  
- **EDR timeline:** Child processes and module loads.

### Containment Actions
- **Block** destination; **quarantine** artifacts; **terminate** the process chain; consider **host isolation** if execution is observed.

### Prevention Measures
- Egress filtering and **domain allowlists**; disable **WebClient** when not required.  
- AppLocker/WDAC to restrict direct invocation of **Publisher** on non‑design workstations.  
- Harden Office (block Internet‑origin macros/embedded objects).

### Recovery
- Remove staged content/persistence; rotate credentials if exposure suspected; tune detections/runbooks.

### False Positives
- Legitimate intranet workflows opening `.pub` files from **approved** shares/portal links; validate via owner and allowlist.

---

## Playbook 2 — MSPUB Outbound Network Connection (Sysmon EID 3)

### Overview
This playbook investigates **outbound connections** attributed to `MSPUB.EXE`. While local documents are typical, **remote sourcing** results in network I/O
that may be **unexpected** for many endpoints and can reflect **T1105** staging.

### Initial Response
1. **Capture records:** Export **EID 3** (dest IP/host/port/protocol) and correlate to **EID 1/4688** for `MSPUB.EXE`.  
2. **Classify destination:** Internal vs external; highlight **raw IPs**, **new/rare domains**, and **non‑standard ports**.  
3. **Scope usage:** Determine if the user legitimately opens Publisher documents from remote sources.

### Investigation Steps
#### 1) Process & Command Context
- Confirm **command line** includes a remote path/URL; validate `Image` path/signature and **parent process**.  
- Check recent files/MRUs referencing remote sources.

#### 2) Destination Validation
- For **WebDAV**, pivot to **WebClient** (`svchost.exe`) traffic (ports **80/443**); use **proxy** logs for HTTP(S) metadata.  
- For **SMB**, validate **445** sessions and enumerate the accessed share/path.

#### 3) Artifact Discovery
- Search for **EID 11** file writes to **INetCache**/**temp**; hash and analyze.  
- Look for **execution** of downloaded artifacts (child processes).

#### 4) Correlation & Fleet
- Pivot on **destination**, **hashes**, and **CLI** patterns across hosts to assess spread.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\MSPUB.EXE`, destination details.  
- **Sysmon EID 1 / 4688:** Process creation context.  
- **Sysmon EID 11:** File writes following the connection.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.

### Containment Actions
- **Block** endpoints; **quarantine** artifacts; **terminate** activity; consider **host isolation** if code execution occurred.

### Prevention Measures
- Restrict direct use of Publisher on general endpoints; egress controls; monitor **rare process → network** pairs.  
- Alert on **Internet‑zone** content opened by Office helpers.

### Recovery
- Remove artifacts/persistence; tune detections/allowlists; update runbooks.

### False Positives
- Approved business workflows fetching Publisher assets from trusted internal portals.

---

## Playbook 3 — MSPUB DNS Queries (Sysmon EID 22)

### Overview
Investigate **DNS lookups** temporally tied to `MSPUB.EXE` execution. In **explicit proxy** environments, **EID 22** may only show queries to the **proxy FQDN**;
the actual destination resolves on the proxy. Still, **new/rare** domains proxied via Publisher are suspicious for **T1105** staging.

### Initial Response
1. **Capture records:** Export **EID 22** entries with process attribution; correlate to **EID 1/4688**.  
2. **Classify FQDNs:** Internal vs external; flag **DGA‑like** names, **raw‑IP URLs** in command line, **recently registered** domains (if TI available).  
3. **Proxy context:** If a proxy is in use, pull **proxy logs** to map proxy FQDN → upstream destination hostnames/URLs.

### Investigation Steps
#### 1) Process & Command Context
- Confirm `MSPUB.EXE` launch details and remote inputs in the **command line/MRUs**.  
- Review **user** and **parent** process to assess legitimacy.

#### 2) Destination Enrichment
- Enrich FQDNs (age, reputation).  
- Map proxy FQDN to upstream destinations using **proxy** telemetry (Host header/SNI).

#### 3) Artifact & Network Corroboration
- Check for **EID 3** egress and **EID 11** file writes aligned in time.  
- Hash/analyze any resultant artifacts; identify **child process** execution.

#### 4) Fleet & Follow‑On
- Pivot on **FQDN**, destination, and artifact hashes across the fleet to discover related activity.

### Key Artifacts
- **Sysmon EID 22:** DNS queries attributed to `MSPUB.EXE` (or proxy FQDN).  
- **Sysmon EID 1 / 4688:** Process creation context.  
- **Sysmon EID 3 / Proxy:** Network flows for the time window.  
- **Sysmon EID 11:** File creation side effects.

### Containment Actions
- **Block** suspicious domains; **quarantine** related artifacts; **terminate** processes; consider **host isolation** if execution observed.

### Prevention Measures
- Domain allowlists; restrict Office fetching from Internet; disable **WebClient** where not needed.  
- App control to limit `MSPUB.EXE` usage; ASR rules for Office behavior.

### Recovery
- Remove staged content/persistence; rotate credentials if exposure suspected; tune detections/runbooks.

### False Positives
- Publisher legitimately connecting to **internal** data sources or vendor portals; validate via owners/change tickets and allowlist.