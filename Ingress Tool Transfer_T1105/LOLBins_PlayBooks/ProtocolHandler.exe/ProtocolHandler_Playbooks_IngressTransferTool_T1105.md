# T1105 — Ingress Tool Transfer · LOLBin: ProtocolHandler.exe (URL Protocol Dispatch Helper)
**Rules Covered:**  
- CNC-E-2726320-201 — ProtocolHandler URL on Command Line (Process Creation)  
- CNC-E-2726320-202 — ProtocolHandler Unusual Network Connection (Sysmon EID 3 or 22)  
**Last updated:** 2025-10-28 16:26 UTC

> `ProtocolHandler.exe` is a Microsoft‑signed helper used to **resolve and dispatch URI schemes** (e.g., `http`, `https`, custom `ms-` protocols) to the
> registered application. When invoked directly with a **remote URL** or **UNC/WebDAV path**, it can lead to **download or fetch operations** performed under a
> trusted binary, making it a useful primitive for **T1105 – Ingress Tool Transfer** or for launching downstream handlers that then fetch content.

---

## Playbook 1 — URL on Command Line (Process Creation)

### Overview
Investigate **process creation** of `ProtocolHandler.exe` where the **command line contains a remote locator**, such as:
- `http(s)://host/path` (raw IPs or non‑standard ports are especially suspicious)  
- `\\server\share\file`  (SMB UNC)  
- `\\host@SSL\DavWWWRoot\path\file` (WebDAV over HTTPS)  
This indicates that a signed **protocol dispatch** binary is being used to open or fetch remote content, potentially staging payloads or redirecting to downstream apps.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** with `Image`, full `CommandLine`, `ParentImage`, `User`, integrity level, CWD, and timestamp.  
2. **Parse target:** Extract **scheme/host/port/path** and classify **internal vs external**; flag **raw IPs**, **URL shorteners**, and **non‑standard ports**.  
3. **Secure artifacts:** Snapshot **INetCache**/**%TEMP%** around the event; capture any downloaded files, link/shortcut artifacts, or handoff files; compute **hashes**.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path/signature (typically under Windows components or app packages for protocol routing).  
- Review **parent** process to identify the delivery vector (browser, Outlook, Office, Teams, script host, scheduled task, RMM).  
- Check if the launch is **user‑initiated** vs background/automation.

#### 2) Command‑Line Semantics
- Confirm the **URI scheme** being dispatched (`http/https`, `ftp`, `ms-` custom, UNC/WebDAV).  
- Identify any **parameters** that would cause silent/open‑without‑prompt behavior for the handler app.  
- Note **output or handoff** indicators (temp files, app‑specific caches) that appear immediately after launch.

#### 3) Network & DNS Corroboration
- Correlate **Sysmon EID 3** egress attributed to `ProtocolHandler.exe` or the **downstream handler process** (browser, WebClient `svchost.exe`, etc.).  
- Use **Sysmon EID 22** for DNS queries (in explicit proxy setups, expect the **proxy FQDN** on the endpoint instead of the upstream host).  
- Inspect **proxy** logs for URL, method/status, bytes, content‑type, and JA3/UA anomalies.

#### 4) Artifact & Execution
- Check **Sysmon EID 11** for writes under **INetCache/%TEMP%** (e.g., HTML/JS/ZIP/EXE/DLL/LNK).  
- Review **child processes** spawned by the handler app (`msedge.exe`, `iexplore.exe` on legacy, `mshta.exe`, `rundll32.exe`, script hosts).  
- Validate **Zone.Identifier** ADS and extension↔MIME mismatches.

#### 5) Fleet Correlation
- Pivot on **destination hosts**, **CLI substrings** (e.g., `DavWWWRoot`, `@SSL`), **hashes** of artifacts, and **parent process** across endpoints.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Process creation details with full CLI and `ParentImage`.  
- **Sysmon EID 3 / Proxy:** Egress tied to `ProtocolHandler.exe` or its downstream handler.  
- **Sysmon EID 22:** DNS queries for destination or proxy FQDN.  
- **Sysmon EID 11:** Cache/temp file writes.  
- **EDR timeline:** Child processes and module loads.

### Containment Actions
- **Block** destination hosts/domains; **quarantine** artifacts; **terminate** malicious chains; consider **host isolation** if execution is confirmed.

### Prevention Measures
- Egress filtering and **allowlists**; disable **WebClient** when unneeded.  
- Application control (AppLocker/WDAC) to constrain direct use of `ProtocolHandler.exe` and risky protocol handlers on endpoints.  
- Harden Office/email/browsers to reduce automatic protocol activation and enforce prompts.

### Recovery
- Remove staged content/persistence; rotate credentials as needed; tune detections/allowlists and update runbooks.

### False Positives
- Legitimate enterprise workflows opening approved **SharePoint/intranet/SMB** resources via registered handlers. Validate via owner/change tickets and allowlist.

---

## Playbook 2 — Unusual Network Connection (Sysmon EID 3 or 22)

### Overview
This playbook investigates **network or DNS activity** associated with `ProtocolHandler.exe`. While the binary may simply pass the URI to a registered app,
**explicit network egress** or **DNS to non‑enterprise/non‑Microsoft destinations**, **raw IPs**, or **non‑standard ports** can indicate abuse for **T1105** staging.

### Initial Response
1. **Capture records:** Export **Sysmon EID 3** (dest IP/host/port/proto) and **EID 22** (DNS queries) correlating to the same time window and host.  
2. **Classify destination:** Internal vs external; flag **raw IPs**, **new/rare domains**, **suspicious TLDs**, and **non‑standard ports**.  
3. **Scope usage:** Determine if the user/asset regularly triggers protocol handlers for remote resources (baseline via historical telemetry).

### Investigation Steps
#### 1) Process & Command Context
- Retrieve **EID 1/4688** for `ProtocolHandler.exe`; confirm the **URI**/path used and the **parent process**.  
- Identify the **downstream handler** process that actually fetched content and collect its **CLI** and subsequent actions.

#### 2) Destination Validation
- Enrich destination domain/IP (reputation/ASN/age); verify **proxy** logs (Host/SNI, method/status/bytes).  
- For **WebDAV UNC** patterns, pivot to **WebClient** telemetry (ports **80/443**). For SMB UNC, validate **445** sessions and share paths.

#### 3) Artifact & Follow‑On
- Search **EID 11** for newly created files in **INetCache/%TEMP%**; **hash** and analyze.  
- Identify **child processes** executed shortly after (script hosts/LOLBins) and **module loads** from cached content.

#### 4) Fleet & Blast Radius
- Pivot by **FQDN/IP**, **CLI fragments** (e.g., `DavWWWRoot`, `@SSL`), and **hashes** across endpoints to uncover related activity.

### Key Artifacts
- **Sysmon EID 3 / 22:** Network/DNS observables linked to the event.  
- **Sysmon EID 1 / 4688:** Process creation context and parentage.  
- **Sysmon EID 11:** Cache/temp file writes aligned with the connection.  
- **EDR timeline:** Downstream handler behavior.

### Containment Actions
- **Block** suspicious hosts; **quarantine** artifacts; **terminate** chains; consider **host isolation** if execution is indicated.

### Prevention Measures
- Maintain **allowlists** for sanctioned destinations; enforce **egress controls**.  
- Reduce automatic protocol activations; restrict risky handlers via policy or app control.  
- Alert on `ProtocolHandler.exe` to **raw IPs** or **Internet‑zone** destinations.

### Recovery
- Remove artifacts/persistence; tune allowlists/detections; update SOPs.

### False Positives
- Business workflows leveraging custom enterprise protocols or intranet resolvers; validate and allowlist as appropriate.