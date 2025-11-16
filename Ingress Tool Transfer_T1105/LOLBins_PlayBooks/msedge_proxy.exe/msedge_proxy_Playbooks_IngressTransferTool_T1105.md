# T1105 — Ingress Tool Transfer · LOLBin: msedge_proxy.exe (Microsoft Edge Helper)
**Rules:**  
- CNC-E-2726320-174A — msedge_proxy URL on Command Line (Process Creation)  
- CNC-E-2726320-174B — msedge_proxy Network Connection (Sysmon EID 3)  
**Last updated:** 2025-10-28 06:38 UTC

> `msedge_proxy.exe` is an Edge‑signed helper binary used by Microsoft Edge/Updater components. When invoked directly with a **URL/remote path**,
> it can perform **HTTP(S)** fetches or broker network requests on behalf of Edge services. Adversaries abuse this to **download payloads**
> via a **Microsoft‑signed** process, aiding **Ingress Tool Transfer (T1105)** and evasion of simple allowlists.

---

## Playbook 1 — msedge_proxy URL on Command Line (Process Creation)

### Overview
Investigate **process creation** of `msedge_proxy.exe` where the **command line contains a URL** (e.g., `http(s)://…`) or **WebDAV/UNC** indicators
(e.g., `\\host@SSL\DavWWWRoot\…`, `\\host\share\…`). This suggests a **direct fetch** or brokered network action from a signed helper.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** with `Image`, full `CommandLine`, `ParentImage`, `User`, integrity level, working dir, timestamp.  
2. **Parse indicators:** Extract **scheme/host/port/path**; flag **raw IPs**, **new domains**, and **non‑standard ports**.  
3. **Secure artifacts:** Enumerate nearby **file writes** (cache/temp) and capture copies for hashing.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path under Edge install directories (e.g., `C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge_proxy.exe` or platform subfolders).  
- Review **parent** (Office, scripts, MSI, scheduled tasks, other LOLBins). Edge normally launches it; **non‑Edge parents** are suspicious.  
- Note flags that imply silent/background operation.

#### 2) Network & DNS
- Correlate **EID 3** (if attributed) and **proxy** logs for HTTP/S details; **EID 22** for DNS (or proxy FQDN in explicit proxy setups).  
- For **WebDAV UNC**, expect egress via **WebClient** `svchost.exe` (80/443) rather than direct process attribution.

#### 3) Artifact & Content Analysis
- Check **INetCache**, `%TEMP%`, and user‑writable locations for downloads; compute hashes, determine **true type** (PE/script/archive).  
- Inspect **Zone.Identifier** ADS and **extension ↔ MIME** mismatch; review **strings** for embedded URLs/C2 beacons.

#### 4) Correlation & Follow‑On
- Hunt for **child processes** executing the downloaded artifacts (PowerShell, rundll32, mshta, wscript, cmd).  
- Pivot fleet‑wide by **URL host**, **hash**, and **command‑line** pattern to find additional hits.

### Key Artifacts
- **Sysmon EID 1 / 4688:** `Image=...\\msedge_proxy.exe` with URL on the command line; `ParentImage`.  
- **Sysmon EID 11:** File writes in cache/temp paths around the execution time.  
- **Sysmon EID 3 / Proxy:** Outbound HTTP(S) sessions; SNI/Host, status, bytes.  
- **Sysmon EID 22:** DNS lookups aligned with the event.  
- **EDR timeline:** Child processes and module loads.

### Containment Actions
- **Block** destination domain/IP; **quarantine** artifacts; **terminate** the process chain; consider **host isolation** if execution occurred.

### Prevention Measures
- Egress filtering and **domain allowlists**; restrict direct invocation of Edge helpers via **AppLocker/WDAC**.  
- Alert on **rare process → URL** patterns and **non‑Edge parents** launching `msedge_proxy.exe`.

### Recovery
- Remove staged payloads/persistence; rotate credentials if exposure suspected; update allowlists/detections.

### False Positives
- Edge/enterprise update flows fetching from **approved Microsoft** domains, or sanctioned enterprise distribution endpoints. Validate via change tickets.

---

## Playbook 2 — msedge_proxy Outbound (Sysmon EID 3)

### Overview
This playbook covers **outbound connections** attributed to `msedge_proxy.exe`. While Edge may legitimately use the helper, **direct egress** to
**non‑Microsoft** or **new/rare** destinations, **raw IPs**, or **non‑standard ports** is suspicious for **T1105** staging.

### Initial Response
1. **Capture records:** Export **EID 3** (dest IP/host/port/proto) and correlate nearby **EID 1/4688** for `msedge_proxy.exe`.  
2. **Classify destination:** Internal vs external; explicitly distinguish **Microsoft update/CDN** endpoints from unknowns.  
3. **Scope role:** Determine whether the asset/user is expected to run Edge update/maintenance tasks at that time.

### Investigation Steps
#### 1) Process & Command Context
- Retrieve full **command line** and **parent**; identify explicit **URL** arguments or update subcommands.  
- Check Edge **version/update** telemetry to confirm genuine update cycles vs ad‑hoc launches.

#### 2) Destination Validation
- Enrich domains/IPs (age/reputation); compare to **allowlists** for Microsoft services (update/CDN/telemetry).  
- For **WebDAV/UNC** flows, pivot to **SMB**/**WebClient** logs.

#### 3) Artifact Discovery
- Search for **file creations** (Sysmon **EID 11**) and **cache** artifacts around the egress time; hash/analyze.  
- Identify any **execution** of retrieved content (child process chains).

#### 4) Correlation & Fleet
- Pivot on **destination**, **hashes**, and **command‑line** across endpoints; look for synchronous usage on multiple hosts.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\msedge_proxy.exe` with destination details.  
- **Sysmon EID 1 / 4688:** Process creation context (CLI, parent).  
- **Sysmon EID 11:** File writes tied to the connection.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables; SNI/Host, method, status, bytes.

### Containment Actions
- **Block** suspicious endpoints; **quarantine** artifacts; **terminate** activity; consider **host isolation** on execution.

### Prevention Measures
- Maintain strict **egress controls** and **Microsoft endpoint allowlists**; restrict direct invocation of helper binaries.  
- Alert on `msedge_proxy.exe` launched by **non‑Edge parents** and on **Internet‑zone** URL arguments.

### Recovery
- Remove artifacts/persistence; tune detections and allowlists; document deviations in runbooks.

### False Positives
- Legitimate Edge servicing or enterprise content fetches from approved domains/CDNs at expected maintenance windows. Validate via owners/schedules.