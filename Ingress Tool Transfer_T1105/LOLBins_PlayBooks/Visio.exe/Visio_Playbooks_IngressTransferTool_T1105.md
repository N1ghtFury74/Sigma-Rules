# T1105 — Ingress Tool Transfer · LOLBin: Visio.exe (Microsoft Visio)
**Rules Covered:**  
- CNC-E-2726320-301 — Visio URL on Command Line (Process Creation)  
- CNC-E-2726320-302 — Visio Unusual Network Connection (Sysmon EID 3 / DNS EID 22)  
**Last updated:** 2025-10-28 16:35 UTC

> `Visio.exe` is a signed Microsoft Office binary used to open and render **.vsd/.vsdx** and related diagram formats. When invoked with a
> **remote URL/UNC/WebDAV path** on the command line, Visio (or helper components) may **fetch remote content** and cache artifacts, providing
> a potential path for **T1105 — Ingress Tool Transfer** and follow‑on execution chains via OLE/links/macros or external objects.

---

## Playbook 1 — URL on Command Line (Process Creation)

### Overview
Investigate **process creation** where `Visio.exe` is launched with a **remote locator** in its command line:
- `http(s)://host/path/file.vsdx` (flag raw IPs, shorteners, non‑standard ports)  
- `\\server\share\file.vsdx` (SMB UNC)  
- `\\host@SSL\DavWWWRoot\folder\file.vsdx` (WebDAV over HTTPS)

This indicates Visio is sourcing a document from a **remote location**, which can trigger downloads and cache writes under a trusted Office binary.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** for `Visio.exe` with full `CommandLine`, `ParentImage`, `User`, IL, CWD, timestamp.  
2. **Parse target:** Extract **scheme/host/port/path**; classify **internal vs external**; flag **raw IPs** and **new/rare domains**.  
3. **Secure artifacts:** Snapshot **INetCache**, `%TEMP%`, and recent **Office Recent Files** lists; copy & **hash** any cached content without opening it live.

### Investigation Steps
#### 1) Process & Lineage
- Validate binary path/signature (Microsoft Office root).  
- Review **parent** process (Outlook, Teams, browser, script host, RMM) and whether launch was **user‑initiated** vs **automated**.  
- Note window style or hidden launches (potentially scripted).

#### 2) Document Semantics
- Inspect the **.vsd/.vsdx** (offline) for **embedded OLE/links**, **external data connections**, or **pack URIs** to secondary resources.  
- Check for **macro‑like** or add‑in behaviors (Visio can host add‑ins/VBA in some editions).

#### 3) Network & DNS
- Correlate **Sysmon EID 3** egress from `Visio.exe` or helper services (WebClient for WebDAV).  
- Use **Sysmon EID 22** for DNS queries (proxy FQDN seen on endpoints in explicit‑proxy designs).  
- Inspect **proxy** logs for URL, method/status, bytes, content‑type; highlight **MIME/extension mismatches**.

#### 4) Artifact & Execution
- Review **Sysmon EID 11** for file writes in **INetCache/%TEMP%**; verify **Zone.Identifier** ADS.  
- Identify **child processes** (`mshta.exe`, `rundll32.exe`, `powershell.exe`, browser processes) soon after document open.

#### 5) Fleet Correlation
- Pivot by **destination host**, **CLI fragments** (`DavWWWRoot`, `@SSL`), **hashes** of the document, and **parent process** across endpoints.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Process creation metadata with full CLI and parent.  
- **Sysmon EID 3 / Proxy:** HTTP(S)/WebDAV/SMB egress details.  
- **Sysmon EID 22:** DNS queries aligned with the event.  
- **Sysmon EID 11:** Cache/temp file writes.  
- **Office MRU/RecentFiles:** Evidence of remote document open.

### Containment Actions
- **Block** destination hosts/domains; **quarantine** the document and cached artifacts; consider **host isolation** if execution occurred.

### Prevention Measures
- Egress controls and **allowlists** for Office binaries; disable **WebClient** if unneeded.  
- Office hardening: **Protected View**, block Internet macros/add‑ins, restrict external data connections.  
- App control to limit `Visio.exe` launched by **untrusted parents**.

### Recovery
- Remove staged artifacts/persistence; reset Office trust settings if altered; tune detections/allowlists.

### False Positives
- Legitimate business usage opening Visio files from **approved intranet/SharePoint/SMB** locations; validate via owners/change tickets and allowlist.

---

## Playbook 2 — Unusual Network Connection (Sysmon EID 3 / DNS EID 22)

### Overview
This playbook investigates **network/DNS activity** tied to `Visio.exe`. While opening local files is common, **egress to Internet/raw IPs** or **WebDAV**
is unusual and may indicate **T1105** staging or retrieval of external objects embedded in the diagram.

### Initial Response
1. **Capture records:** Export **Sysmon EID 3** (dest IP/host/port/proto) and **Sysmon EID 22** (DNS) and correlate to `Visio.exe` execution (EID 1/4688).  
2. **Classify destination:** Internal vs external; flag **raw IPs**, **unapproved TLDs**, **newly‑seen domains**, and **non‑standard ports**.  
3. **Scope user/asset:** Determine if the user commonly interacts with Visio diagrams from remote repositories.

### Investigation Steps
#### 1) Process & Command Context
- Retrieve **EID 1/4688** for `Visio.exe` to confirm presence of a **remote path** on the CLI and identify the **parent process**.  
- Identify **downstream** processes actually fetching content (browser/WebClient/script hosts) and gather their telemetry.

#### 2) Destination Validation
- Enrich destinations (reputation/ASN/age). Check **proxy** logs for method/status/bytes and content-type anomalies.  
- For **WebDAV UNC**, pivot to **WebClient** (`svchost.exe`) telemetry on ports **80/443**; for SMB, validate **445** sessions and shares.

#### 3) Artifact & Follow‑On
- Search **EID 11** for new files in **INetCache/%TEMP%**; **hash** and analyze.  
- Look for **child processes** executed shortly after (script hosts/LOLBins) and **module loads** from cached locations.

#### 4) Fleet & Blast Radius
- Pivot by **FQDN/IP**, **CLI fragments** (`DavWWWRoot`, `@SSL`), and **document hashes** across endpoints.

### Key Artifacts
- **Sysmon EID 3 / 22:** Network/DNS observables linked to the event.  
- **Sysmon EID 1 / 4688:** Process creation and parentage.  
- **Sysmon EID 11:** Cache/temp file writes aligned with the connection.  
- **EDR timeline:** Downstream handler behavior and child processes.

### Containment Actions
- **Block** suspicious hosts; **quarantine** artifacts; **terminate** activity; consider **host isolation** if execution is indicated.

### Prevention Measures
- Maintain **allowlists** for sanctioned destinations; enforce **egress** and **Office hardening** policies.  
- Alert on `Visio.exe` to **raw IPs** or **Internet‑zone** destinations; restrict risky protocol handlers.

### Recovery
- Remove artifacts/persistence; tune allowlists/detections; update playbooks and SOPs.

### False Positives
- Enterprise workflows leveraging Visio files from **approved intranet** locations; validate and allowlist accordingly.