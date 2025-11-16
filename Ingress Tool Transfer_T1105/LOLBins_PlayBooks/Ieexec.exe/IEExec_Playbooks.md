# T1105 — Ingress Tool Transfer · LOLBin: IEExec.exe  
**Rules:**  
- CNC-E-2726320-158 — IEExec Process Execution (Legacy)  
- CNC-E-2726320-159 — IEExec Network Connection (Sysmon EID 3)  
- CNC-E-2726320-160 — IEExec FileCreate (Unexpected) · Sysmon EID 11  
**Last updated:** 2025-10-28 05:58 UTC

> `IEExec.exe` is the **.NET Internet Explorer Execution engine** (ClickOnce/URL‑Launched .NET host). It can load and run managed assemblies
> from **HTTP/HTTPS**, **UNC/WebDAV**, and **file** URLs under legacy **Code Access Security (CAS)** trust decisions. Adversaries repurpose it to
> **fetch and execute** payloads from remote locations (T1105) while leveraging a **Microsoft‑signed** binary (LOLBin).

---

## Playbook 1 — IEExec Process Execution (Legacy)

### Overview
Investigate alerts where **`IEExec.exe`** is launched (Sysmon **EID 1** / Security **4688**). Suspicious indicators include **URL operands**
(`http(s)://`, `file://`, `\\host\share`, `\\host@SSL\DavWWWRoot\...`) and execution from **user‑writable** directories. This often
indicates **download‑and‑run** of managed code via a signed host.

### Initial Response
1. **Preserve context:** Export full **process creation** (image, command line, parent, user, integrity level, working dir, timestamp).  
2. **Parse source:** Extract **scheme/host/port/path**; treat **raw IPs**, **non‑standard ports**, and **new domains** as high‑signal.  
3. **Collect artifacts:** If a local path is referenced (e.g., after prior download), **acquire** the assembly and dependent files.

### Investigation Steps
#### 1) Process & Lineage
- Verify `Image` path (e.g., `C:\\Windows\\Microsoft.NET\\Framework(64)\\v*\\IEExec.exe`) and signer metadata.  
- Inspect `ParentImage` (Office, browser, script host, another LOLBin) and document the **launch chain**.  
- Identify CAS/zone context (Internet/Intranet) implied by **URL scheme/host**.

#### 2) Command‑Line Semantics
- Recognize patterns like:  
  - `IEExec.exe http(s)://host/app.exe` (managed assembly delivered over HTTP(S))  
  - `IEExec.exe file://\\host\share\app.exe` or WebDAV UNC (`\\host\DavWWWRoot\...`)  
- Note **parameters** after the assembly path (often passed to the managed entry point).

#### 3) Artifact & Execution Analysis
- If an assembly was downloaded first, verify **file creation** (Sysmon **EID 11**), hash, and **PE/CLR** markers.  
- Review **module loads** for CLR (`clr.dll`, `mscorwks/mscoree`) around the event.  
- Hunt for **child processes** spawned by the managed code (PowerShell/mshta/wscript/rundll32).

#### 4) Network & DNS Corroboration
- Check **Sysmon EID 3** (if attributed) and **EID 22** DNS for the destination host (or **proxy FQDN** in explicit‑proxy setups).  
- If **WebDAV**, expect egress by **WebClient** `svchost.exe` rather than `IEExec.exe`; pivot to **proxy** logs for HTTP details.

### Key Artifacts
- **Sysmon EID 1 / 4688:** `Image=...\\IEExec.exe`, full `CommandLine`, parent, user.  
- **Sysmon EID 11:** Downloaded or staged assemblies/configs.  
- **Sysmon EID 3 / Proxy:** Outbound connections to URL/UNC endpoints.  
- **Sysmon EID 22:** DNS queries to destination or proxy FQDN.  
- **EDR timeline:** CLR loads and child process graph.

### Containment Actions
- **Terminate** the process chain; **quarantine** retrieved assemblies; **block** destination host/IP/domain.  
- Consider **host isolation** if follow‑on execution/persistence is confirmed.

### Prevention Measures
- **AppLocker/WDAC** to restrict `IEExec.exe` usage; allow only trusted admin stations.  
- Enforce **egress filtering** and **domain allowlists**; disable **WebClient** where not needed.  
- Prefer modern deployment mechanisms; deprecate ClickOnce/CAS paths where possible.

### Recovery
- Remove payloads/persistence; rotate any exposed credentials; tune allowlists/detections; document deviations.

### False Positives
- Rare legacy **ClickOnce** or **intranet** apps invoked by `IEExec.exe`. Validate via owners/change records and known service URLs.

---

## Playbook 2 — IEExec Network Connection (Sysmon EID 3)

### Overview
This playbook covers alerts where **`IEExec.exe`** shows **outbound network connections**. Normal usage can be local/intranet, but
process‑attributed egress to **Internet hosts**, **raw IPs**, or **non‑standard ports** is suspicious and consistent with **T1105**.

### Initial Response
1. **Capture records:** Export **EID 3** (dest host/IP/port) and correlate to nearby **process creation** (EID 1/4688).  
2. **Classify destination:** Internal vs external; enrich reputation/age; note **TLS SNI/URL** in proxy logs if available.  
3. **Scope role:** Determine if the device/user legitimately uses legacy URL‑hosted .NET apps.

### Investigation Steps
#### 1) Process & Lineage
- Confirm `Image` path/signature; review `ParentImage` and **command line** for URL/UNC indicators.  
- Identify working directory and any **referenced local outputs**.

#### 2) Destination Validation
- **HTTP/HTTPS:** Pivot to **proxy** details (method, status, bytes).  
- **WebDAV UNC:** Expect egress from **`svchost.exe` (WebClient)**; attribute accordingly.  
- **SMB UNC:** Corroborate **port 445** sessions and **logon type 3** events.

#### 3) Artifact Discovery
- Search for **file creations** (EID 11) adjacent to the connection window (assemblies/configs/logs).  
- Hash/analyze content; confirm **managed PE** characteristics where applicable.

#### 4) Correlation & Follow‑On
- Hunt for **child process** execution or lateral launches after the connection.  
- Perform **fleet prevalence** on destinations and file hashes.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\IEExec.exe`, destination details.  
- **Sysmon EID 1 / 4688:** Launch context and `CommandLine`.  
- **Sysmon EID 11:** File writes tied to network activity.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.

### Containment Actions
- **Block** destination; **terminate** activity; **quarantine** artifacts; consider **host isolation** on execution.

### Prevention Measures
- Egress filtering/allowlists; disable **WebClient** if unused; restrict `IEExec.exe` via **application control**.  
- Monitor **rare process → network** pairs and **Internet‑zone** usage.

### Recovery
- Remove payloads/persistence; tune detections; update runbooks/allowlists.

### False Positives
- Intranet‑hosted legacy applications accessed during maintenance windows; validate by ticket/owner.

---

## Playbook 3 — IEExec FileCreate (Unexpected) · Sysmon EID 11

### Overview
Investigate **file creations** where `IEExec.exe` is the actor. Managed payloads may **drop support files**, configs, or even additional
binaries. In malicious use, this represents **staging** of tools fetched from remote sources (**T1105**).

### Initial Response
1. **Secure artifacts:** Copy and **hash** created files; preserve timestamps and **owner**.  
2. **Trace lineage:** Link the **EID 11** to prior `IEExec.exe` **EID 1/4688** and any **EID 3/22** activity.  
3. **Assess location:** Treat writes under **%TEMP%**, **%USERPROFILE%**, **AppData** (Roaming/Local/LocalLow), **Downloads**, or **Public** as higher risk.

### Investigation Steps
#### 1) Artifact Inspection
- Determine **type** (managed PE/script/archive/config). Look for **CLR headers**, **App.config**, **ClickOnce manifests**, or **embedded URLs**.  
- Check **extension ↔ MIME** consistency, **entropy**, and suspicious strings.  
- Identify whether the file is **child‑executed** shortly after creation.

#### 2) Process Context
- Retrieve `IEExec.exe` **command line** to confirm **source URL/UNC**; examine `ParentImage` and user context.  
- Review module loads and **.NET runtime** telemetry if available.

#### 3) Network & DNS Corroboration
- Correlate with **EID 3** (process‑attributed) or **WebClient svchost.exe** flows for WebDAV.  
- Review **EID 22** DNS queries (or proxy FQDN) near the write time.

#### 4) Follow‑On & Fleet
- Search for **execution** of created files or use by sibling tools (PowerShell/mshta/wscript/rundll32).  
- Run **fleet prevalence** for file hashes and the source destination.

### Key Artifacts
- **Sysmon EID 11:** `TargetFilename` created by `IEExec.exe`.  
- **Sysmon EID 1 / 4688:** Prior process launch and command line.  
- **Sysmon EID 3 & 22 / Proxy:** Corroborating network/DNS.  
- **EDR timeline:** Child processes and module loads.

### Containment Actions
- **Quarantine** created files; **block** destinations; **terminate** related activity; consider **host isolation** if code exec observed.

### Prevention Measures
- Restrict `IEExec.exe` via **AppLocker/WDAC**; block Internet‑zone use from endpoints.  
- Enforce **egress controls** and disable **WebClient** if unused; alert on **rare process → file‑write** patterns.

### Recovery
- Remove artifacts/persistence; rotate exposed credentials; update tuning and documentation.

### False Positives
- Legacy **ClickOnce** or intranet .NET apps legitimately writing caches/configs under user profiles; validate by owner/change ticket.