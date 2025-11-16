# T1105 — Ingress Tool Transfer · LOLBin: ngen.exe (Native Image Generator)
**Rules:**  
- CNC-E-2726320-175 — NGen URL on Command Line (Process Creation)  
- CNC-E-2726320-176 — NGen Outbound Network Connection (Sysmon EID 3)  
**Last updated:** 2025-10-28 07:06 UTC

> `ngen.exe` (Native Image Generator) precompiles .NET assemblies into native images to improve startup performance. In normal use it
> operates on **local** assemblies under administrative contexts (e.g., install-time, servicing). Adversaries may abuse `ngen.exe` by
> supplying **remote assembly locations** (HTTP(S), WebDAV, UNC) to cause a **signed Microsoft binary** to fetch and stage content, which
> aligns with **T1105 — Ingress Tool Transfer**. Network activity by `ngen.exe` is rare in most environments and warrants investigation.

---

## Playbook 1 — NGen URL on Command Line (Process Creation)

### Overview
Investigate **process creation** of `ngen.exe` where the **command line includes a URL or remote path**, e.g.:
- `http(s)://…/payload.dll`  
- `\\server\share\app\assembly.dll`  
- `\\host@SSL\DavWWWRoot\path\assembly.dll` (WebDAV over HTTPS)  
Such usage suggests **remote sourcing** of an assembly or manifest for compilation / probing, which can force a **download** or staged copy.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** with `Image`, full `CommandLine`, `ParentImage`, `User`, integrity level, CWD, timestamp.  
2. **Parse target:** Extract **scheme/host/port/path** and classify **internal vs external**; flag **raw IPs** and **non‑standard ports**.  
3. **Secure artifacts:** Snapshot `%TEMP%`, `%WINDIR%\assembly\NativeImages_*` (or `C:\Windows\assembly\NativeImages_*`) and relevant working dirs; copy & **hash** any newly written files.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path/signature (`C:\Windows\Microsoft.NET\Framework*\ngen.exe`).  
- Review **parent** (msiexec, powershell, cmd, sccm/installer, office/script hosts). Non‑installer parents are suspicious.  
- Note elevation context; `ngen` often runs **elevated** in legit scenarios.

#### 2) Command‑Line Semantics
- Identify assembly targets and options (e.g., `install`, `update`, `executeQueuedItems`).  
- Confirm whether the argument is a **file path** that points remote, a **manifest**, or a **dependency** that triggers remote fetch via CLR/fusion.  
- For WebDAV/UNC patterns (`DavWWWRoot`, `@SSL`), downloads may be brokered by **WebClient** `svchost.exe` over **80/443**.

#### 3) Artifact & Content Analysis
- Inspect created files under **NativeImages_*** and `%TEMP%`; determine **true type** (PE/CLR), compute **hashes**, check **Zone.Identifier** ADS.  
- Look for **module load** or **child process** activity soon after (e.g., the compiled image being executed by another process).

#### 4) Network & DNS Corroboration
- Correlate with **Sysmon EID 3** attributed to `ngen.exe` (rare) and with **proxy** logs (HTTP(S) requests).  
- Check **Sysmon EID 22** DNS (or proxy FQDN in explicit proxy setups).  
- If SMB was used, validate **445** sessions and share access.

#### 5) Correlation & Fleet
- Pivot by **destination host**, **assembly name**, **hashes** of any staged artifacts, and **CLI substrings** across the fleet.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Full CLI with remote path; `ParentImage`.  
- **Sysmon EID 11:** File writes in **NativeImages_*** or `%TEMP%`.  
- **Sysmon EID 3 / Proxy:** Outbound HTTP(S)/WebDAV or SMB flows.  
- **Sysmon EID 22:** DNS lookups aligned with execution.  
- **EDR timeline:** Child processes or module loads of the new native image.

### Containment Actions
- **Block** destination hosts; **quarantine** staged assemblies; **terminate** process chain; consider **host isolation** if execution occurred.

### Prevention Measures
- Restrict `ngen.exe` to **installer/servicing** contexts via **AppLocker/WDAC** and **least privilege**.  
- Egress controls to prevent developer/endpoint **Internet‑zone** assembly fetching; disable **WebClient** if unused.  
- Alert on **rare process → URL/UNC** patterns for `ngen.exe`.

### Recovery
- Remove staged artifacts/persistence; rotate credentials if exposure suspected; tune detections and allowlists.

### False Positives
- Dev/build servers legitimately compiling assemblies from **approved** internal UNC shares or package sources. Validate via owner/tickets.

---

## Playbook 2 — NGen Outbound Network Connection (Sysmon EID 3)

### Overview
This playbook investigates **outbound connections** attributed to `ngen.exe`. Legitimate `ngen` runs are usually local; outbound traffic indicates
**remote sourcing** (HTTP(S), WebDAV, SMB) and may reflect **T1105** staging.

### Initial Response
1. **Capture records:** Export **EID 3** (dest IP/host/port/proto) and correlate with **EID 1/4688** for `ngen.exe`.  
2. **Classify destination:** Internal vs external; flag **raw IPs**, **new/rare domains**, and **non‑standard ports**.  
3. **Scope role:** Determine if the host is an **installer/build** system where `ngen` network usage is expected.

### Investigation Steps
#### 1) Process & Command Context
- Retrieve full **command line** (identify assembly/manifest path); validate `Image`/signature and **parent**.  
- Check for **WebDAV/UNC** indicators; note if execution occurred during **setup/servicing windows**.

#### 2) Destination Validation
- Enrich domains/IPs and inspect **proxy** logs (Host/SNI, method/status/bytes).  
- For WebDAV, pivot to **WebClient** telemetry (`svchost.exe` on ports 80/443). For SMB, validate **445** sessions and accessed shares.

#### 3) Artifact Discovery
- Search for **EID 11** writes (NativeImages_*, `%TEMP%`); hash and classify artifacts.  
- Look for **follow‑on execution** of compiled images by other processes (EDR module loads).

#### 4) Correlation & Fleet
- Pivot on **destinations**, **hashes**, and **CLI** patterns; cluster by **parent process** and **user** across endpoints.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\ngen.exe`, destination host/IP/port.  
- **Sysmon EID 1 / 4688:** Process creation and CLI context.  
- **Sysmon EID 11:** File creation associated with staging/compilation.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.

### Containment Actions
- **Block** suspicious endpoints; **quarantine** artifacts; **terminate** activity; consider **host isolation** if execution was observed.

### Prevention Measures
- Limit `ngen.exe` usage to sanctioned scenarios; enforce **egress filtering**; monitor **rare process → network** pairs.  
- Application control to prevent `ngen.exe` invocation by **untrusted parents** (e.g., Office, script hosts).

### Recovery
- Remove staged artifacts/persistence; tune detections and allowlists; update runbooks.

### False Positives
- Controlled enterprise packaging/build pipelines that momentarily pull assemblies from **internal** repositories or shares.