# T1105 — Ingress Tool Transfer · LOLBin: Scrobj.dll (Script Component/TypeLib)
**Rule covered:** CNC-E-2726320-175 — Scrobj.dll GenerateTypeLib URL → INetCache (Process Creation)  
**Last updated:** 2025-10-28 06:18 UTC

> `scrobj.dll` is the **Script Component Runtime** used by Windows Script and COM to host script components and generate type libraries.
> When invoked (often via `rundll32.exe`) with a **URL operand**, it may retrieve remote script/component content and write artifacts under
> **INetCache**. Adversaries can abuse this to stage content from **HTTP/HTTPS/WebDAV** and hand off to script engines or COM consumers.

---

## Playbook — Scrobj.dll URL → INetCache (Process Creation)

### Overview
Investigate cases where **`rundll32.exe`** loads **`scrobj.dll`** (or equivalent host) and a **URL/UNC** appears in the command line, followed by
**file writes** to **INetCache**. This pattern indicates **remote retrieval** of script/COM component data—consistent with **T1105**.

### Initial Response
1. **Preserve context:** Export **process creation** (Sysmon EID 1 / Security 4688): `Image`, full `CommandLine`, `ParentImage`, `User`, IL, timestamp.  
2. **Parse source:** Extract **scheme/host/port/path**; classify internal vs external; flag **raw IPs** and **non‑standard ports**.  
3. **Secure artifacts:** Capture **INetCache** outputs attributed to this execution and compute **hashes**.

### Investigation Steps
#### 1) Process & Lineage
- Confirm `Image` = `rundll32.exe` with `CommandLine` loading `scrobj.dll` export (e.g., `rundll32.exe scrobj.dll,SomeExport <URL>`).  
- Validate the `rundll32.exe` **path/signature**; review **parent** (Office, browser, script host) for phishing/macros.

#### 2) Network & DNS
- **Sysmon EID 3** (if attributed) and **proxy** logs for HTTP/S; **EID 22** for DNS (or proxy FQDN in explicit‑proxy scenarios).  
- For **WebDAV** (`\\host\DavWWWRoot\` / `@SSL`), expect egress via **WebClient** `svchost.exe` on **80/443**.

#### 3) Artifact Analysis
- Review **INetCache** files (names, types, sizes). Check **extension↔MIME** consistency, **strings**, **entropy**.  
- Identify **follow‑on** consumer processes (e.g., `wscript.exe`, `powershell.exe`, `mshta.exe`) reading the cache files.

#### 4) Correlation & Fleet
- Pivot on **destination**, **cache file hashes**, and **command‑line pattern** across endpoints to scope spread.

### Key Artifacts
- **Sysmon EID 1 / 4688:** `rundll32.exe` loading `scrobj.dll` with a **URL/UNC**.  
- **Sysmon EID 11:** Writes under **INetCache** or user‑writable paths.  
- **Sysmon EID 3 / 22 / Proxy:** Network/DNS corroboration.  
- **EDR timeline:** Child processes consuming the cached content.

### Containment Actions
- **Block** destination host/domain; **quarantine** cache artifacts; **terminate** process chain; consider **host isolation** if execution observed.

### Prevention Measures
- Constrain `rundll32.exe` DLL entry points via **AppLocker/WDAC** and block **Internet‑zone** use.  
- Egress filtering and **domain allowlists**; disable **WebClient** if unused.  
- Alert on **rare process→URL** for DLL hosts and **INetCache** writes by those hosts.

### Recovery
- Remove staged content/persistence; tune detections/allowlists; rotate any exposed credentials.

### False Positives
- Rare intranet automation hosting signed script components. Validate with app owners and allowlist approved domains.