# T1105 — Ingress Tool Transfer · LOLBin: ConfigSecurityPolicy.exe  
**Rule:** CNC-E-2726320-138 — ConfigSecurityPolicy Network Transfer · Process Creation  
**Last updated:** 2025-10-28 04:25 UTC

---

## Overview
This playbook supports investigation of alerts where **`ConfigSecurityPolicy.exe`** is executed with **process-creation arguments**
that indicate **network transfer** behavior (e.g., HTTP/HTTPS URLs, UNC/WebDAV paths, or explicit proxy usage). Although
the binary is intended for configuration/security policy workflows, adversaries may leverage it to **retrieve** or **stage**
content through enterprise egress paths as a **living-off-the-land** **Ingress Tool Transfer (T1105)** step.

---

## Attack Context
- **Technique:** T1105 — Ingress Tool Transfer  
- **Binary:** `ConfigSecurityPolicy.exe` (signed Windows component)  
- **Detection intent (this rule):** Process creation where the command line shows a **remote destination**:  
  - **URLs**: `http://`, `https://` (optionally with non‑standard ports)  
  - **UNC/WebDAV**: `\\host\share\...`, `\\host\DavWWWRoot\...`, `\\host@SSL\DavWWWRoot\...`  
  - **Proxies/flags**: per‑invocation or system proxy usage that implies remote fetch
- **Typical operator goal:** Stage small tools/configs to disk for later execution or configuration pivoting.

---

## Initial Response
1. **Preserve context:** Export the full **process-creation** record (image, command line, parent, user, integrity level, timestamp).  
2. **Extract destination:** Parse the command line for **URLs/UNC**; capture **host, path, port**, and **query** elements.  
3. **Collect artifacts:** Identify **output paths** or inferred write locations; immediately **acquire** those files (hash + copy).  
4. **Classify asset:** Determine whether this endpoint is expected to run policy/config tooling under current user/role.

---

## Investigation Steps

### 1) Process and Image Analysis
- Confirm `Image` is the trusted path (e.g., `C:\\Windows\\System32\\ConfigSecurityPolicy.exe`) and verify signer/metadata.  
- Review `ParentImage` and `ParentCommandLine` for suspicious launch chains (script hosts, Office, other LOLBins).  
- Document **all switches** and **operands**; note any **download targets**, **working directory**, or **redirections** (`>`, `>>`).

### 2) Command-Line Semantics
- Identify whether the remote reference is a **URL** or **UNC/WebDAV**.  
- For URLs, note **scheme**, **host**, **port**, and **path**; treat **raw IPs**, **non‑standard ports**, and **new domains** as high risk.  
- For UNC/WebDAV, record the **server** and **share**; determine if **WebClient** service involvement is likely (DavWWWRoot/@SSL).

### 3) File and Path Analysis
- Locate **new or modified files** near the alert time in **%TEMP%**, **%ProgramData%**, **user profile**, and **current working dir**.  
- Compute **hashes**, extract **strings**, and determine **file type** (PE/script/text/archive); evaluate **entropy** and **headers**.  
- Prioritize artifacts in **user‑writable** paths and with **suspicious extensions** or **mismatched types**.

### 4) Network and DNS Corroboration
- **DNS (EID 22):** Lookups for destination host (or **proxy FQDN** if explicit proxy is used).  
- **Network (EID 3 / Proxy):** Connections attributable to `ConfigSecurityPolicy.exe` or to the **WebClient/Proxy service**.  
- Where proxy logs exist, confirm **method** (GET/POST), **status**, **response size**, and **SNI/Host** for TLS.  
- If the path is WebDAV UNC, correlate egress from **`svchost.exe`** hosting WebClient over **80/443**.

### 5) Correlation & Follow‑On
- Hunt for **follow‑on execution** of the downloaded artifact (child process of `ConfigSecurityPolicy.exe` or shortly after).  
- Pivot to related binaries (`powershell.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`) launching near the same time.  
- Perform **fleet prevalence** checks on the **URL/domain/IP** and the **artifact hash**.

---

## Key Artifacts
- **Process Creation (EID 1 / 4688):** `Image=...\\ConfigSecurityPolicy.exe`, full `CommandLine`, `ParentImage`, `User`.  
- **File Creation (EID 11):** New `TargetFilename` written by `ConfigSecurityPolicy.exe`.  
- **DNS (EID 22):** `QueryName` for destination (or proxy FQDN).  
- **Network (EID 3 / Proxy):** Destination IP/host/port and request details; WebDAV flows may be seen under **WebClient svchost**.  
- **EDR timeline:** Process lineage and module loads tied to staged content.

---

## Containment Actions
- **Quarantine** any staged files; **block** destination domain/IP; if WebDAV, **delete mappings** or disable session.  
- **Terminate** suspicious processes and consider **host isolation** if execution/persistence is observed.  
- If sensitive configs/credentials might be exposed, coordinate **rotation** and **policy resets**.

---

## Prevention Measures
- Apply **application control** (AppLocker/WDAC) to restrict unsanctioned use of configuration/installer tools.  
- Maintain **allowlists** for approved update/config endpoints; alert on **new/unapproved** hosts and **raw IP** usage.  
- Restrict execution from **user‑writable** paths; enable **AMSI/script** telemetry for follow‑on tooling.  
- Enforce **egress filtering** and monitor **WebClient** usage if WebDAV is not a business requirement.

---

## Recovery
- Remove malicious content and any **persistence**; revert unintended configuration changes.  
- Tune detections with environment‑specific allowlists; document deviations and update runbooks.

---

## False Positives
- **Legitimate configuration deployment** using `ConfigSecurityPolicy.exe` that fetches policy from **approved** internal servers.  
- **IT automation** in sanctioned maintenance windows pulling templates or policy bundles.  
- Mitigation: Add **approved domains/UNC paths** to allowlists and validate against **tickets/owners**.