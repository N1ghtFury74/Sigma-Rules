# T1105 — Ingress Tool Transfer · LOLBin: cmd.exe  
**Rules:**  
- CNC-E-2726320-134 — Cmd.exe Copy_Noisyone  
- CNC-E-2726320-134 — Cmd.exe CopyType to WebDAV  
**Last updated:** 2025-10-28 04:20 UTC

---

## Playbook 1 — Cmd.exe Copy_Noisyone (Process Creation: `copy`-based ingress)

### Overview
This playbook guides investigation when **`cmd.exe`** launches with command‑line patterns indicating **file copy** for potential ingress (e.g., `cmd.exe /c copy <src> <dst>`). Operators commonly leverage **UNC paths** (SMB or WebDAV‑mapped) or local staging paths to pull or place payloads as part of **Ingress Tool Transfer (T1105)**. Because **`copy`** is a built‑in cmd.exe command, resulting file writes are often attributed to **`cmd.exe`** itself.

### Attack Context
- **Technique:** T1105 — Ingress Tool Transfer  
- **Binary:** `cmd.exe` (internal `copy` command)  
- **Typical abuse paths:**
  - **SMB UNC:** `\\\host\share\path\file` (port 445)
  - **Mapped drives:** `Z:\\path\file` that back to SMB/WebDAV
  - **User‑writable staging:** `%TEMP%`, `%PUBLIC%`, `Downloads\`, Desktop

### Initial Response
1. **Snapshot the event:** Export the full **process creation** record (`Image`, `CommandLine`, `ParentImage`, `User`).  
2. **Parse operands:** Extract **source** and **destination** arguments from the `copy` command.  
3. **Collect artifacts:** Acquire the **destination file** immediately (hash, copy, quarantine if required).  
4. **Classify host/user:** Determine whether administrative copy operations are expected on this endpoint.

### Investigation Steps
#### 1) Process and Image Analysis
- Verify `Image` = `C:\\Windows\\System32\\cmd.exe` (or `SysWOW64\\cmd.exe`).  
- Review `ParentImage` for suspicious launch chains (script engines, Office, LOLBins).  
- Confirm presence of `copy`, `/y` (overwrite), `/b` (binary) switches, and operands order.
#### 2) File and Path Analysis
- Identify **destination path**; check if **user‑writable**.  
- Compute **hash** (MD5/SHA256), extract **strings**, determine **file type** (PE/script/text/archive).  
- Look for **extension mismatch** or **randomized names**.
#### 3) Network and Protocol Corroboration
- If **SMB UNC** used, review **SMB session** telemetry and **Security logs** for network logon (type 3).  
- For mapped drives, confirm the **backing share/WebDAV** and timing of the mapping (e.g., `net use`).  
- Validate **DNS** lookups and **network flows** to the relevant host (SMB 445 or WebDAV 80/443 via WebClient).
#### 4) Follow‑On Execution
- Hunt for **immediate execution** of the copied file (child of `cmd.exe` or launched moments later).  
- Pivot to related binaries (`powershell.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`).  
- Check **fleet prevalence** for the hash/path.

### Key Artifacts
- **Process Creation (EID 1 / 4688):** `Image=...\\cmd.exe`, `CommandLine` with `copy` operands.  
- **File Create (EID 11):** `TargetFilename` written by `cmd.exe`.  
- **DNS (EID 22):** Queries to remote host (if UNC to remote).  
- **Network (EID 3 / SMB telemetry):** Connections to `445` (SMB) or to WebDAV backends.  
- **Logon events:** Network logon (type 3) to the file server; `net use` mappings near the time of copy.

### Containment Actions
- Quarantine the **destination file**; **disable** any mapped path or credential used.  
- **Block** external hosts involved; consider **host isolation** if execution observed.

### Prevention Measures
- Restrict write access to **user‑writable** high‑risk paths; enforce **application control** on script/PE execution from them.  
- Hard‑en **SMB** (signing, firewalling) and monitor **drive mappings**.

### Recovery
- Remove staged payloads and any persistence; reset compromised credentials; re‑baseline shares/mappings.

### False Positives
- Legitimate admin or deployment scripts performing bulk copies. Validate **change tickets**, **operators**, and **approved shares**.

---

## Playbook 2 — Cmd.exe CopyType to WebDAV (Process Creation: `copy`/`type` → WebDAV UNC)

### Overview
This playbook covers alerts where **`cmd.exe`** uses **`copy`** or **`type`** to **write to WebDAV UNC paths**, a common way to exfiltrate or **ingress** content through HTTP(S)‑backed WebDAV shares. Windows’ **WebClient** service translates WebDAV UNC paths to HTTP(S) requests handled by **`svchost.exe`**, so network activity may not appear under `cmd.exe` directly.

### Attack Context
- **Technique:** T1105 — Ingress Tool Transfer  
- **Binary:** `cmd.exe` (`copy`, `type`) with **WebDAV UNC** paths  
- **Canonical WebDAV UNC forms:**
  - `\\\host\DavWWWRoot\path\file`
  - `\\\host@SSL\DavWWWRoot\path\file` (HTTPS)
  - Optional ported form: `\\\host@{port}\DavWWWRoot\path\file`
- **Notes:** Adversaries can first map a drive (`net use * \\\\host\DavWWWRoot /user:...`) then use `copy`/`type` to place or fetch payloads.

### Initial Response
1. **Preserve the record:** Export **process creation** with the full `CommandLine`.  
2. **Confirm WebDAV semantics:** Identify **UNC operands** that match `DavWWWRoot` or `@SSL` patterns.  
3. **Collect artifacts:** If writing **to** WebDAV, collect the **source** file; if writing **from** WebDAV, collect the **destination** file.  
4. **Scope identity:** Review credentials in recent `net use` or **stored credentials** used by WebClient.

### Investigation Steps
#### 1) Process and Image Analysis
- Validate `Image` path of `cmd.exe`; review `ParentImage` for initial vector.  
- Confirm `copy` or `type` usage and operand ordering (direction of transfer).  
- Note use of `/y` (overwrite), `/b` (binary) or redirections (`>`, `>>`).

#### 2) WebDAV Path & Service Correlation
- Enumerate **WebClient service** status on the endpoint.  
- On the same timeline, check **`svchost.exe`** instances hosting **WebClient** for **network egress** to the target host.  
- Confirm **DNS lookups** for the WebDAV host; in TLS, capture **SNI/host** via proxy where available.

#### 3) File & Path Analysis
- If **downloading from WebDAV**, locate the **destination file** on disk; hash, inspect type/entropy, and path risk.  
- If **uploading to WebDAV**, determine if sensitive content was staged; coordinate with DLP/IR for potential **exfil**.  
- Review local **staging directories** used in the command (Temp/Public/Downloads).

#### 4) Follow‑On & Lateral Context
- Hunt for execution of downloaded artifacts or subsequent tooling that references the same WebDAV host.  
- Check **fleet prevalence** of the host and path; search for other endpoints interacting with the same WebDAV server.

### Key Artifacts
- **Process Creation (EID 1 / 4688):** `cmd.exe` command line with `copy`/`type` + `DavWWWRoot`/`@SSL`.  
- **File Create (EID 11):** Destination file writes attributed to `cmd.exe`.  
- **DNS (EID 22):** Queries for the WebDAV host.  
- **Network (EID 3 / Proxy):** Egress performed by **`svchost.exe` (WebClient)** over **80/443**; confirm PUT/GET semantics if logs exist.  
- **Mapped drives:** `net use` events and current mappings to WebDAV endpoints.

### Containment Actions
- **Invalidate** the WebDAV session (`net use /delete`) and **stop** WebClient if not required.  
- **Block** the WebDAV host at the proxy/firewall; quarantine downloaded payloads; consider **host isolation**.

### Prevention Measures
- Disable **WebClient** where not needed; restrict **WebDAV** egress to approved domains.  
- Enforce **application control** for execution from **user‑writable** paths.  
- Monitor for **drive mappings** to `DavWWWRoot` and alert on **new/unapproved** hosts.

### Recovery
- Remove staged payloads and clean up **drive mappings**; rotate credentials used for WebDAV if compromised.  
- Update detections (host/path allowlists) and IR runbooks.

### False Positives
- Legitimate business workflows leveraging **SharePoint/WebDAV** or document management systems via UNC semantics.  
- Admin scripts moving files to sanctioned WebDAV repositories (validate **change windows** and **domains**).