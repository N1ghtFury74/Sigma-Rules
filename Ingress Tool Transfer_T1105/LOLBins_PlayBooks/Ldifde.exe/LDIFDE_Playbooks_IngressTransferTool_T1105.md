# T1105 — Ingress Tool Transfer · LOLBin: LDIFDE.exe  
**Rules:**  
- CNC-E-2726320-165 — LDIFDE Import with URL Value-Spec (Process Creation)  
- CNC-E-2726320-166 — LDIFDE Network Connection (Sysmon EID 3)  
- CNC-E-2726320-167 — LDIFDE FileCreate of Non‑LDIF Artifact (Sysmon EID 11)  
**Last updated:** 2025-10-28 06:05 UTC

> `ldifde.exe` is a Microsoft tool to import/export directory data using the **LDAP Data Interchange Format (LDIF)**. In abuse scenarios,
> adversaries may reference **remote URLs/UNC paths** inside LDIF **value‑specs** (e.g., `photo:< file://…`, `userCertificate:< http://…`) or
> stage content via **UNC/WebDAV**, transforming LDIF import flows into **Ingress Tool Transfer (T1105)** chains. Network/DNS may be attributed
> directly to `ldifde.exe` (SMB) or to **WebClient `svchost.exe`** for WebDAV.

---

## Playbook 1 — LDIFDE Import with URL Value‑Spec (Process Creation)

### Overview
Investigate alerts where **`ldifde.exe`** launches to **import** (`-i`) an LDIF that contains **URL/UNC value‑specs** (e.g., `:< http(s)://`, `:< file://\\host\share`,
`:< \\host@SSL\DavWWWRoot\…`). This enables retrieval of **binary attributes** (photos, certs, blobs) from remote sources and can be repurposed to **pull tools/data**.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** for `ldifde.exe` (image, full command line, parent, user, IL, working dir, timestamp).  
2. **Collect inputs:** Acquire the **LDIF file** referenced (`-f`), any auxiliary include files, and the **current directory** contents.  
3. **Parse indicators:** Extract **remote paths** from the LDIF (schemes, hosts, ports); classify **internal vs external**, flag **raw IPs** and **non‑std ports**.

### Investigation Steps
#### 1) Process & Lineage
- Verify `Image` path (e.g., `C:\\Windows\\System32\\ldifde.exe`) and signer.  
- Review `ParentImage` (script engines, Task Scheduler, Office) to determine automation vs interactive use.  
- Confirm **import mode** (`-i`), server/port (`-s`, `-t`), credentials (`-b`, `-a`), and target naming context (`-d`).

#### 2) LDIF Content Review
- Search for **value‑spec with external reference** syntax: `attribute:< URL` or `:< file://` or direct **UNC**.  
- Identify attributes likely to carry **arbitrary blobs** (`userCertificate`, `jpegPhoto`, `thumbnailPhoto`, `msExch*`, custom attributes).  
- Determine **write targets** (where the data lands in AD or on disk via staging scripts).

#### 3) Network & DNS Corroboration
- Expect **Sysmon EID 3** for SMB if UNC sources, or **WebClient `svchost.exe`** egress for WebDAV; **proxy logs** for HTTP(S).  
- **Sysmon EID 22** may show DNS lookups for destination (or **proxy FQDN** under explicit proxies).

#### 4) Artifact Discovery
- If value‑specs reference **local staging**, look for **file creation** (EID 11) in `%TEMP%`/working paths.  
- Hash/analyze any staged files; check **extension↔MIME** mismatch and **entropy** for encoded payloads.

#### 5) Correlation & Follow‑On
- Hunt for **subsequent execution** of newly staged content (PowerShell, rundll32, mshta, wmic, cmd).  
- Fleet‑wide, pivot by **LDIF filename**, **remote host**, and **hashes** to identify spread.

### Key Artifacts
- **Sysmon EID 1 / 4688:** `Image`, `CommandLine`, `ParentImage`, `User`.  
- **LDIF content:** External value‑spec URLs/UNCs.  
- **Sysmon EID 3 / Proxy:** Network connections for remote sources.  
- **Sysmon EID 22:** DNS queries; proxy FQDN if applicable.  
- **Sysmon EID 11:** Local staging writes by `ldifde.exe` (less common but possible in scripted flows).

### Containment Actions
- **Block** suspicious remote hosts; **quarantine** LDIF and any staged artifacts; **terminate** process chain; consider **host isolation** if execution occurred.

### Prevention Measures
- Restrict **directory import rights**; require **code‑signed change workflows**.  
- Egress filtering and **domain allowlists**; disable **WebClient** where unused.  
- Application control (**AppLocker/WDAC**) to constrain `ldifde.exe` use to admin jump boxes.

### Recovery
- Revert unauthorized directory changes; remove staged payloads; rotate exposed credentials; update tuning/runbooks.

### False Positives
- Legitimate **directory provisioning** importing media/certs from **approved internal** repositories via URL/UNC. Validate via change tickets and owners.

---

## Playbook 2 — LDIFDE Network Connection (Sysmon EID 3)

### Overview
This playbook addresses alerts where **`ldifde.exe`** exhibits **outbound connections** (Sysmon **EID 3**). LDIF imports with **UNC/WebDAV/HTTP**
value‑specs can generate process‑attributed egress, which is **atypical** for many environments and may indicate **T1105** behavior.

### Initial Response
1. **Capture records:** Export **EID 3** (dest host/IP/port) and correlate with **EID 1/4688** for `ldifde.exe`.  
2. **Classify destination:** Internal vs external; flag **raw IPs**, **new domains**, and **non‑standard ports**.  
3. **Scope usage:** Determine if the device/user is expected to run `ldifde` with remote value sources.

### Investigation Steps
#### 1) Process & Lineage
- Confirm `Image` path/signature; review `ParentImage` and **command line** for `-i`, `-f`, `-s`, `-t`, and **remote indicators**.  
- Identify working directory and any referenced **LDIF** or **script** files.

#### 2) Destination Validation
- **SMB UNC:** Validate **port 445** sessions and **logon type 3**; enumerate share/path.  
- **WebDAV UNC:** Expect egress from **WebClient `svchost.exe`** on **80/443**; pivot to **proxy** logs.  
- **HTTP/HTTPS:** Examine proxy logs for **method/status/bytes**; enrich domain/IP reputation and compare to allowlists.

#### 3) Artifact Discovery
- Search for **file creations** (EID 11) near the network event (staging logs, temp files, downloaded blobs if scripted).  
- Hash/analyze artifacts; confirm whether they are **consumed by ldifde** or executed by follow‑on tools.

#### 4) Correlation & Follow‑On
- Hunt for **execution** of staged artifacts; pivot on **destination host** and **hashes** across fleet to identify spread.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\ldifde.exe`, destination details.  
- **Sysmon EID 1 / 4688:** Launch context and `CommandLine`.  
- **Sysmon EID 11:** File writes tied to retrieval.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.

### Containment Actions
- **Block** destination; **terminate** activity; **quarantine** artifacts; consider **host isolation** if execution seen.

### Prevention Measures
- Egress filtering/allowlists; disable **WebClient** when not needed; restrict `ldifde.exe` with **application control**.  
- Monitor **rare process → network** pairs and **Internet‑zone** LDIF imports.

### Recovery
- Remove artifacts/persistence; tune detections; update runbooks and allowlists.

### False Positives
- Approved directory operations retrieving media/certs from internal hosts; validate by change records and owners.

---

## Playbook 3 — LDIFDE FileCreate of Non‑LDIF Artifact (Sysmon EID 11)

### Overview
This playbook supports investigations where `ldifde.exe` is recorded as creating **non‑LDIF files** (e.g., binaries/scripts/cached blobs).
While `ldifde.exe` primarily reads LDIF and writes **logs**, adversarial workflows may script it to stage additional **payloads** to disk as part
of a broader **T1105** chain.

### Initial Response
1. **Secure artifacts:** Copy and **hash** created files; preserve timestamps and **owner**.  
2. **Trace lineage:** Link **EID 11** to prior `ldifde.exe` **EID 1/4688** and any **EID 3/22** activity.  
3. **Assess location:** Treat writes under **%TEMP%**, **%USERPROFILE%**, **AppData**, **Downloads**, or **Public** as higher risk.

### Investigation Steps
#### 1) Artifact Inspection
- Determine **type** (text/log vs PE/script/archive). Check **extension ↔ MIME** consistency, **entropy**, and suspicious **strings/URLs**.  
- Determine whether the artifact appears to be **input**, **output**, or **collateral** from the import process (e.g., transformed blobs).

#### 2) Process Context
- Retrieve `ldifde.exe` **command line** and the **LDIF** content it processed.  
- Inspect **ParentImage** and user context; identify any **temporary** or **redirected** outputs controlled by scripts/batch files.

#### 3) Network & DNS Corroboration
- Correlate with **EID 3** for UNC/WebDAV/HTTP flows; **WebClient** egress for WebDAV; **proxy** logs for HTTP(S).  
- Review **EID 22** DNS (or proxy FQDN) around the write time.

#### 4) Follow‑On & Fleet
- Search for **execution** of created files; pivot by **hash** and **path** across the fleet.  
- Review directory changes induced by the LDIF import to assess **impact**.

### Key Artifacts
- **Sysmon EID 11:** `TargetFilename` created by `ldifde.exe`.  
- **Sysmon EID 1 / 4688:** Prior process launch with `-i` and `-f`.  
- **Sysmon EID 3 & 22 / Proxy:** Corroborating network/DNS telemetry.  
- **LDIF file(s):** Parsed URLs/UNCs and object attribute changes.

### Containment Actions
- **Quarantine** suspicious files; **block** related destinations; **terminate** process chains; consider **host isolation** on code execution.

### Prevention Measures
- Restrict `ldifde.exe` usage; enforce **change control** for directory imports; maintain **egress controls**.  
- Monitor for `ldifde.exe` writing into **user‑writable** locations and for **rare process → file‑write** patterns.

### Recovery
- Remove artifacts/persistence; revert unintended directory changes; update detections and allowlists; document deviations.

### False Positives
- Legitimate provisioning that temporarily writes **logs** or **intermediate files** alongside LDIF operations (ensure extension/path allowlists).