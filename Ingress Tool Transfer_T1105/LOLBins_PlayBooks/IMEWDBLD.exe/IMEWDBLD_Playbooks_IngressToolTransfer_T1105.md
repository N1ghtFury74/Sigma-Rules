# T1105 — Ingress Tool Transfer · LOLBin: IMEWDBLD.exe  
**Rules:**  
- CNC-E-2726320-161 — IMEWDBLD.exe Network Connection (Sysmon EID 3)  
- CNC-E-2726320-162 — IMEWDBLD.exe FileCreate (Sysmon EID 11)  
**Last updated:** 2025-10-28 05:59 UTC

> `IMEWDBLD.exe` is the **Input Method Editor Word List Builder** (Microsoft‑signed). While legitimately used to build/update IME word lists,
> adversaries can repurpose it to **pull source content over UNC/WebDAV** and **write artifacts** under user‑writable paths as part of
> **Ingress Tool Transfer (T1105)** workflows. Network/DNS may be directly attributed to `IMEWDBLD.exe` (SMB) or to `svchost.exe` WebClient (WebDAV).

---

## Playbook 1 — IMEWDBLD.exe Network Connection (Sysmon EID 3)

### Overview
Investigate alerts where **`IMEWDBLD.exe`** establishes **outbound connections**. Normal usage is largely **local**; process‑attributed
network I/O to **UNC/WebDAV/HTTP(S)** endpoints is **atypical** and may indicate remote content retrieval or staging.

### Initial Response
1. **Capture records:** Export **EID 3** (dest host/IP/port/protocol) and correlate with nearby **process creation** (EID 1 / 4688).  
2. **Destination triage:** Internal vs external; flag **raw IPs**, **new domains**, and **non‑standard ports**.  
3. **User/asset context:** Determine if the user/device is expected to manage IME dictionaries (usually limited to specific locales/admins).

### Investigation Steps
#### 1) Process & Lineage
- Verify `Image` path (e.g., `C:\\Windows\\System32\\IMEWDBLD.exe`) and signer metadata.  
- Review `ParentImage` and full `CommandLine` for **source/destination** hints, UNC paths, or parameters indicating import/export.  
- Note working directory and integrity level.

#### 2) Destination Validation
- **SMB UNC:** `\\host\share\...` — corroborate with **SMB session** logs (port 445) and **Security logon type 3**.  
- **WebDAV UNC:** `\\host\DavWWWRoot\...` or `\\host@SSL\DavWWWRoot\...` — expect egress via **WebClient** `svchost.exe` over **80/443**; pivot to **proxy** logs.  
- **HTTP/HTTPS:** Check proxy for **method/status/bytes**; enrich destination reputation and compare with allowlists.

#### 3) Artifact Discovery
- Search for **file creations** (EID 11) temporally aligned: IME dictionaries (`.dic`, `.lex`, `.txt`), temp files, or unexpected binaries/scripts.  
- Hash and analyze any artifacts; check for **extension ↔ MIME** mismatch, **entropy**, and suspicious strings.

#### 4) Correlation & Follow‑On
- Look for **execution** of created artifacts or hand‑off to sibling tools (`powershell.exe`, `rundll32.exe`, `mshta.exe`).  
- Fleet‑wide, pivot on destination hosts and artifacts’ hashes to scope impact.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\IMEWDBLD.exe`, destination host/IP/port.  
- **Sysmon EID 1 / 4688:** Launch context and `CommandLine`.  
- **Sysmon EID 11:** Files written during/after transfer.  
- **Sysmon EID 22 / Proxy:** DNS queries and HTTP(S) observables.  
- **EDR timeline:** Parent/child process graph and module loads.

### Containment Actions
- **Block** suspicious destinations; **terminate** activity; **quarantine** artifacts; consider **host isolation** if execution is observed.

### Prevention Measures
- Enforce **egress filtering** and domain allowlists; disable **WebClient** where not required.  
- Apply **AppLocker/WDAC** to restrict use of IME utilities where not business‑critical.  
- Monitor for **rare process → network** patterns (e.g., `IMEWDBLD.exe` initiating Internet egress).

### Recovery
- Remove staged content/persistence; rotate any exposed credentials; tune detections/allowlists.

### False Positives
- Legitimate **IME dictionary** sync/import from **approved internal shares** during localized deployments. Validate via ticket/owner.

---

## Playbook 2 — IMEWDBLD.exe FileCreate (Sysmon EID 11)

### Overview
Investigate **file creations** where `IMEWDBLD.exe` is the actor. While typical outputs are **dictionary/lexicon** files, adversarial use may drop
**payloads**, **scripts**, or **stagers** to user‑writable directories as part of a staged **T1105** chain.

### Initial Response
1. **Secure artifacts:** Copy and **hash** newly created files; preserve timestamps and **owner**.  
2. **Trace lineage:** Link **EID 11** to prior `IMEWDBLD.exe` **EID 1/4688** and any **EID 3/22** network activity.  
3. **Assess location:** Treat writes under **%TEMP%**, **%USERPROFILE%**, **AppData**, **Downloads**, or **Public** as higher risk.

### Investigation Steps
#### 1) Artifact Inspection
- Determine **type**: dictionary/lexicon (`.dic`, `.lex`, `.txt`) vs executable/script/archive; check **extension ↔ MIME** consistency.  
- Inspect **strings** for URLs, encoded data, or commands; calculate **entropy** to spot packed/encoded blobs.  
- Identify whether the artifact was **executed** shortly after creation.

#### 2) Process Context
- Retrieve `IMEWDBLD.exe` **command line** to infer **source** (local vs remote, UNC/WebDAV/HTTP).  
- Review `ParentImage` and user context (interactive vs script/automation).  
- Check for **temporary file** patterns preceding the final output.

#### 3) Network & DNS Corroboration
- Correlate with **EID 3** for SMB/WebDAV/HTTP flows; for WebDAV, pivot to **WebClient** egress under `svchost.exe`.  
- Review **EID 22** DNS queries (or proxy FQDN lookups) around the write time.

#### 4) Follow‑On & Fleet
- Hunt for **child processes** reading/executing the created file; pivot hashes/paths across the fleet for prevalence.

### Key Artifacts
- **Sysmon EID 11:** `TargetFilename` created by `IMEWDBLD.exe`.  
- **Sysmon EID 1 / 4688:** Prior process creation with `CommandLine` and `ParentImage`.  
- **Sysmon EID 3 & 22 / Proxy:** Corroborating network/DNS telemetry.  
- **EDR timeline:** Process graph and module loads referencing the new artifact.

### Containment Actions
- **Quarantine** suspicious files; **block** related destinations; **terminate** process chains; consider **host isolation** on code execution.

### Prevention Measures
- Restrict IME utilities usage; enforce **egress controls**; disable **WebClient** if not needed.  
- Monitor for `IMEWDBLD.exe` writing into **user‑writable** locations and for **rare process → file‑write** patterns.

### Recovery
- Remove artifacts/persistence; update detections and allowlists; document deviations; educate users/admins as needed.

### False Positives
- Legitimate IME dictionary builds or imports by localization teams storing word lists in user profiles or app data. Validate with owners/change tickets.