# CertOC.exe (LOLBin) — T1105 Ingress Tool Transfer: Investigation Playbooks
_Last updated: 2025-10-25 14:40 UTC_

This package contains playbooks for two detections:
1) **GetCACAPS to Non-Approved SCEP Path** (process intent to fetch remote content)
2) **File Creation by CertOC.exe** (staging evidence on disk)

---

## Playbook 1 — T1105 · CertOC.exe GetCACAPS to Non‑Approved SCEP Path (Process Creation)

### Overview
Detects **CertOC.exe** executed with **`-GetCACAPS <URL>`** where the destination is **not** an approved SCEP/NDES endpoint. The GetCACAPS operation returns **text** and can be repurposed to fetch arbitrary plaintext content (e.g., scripts), making it a viable **Ingress Tool Transfer** vector via a signed Windows binary.

### Attack Context
- **MITRE ATT&CK:** T1105 — Ingress Tool Transfer
- **LOLBin:** `CertOC.exe` (supports `-GetCACAPS` and can contact remote endpoints)
- **Tradecraft:** Operators invoke `certoc.exe -GetCACAPS <http(s)://...>` to pull text content. When aimed at non-corporate hosts, this is a strong indicator of malicious ingress or staging.

### Initial Response
- **Confirm intent:** Capture the **full command line** and the **target URL**.
- **Scope user/host:** Determine whether cert enrollment activity is expected on this asset.
- **Check allowlists:** Compare the URL/domain against **approved SCEP/NDES endpoints** and internal PKI hosts.

### Investigation Steps
1. **Process and Image Analysis**
   - Validate `Image` path: `C:\Windows\System32\certoc.exe` or `C:\Windows\SysWOW64\certoc.exe`.
   - Record `ParentImage`, `User`, `IntegrityLevel`, signer; note if spawned by a script host or LOLBin.
   - Extract `-GetCACAPS` arguments and the destination URL.
2. **File and Path Analysis**
   - Review the **current working directory** of the process and common **user‑writable paths** (Temp, Downloads, Desktop, Public) for newly created **text/script artifacts** around the alert time.
   - Hash and reputation‑check any recovered files; look for redirection artifacts (e.g., output files named like the URL path).
3. **Correlation and Contextual Analysis**
   - **DNS (EID 22):** Lookups for the destination host by `certoc.exe` (or proxy/DoSvc if applicable).
   - **Network (EID 3):** If enabled, confirm sockets to the same host (or to an explicit proxy).
   - **Follow‑on execution:** Examine process lineage for immediate use of the fetched content (PowerShell, wscript, mshta, rundll32, etc.).
   - **PKI context:** Validate whether the URL corresponds to legitimate SCEP discovery; unexpected external domains increase severity.

### Key Artifacts
- **Process Creation (EID 1 / 4688):** `Image`, `CommandLine` containing `-GetCACAPS`, `ParentImage`, `User`.
- **DNS (EID 22):** `QueryName` for destination; note proxy/DoSvc patterns when present.
- **Network (EID 3):** `DestinationHostname/IP`, `DestinationPort` (typically 80/443).
- **File I/O (EID 11):** Newly created text/script files around the event.
- **EDR telemetry:** Any subsequent execution of downloaded content.

### Containment Actions
- Block the **destination domain/IP** and quarantine staged files.
- Kill the offending process; consider **host isolation** if follow‑on execution is observed.
- If misuse is confirmed, restrict or alert on `certoc.exe` usage in the environment.

### Prevention Measures
- Maintain a strict **allowlist** of corporate SCEP/NDES endpoints; alert on **non‑approved** destinations.
- Monitor for `certoc.exe` with **network indicators** or **script‑like URLs** in parameters.
- Apply **application control** (AppLocker/WDAC) and enforce **script control** (AMSI, PowerShell logging).

### Recovery
- Remove any downloaded payloads; revert unauthorized configuration changes.
- Review PKI and device management policies; document exceptions and tighten allowlists.

### False Positives
- Legitimate troubleshooting of SCEP/NDES using `-GetCACAPS` to **approved** internal URLs.
- PKI engineers validating new endpoints during planned maintenance (verify change tickets).

---

## Playbook 2 — T1105 · CertOC.exe File Creation (Staging on Disk)

### Overview
Flags **file creation** events where **`CertOC.exe`** is the writer, indicating potential **staging** of content retrieved via `-GetCACAPS`. While some certificate operations may touch local files, creation of **plaintext/script artifacts** in **user‑writable** paths is suspicious and aligns with **Ingress Tool Transfer**.

### Attack Context
- **MITRE ATT&CK:** T1105 — Ingress Tool Transfer
- **Behavioral cue:** New files created by `certoc.exe` (especially **.ps1/.vbs/.js/.hta/.bat/.cmd/.txt** or odd extensions) outside standard certificate store locations.

### Initial Response
- Enumerate **new/modified files** created by `certoc.exe` at alert time; compute **hashes** and check **signatures**.
- Identify the **parent process** that launched `certoc.exe` and the **user context**.

### Investigation Steps
1. **Process and Image Analysis**
   - Retrieve the originating **process creation** event (EID 1/4688) to capture the **command line** and confirm presence of `-GetCACAPS` or other parameters.
   - Validate `Image` path and signer; assess parent/child relationships (script hosts, Office, browsers).
2. **File and Path Analysis**
   - Inspect the **created file(s)**: extension, content type, entropy, embedded URLs, and execution markers (shebangs, headers).
   - Determine **write location** (Temp, Downloads, user profile, Public); higher risk in broadly writable paths.
3. **Correlation and Contextual Analysis**
   - **DNS/Network:** Correlate to preceding **DNS (EID 22)** and **network (EID 3)** events for the same host/time window.
   - **Execution attempts:** Search for **process creation** events where the created file becomes the **parent** or **child** process shortly after.
   - **Fleet prevalence:** Check if the same hash/URL appears elsewhere.

### Key Artifacts
- **File Create (EID 11):** `TargetFilename`, `Image=...\certoc.exe`, `ProcessGuid`.
- **Process Creation (EID 1 / 4688):** Command line with `-GetCACAPS` (if used).
- **DNS/Network (EID 22/3):** Destination host/connection evidence tied to `certoc.exe` activity.
- **EDR timeline:** Execution of newly created files, registry artifacts (if persistence attempted).

### Containment Actions
- Quarantine/delete staged files; block associated domains/IPs.
- Terminate related processes; isolate host if execution/persistence is observed.

### Prevention Measures
- Monitor/alert on `certoc.exe` writing to **user‑writable** directories.
- Enforce **application control** for script interpreters; restrict unapproved script execution.
- Strengthen **PKI endpoint allowlists**; log and review deviations.

### Recovery
- Remove malicious content and any persistence; update controls and detections.
- Review exceptions and tune allowlists to reduce future noise.

### False Positives
- PKI or enrollment tooling that legitimately writes diagnostic **text files**; validate **paths**, **owners**, and **change windows**.

---