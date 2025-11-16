# T1105 — Ingress Tool Transfer · LOLBin: PhotoViewer.dll (Windows Photo Viewer)
**Rule covered:** CNC-E-2726320-174 — PhotoViewer.dll URL via Rundll32 → INetCache (Process Creation)  
**Last updated:** 2025-10-28 06:18 UTC

> `PhotoViewer.dll` is the Windows Photo Viewer component. Invoking it via `rundll32.exe` with a **URL/UNC** operand can drive **remote content fetch**
> and **INetCache** writes. Attackers can stage content from Internet/WebDAV/SMB locations and pivot to follow‑on execution.

---

## Playbook — PhotoViewer.dll URL → INetCache (Process Creation)

### Overview
Investigate **`rundll32.exe`** invocations of **`PhotoViewer.dll`** where a **URL/UNC** is present and artifacts land in **INetCache**. This is atypical
for normal local image viewing and aligns with **T1105** staging via a signed DLL host.

### Initial Response
1. **Preserve context:** Export **EID 1/4688** with `Image`, full `CommandLine`, `ParentImage`, `User`, IL, working dir, timestamp.  
2. **Parse source:** Extract **scheme/host/port/path**; flag **raw IPs**, **new domains**, **non‑std ports**.  
3. **Secure artifacts:** Acquire **INetCache** outputs and compute **hashes**; note file paths and sizes.

### Investigation Steps
#### 1) Process & Lineage
- Confirm `rundll32.exe` signature/path; identify PhotoViewer export used and arguments.  
- Review **parent** for phishing/scripted launch chains (Office, browsers, installers, other LOLBins).

#### 2) Network & DNS
- Correlate **Sysmon EID 3** and **proxy** logs to validate the fetch; **Sysmon EID 22** for DNS/proxy FQDN lookups.  
- For **WebDAV UNC**, expect egress via **WebClient** `svchost.exe` (80/443). For **SMB**, validate **445** sessions and shares accessed.

#### 3) Artifact Analysis
- Inspect **INetCache** files: headers (JFIF/PNG/WEBP), **metadata**, and possible **embedded data**; check **entropy** and **strings**.  
- Identify subsequent consumers and any **execution** of derived artifacts (scripts/dlls/exes).

#### 4) Correlation & Fleet
- Pivot on **destination host**, **cache file hashes**, and similar command‑line patterns across endpoints.

### Key Artifacts
- **Sysmon EID 1 / 4688:** `rundll32.exe ... PhotoViewer.dll <URL/UNC>`.  
- **Sysmon EID 11:** **INetCache** writes by the Photo Viewer host.  
- **Sysmon EID 3 / 22 / Proxy:** Network/DNS corroboration of the fetch.  
- **EDR timeline:** Child processes and file read chains.

### Containment Actions
- **Block** destination; **quarantine** cached artifacts; **terminate** related processes; consider **host isolation** if execution observed.

### Prevention Measures
- **AppLocker/WDAC** to restrict `rundll32` exports; egress controls and **domain allowlists**.  
- Disable **WebClient** if unused; monitor for **Internet‑zone** inputs to viewer DLLs and **INetCache** writes.

### Recovery
- Remove staged content and persistence; tune detections; document deviations and update runbooks.

### False Positives
- Approved intranet image viewers fetching media from trusted repositories; validate and allowlist.