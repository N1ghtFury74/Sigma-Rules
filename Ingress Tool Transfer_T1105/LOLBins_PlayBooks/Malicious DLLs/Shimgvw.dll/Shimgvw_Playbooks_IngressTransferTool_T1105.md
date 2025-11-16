# T1105 — Ingress Tool Transfer · LOLBin: Shimgvw.dll (Windows Picture and Fax Viewer)
**Rule covered:** CNC-E-2726320-176 — Shimgvw.dll ImageView_Fullscreen URL (Process Creation)  
**Last updated:** 2025-10-28 06:18 UTC

> `shimgvw.dll` provides the legacy **Windows Picture and Fax Viewer** UI. When driven via `rundll32.exe` with **ImageView_Fullscreen** (or similar)
> and a **URL/UNC**, it can retrieve remote images or embedded content. Adversaries may leverage this for **remote fetch** and **cache write** behaviors.

---

## Playbook — Shimgvw.dll URL Invocation (Process Creation)

### Overview
Investigate **`rundll32.exe shimgvw.dll,ImageView_Fullscreen <URL/UNC>`** or similar commands. Remote sources (HTTP/HTTPS/WebDAV/SMB) and
subsequent **cache/file writes** can indicate **T1105** staging via a Microsoft‑signed DLL host.

### Initial Response
1. **Preserve context:** Export **EID 1/4688** including `Image`, full `CommandLine`, `ParentImage`, `User`, IL, timestamp.  
2. **Parse source:** Extract **scheme/host/port**; classify internal vs external; flag **raw IPs**/**non‑std ports**.  
3. **Secure artifacts:** Acquire any **cache/temporary** files created by the viewer around the execution time.

### Investigation Steps
#### 1) Process & Lineage
- Validate `rundll32.exe` path/signature; confirm export usage (`ImageView_Fullscreen`, `ImageView_Fullscreen <path>`).  
- Review **parent** (Office, browser, script engines) to assess initial ingress vector.

#### 2) Network & DNS
- Correlate **EID 3** and **proxy** logs for download transactions; **EID 22** for DNS lookups (or proxy FQDN).  
- For **WebDAV UNC**, expect egress via **WebClient** `svchost.exe` (ports **80/443**). For **SMB**, validate **port 445** sessions.

#### 3) Artifact Analysis
- Inspect saved **image/cache** files: header vs extension, **EXIF** anomalies, **embedded payloads** (stego), high **entropy**.  
- Track downstream consumers (scripts, Office, image libraries) that read or execute content.

#### 4) Correlation & Fleet
- Pivot on destination and cache hashes; look for repeated URL patterns or export usage across hosts.

### Key Artifacts
- **Sysmon EID 1 / 4688:** `rundll32.exe shimgvw.dll,ImageView_Fullscreen <URL/UNC>`.  
- **Sysmon EID 11:** Cache/temp writes around execution.  
- **Sysmon EID 3 / 22 / Proxy:** Network/DNS corroboration.  
- **EDR timeline:** Child processes and readers of the cached files.

### Containment Actions
- **Block** destination; **quarantine** cached artifacts; **terminate** related processes; consider **host isolation** on execution.

### Prevention Measures
- Restrict `rundll32` export usage via **application control**; enforce **egress filtering** and allowlists.  
- Disable **WebClient** if not needed; alert on **Internet‑zone** inputs to legacy viewers.

### Recovery
- Remove staged artifacts; tune detections/allowlists; educate users on legacy viewer risks.

### False Positives
- Intranet documentation systems legitimately rendering images from trusted repositories. Validate and allowlist approved domains.