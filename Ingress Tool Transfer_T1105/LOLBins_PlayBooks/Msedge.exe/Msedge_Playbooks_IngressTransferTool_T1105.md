# T1105 — Ingress Tool Transfer (and Related Collection) · LOLBin: msedge.exe (Microsoft Edge)
**Rules:**  
- CNC-E-2726320-170 — Browsers Headless Dump‑DOM Base64 Capture (Process Creation)  
- CNC-E-2726320-171 — Browsers URL with Double‑Extension Filename (Process Creation)  
**Last updated:** 2025-10-28 06:40 UTC

> `msedge.exe` is Microsoft Edge. Adversaries may drive **headless** browser sessions to fetch, render, and **capture content** (often Base64 DOM/screenshot)
> or to download payloads from crafted URLs (e.g., **double‑extension** trick filenames) using a Microsoft‑signed process. While browsers are expected to
> make network requests, **direct command‑line‑driven** Edge with automation flags is atypical on end‑user systems and can indicate **T1105 — Ingress Tool
> Transfer** or content **collection** in support of subsequent staging/execution.

---

## Playbook 1 — Headless DOM/Base64 Capture (Process Creation)

### Overview
Investigate **process creation** where `msedge.exe` runs with **headless/automation** switches indicative of scripted capture (e.g., `--headless=new`,
`--disable-gpu`, `--dump-dom`, `--virtual-time-budget`, `--screenshot`, `--print-to-pdf`, `--remote-debugging-port=0`, `--user-data-dir=<temp>`). Operators
use this to **fetch remote pages** and **emit content** (DOM text, screenshots, PDFs) to **stdout/files** for staging/exfiltration.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** for `msedge.exe` including full `CommandLine`, `ParentImage`, `User`, IL, working directory, timestamp.  
2. **Capture outputs:** Identify referenced **output paths** (e.g., `--screenshot=`, `--print-to-pdf=`) and copy/hash artifacts. If output is to **stdout** and piped (`>`), capture the target file.  
3. **Parse target URL(s):** Extract destination **scheme/host/port/path**; classify **internal vs external**; flag **raw IPs** and **non‑std ports**.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path/signature; review **parent** (PowerShell, cmd, wscript, office) to determine automation vector.  
- Note **profile isolation** (`--user-data-dir`) suggesting ephemeral, sandboxed sessions favored by attackers.

#### 2) Output & Content Analysis
- Inspect **PDF/screenshots/DOM dumps** for sensitive data, embedded URLs, or encoded payloads (**Base64**) that might represent staged binaries/scripts.  
- Check **Zone.Identifier** ADS and file metadata; compare timestamps with execution.

#### 3) Network & DNS Corroboration
- Correlate with **Sysmon EID 3** (if available) and **proxy** logs for requests (method/status/bytes) to the target URL(s).  
- Review **Sysmon EID 22** DNS queries (or proxy FQDN when explicit proxy is used).

#### 4) Correlation & Follow‑On
- Hunt for immediate **use** of captured outputs (email exfil, cloud sync, compression/uploads) or **execution** of content referenced by the DOM.  
- Fleet‑wide, pivot by **CLI switches**, **destination**, and **parent process** patterns.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Headless/automation switches and target URL.  
- **Sysmon EID 11:** Output artifacts (PDFs, screenshots, dumps).  
- **Sysmon EID 3 / Proxy:** HTTP(S) transactions; **Sysmon EID 22:** DNS.  
- **EDR timeline:** Parent/child processes, pipes/redirection.

### Containment Actions
- **Quarantine** captured artifacts; **block** destination hosts if malicious; **terminate** automation chain; consider **host isolation** if broader abuse found.

### Prevention Measures
- Restrict **headless browser** usage on endpoints via **application control** or policy.  
- Enforce **egress filtering** and domain allowlists; monitor **rare process → headless** CLI patterns.  
- DLP on browser‑generated artifacts (PDF/screenshots) to protect sensitive content.

### Recovery
- Remove staged content; tune detections; educate users/admins on safe browser automation practices.

### False Positives
- Legitimate **QA/automation** jobs or **report rendering** services that intentionally run Edge headless on approved hosts. Validate via owner/schedule.

---

## Playbook 2 — URL with Double‑Extension Filename (Process Creation)

### Overview
Investigate `msedge.exe` launched with a **URL** that **ends with a double‑extension** pattern (e.g., `invoice.pdf.exe`, `report.jpg.hta`, `docx.js`), often
used to disguise **downloaded executables/scripts**. When combined with **automation flags** or a **non‑browser parent**, this is strong evidence of **T1105** staging.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** with full `CommandLine`, `ParentImage`, `User`, IL, working dir, timestamp.  
2. **Collect artifacts:** Retrieve any resulting **downloads** from default paths or specified `--download-path`. Hash and classify.  
3. **Identify destination:** Extract the **URL host**; note **raw IPs**, **new domains**, **non‑standard ports**, and **attachment‑like paths**.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path/signature; scrutinize **non‑Edge parents** (Office, script hosts, scheduled tasks).  
- Note if **download prompts** were suppressed (policy or CLI) and whether a **custom profile dir** was used.

#### 2) Artifact Analysis
- Determine the **true file type** by headers; check **extension↔MIME** mismatch and **Zone.Identifier**.  
- Inspect **strings/URLs** and **entropy**; detonate in sandbox if policy allows.

#### 3) Network & DNS Corroboration
- Correlate **proxy** logs for the URL (status, size, content‑type, referrer); check **EID 3** and **EID 22** if attributed.  
- Look for **WebDAV** patterns (`DavWWWRoot`, `@SSL`) where downloads may be brokered by **WebClient svchost.exe**.

#### 4) Correlation & Follow‑On
- Hunt for execution of the downloaded artifact (`cmd`, `powershell`, `wscript`, `rundll32`, `mshta`, `regsvr32`).  
- Pivot fleet‑wide on **domain**, **hash**, **filename pattern** (e.g., `*.pdf.exe`).

### Key Artifacts
- **Sysmon EID 1 / 4688:** Command line with URL and file name pattern.  
- **Sysmon EID 11:** Downloaded files and temp artifacts.  
- **Sysmon EID 3 / 22 / Proxy:** Network/DNS corroboration.  
- **EDR timeline:** Child processes and module loads after download.

### Containment Actions
- **Quarantine** downloads; **block** destination domains/IPs; **terminate** related processes; consider **host isolation** if execution occurred.

### Prevention Measures
- Browser policies to **block dangerous downloads** and enforce **SmartScreen**; egress filtering and allowlists.  
- Application control for **execution** from **Downloads/temp** paths; alert on **double‑extension** in URLs across browsers.

### Recovery
- Remove staged payloads/persistence; rotate credentials as needed; tune detections/runbooks.

### False Positives
- Rare legitimate downloads with **compound extensions** from trusted developer portals. Validate via owners and allowlist by domain/path when justified.