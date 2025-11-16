# T1105 — Ingress Tool Transfer · LOLBin: PresentationHost.exe (Windows Presentation Foundation Host)
**Rules:**  
- CNC-E-2726320-180 — PresentationHost URL in Command Line (Process Creation)  
- CNC-E-2726320-181 — PresentationHost Outbound Network Connection (Sysmon EID 3)  
**Last updated:** 2025-10-28 07:14 UTC

> `PresentationHost.exe` hosts **XAML Browser Applications (XBAP)** and WPF content. When pointed at **remote XAML/XBAP** via URL/UNC/WebDAV,
> it may **fetch and render** content using a Microsoft‑signed binary. Adversaries can abuse this to stage **Ingress Tool Transfer (T1105)** where
> additional payloads/configs are downloaded and executed through scripted/XAML behaviors or follow‑on LOLBins.

---

## Playbook 1 — URL in Command Line (Process Creation)

### Overview
Investigate **process creation** of `PresentationHost.exe` where the **command line contains a URL or UNC/WebDAV path** to XAML/XBAP or other content
(e.g., `http(s)://…/app.xbap`, `\\server\share\view.xaml`, `\\host@SSL\DavWWWRoot\x.xaml`). This indicates **remote sourcing** by a signed WPF host.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** with `Image`, full `CommandLine`, `ParentImage`, `User`, IL, CWD, timestamp.  
2. **Parse source:** Extract **scheme/host/port/path**; classify **internal vs external**; flag **raw IPs** and **non‑standard ports**.  
3. **Secure artifacts:** Snapshot **INetCache**/**%TEMP%** around the event; copy & **hash** any cached XAML/XBAP or secondary artifacts (no live open).

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path/signature (`C:\\Windows\\System32\\PresentationHost.exe` / `SysWOW64`).  
- Review **parent** (Outlook/Teams/browser → phish, Office macro, script hosts, scheduled tasks).  
- Identify if launched **hidden/silently** (window style flags) or by **untrusted parents**.

#### 2) Content Semantics
- Determine content type (XAML/XBAP/HTML). Inspect (offline) for **Pack URIs**, **WebRequest**, or **scripted events** that fetch additional payloads.  
- Review embedded resource paths and **secondary URLs** referenced by the XAML.

#### 3) Network & DNS
- Correlate **Sysmon EID 3** egress (direct or via WebClient for WebDAV) and **proxy** logs (Host/SNI, method/status/bytes).  
- Use **Sysmon EID 22** to capture DNS queries (proxy FQDN if explicit proxy is configured).

#### 4) Artifact & Execution
- Inspect **INetCache/%TEMP%** writes (EID 11); verify **extension↔MIME** and **Zone.Identifier** ADS.  
- Identify **child processes** spawned (e.g., `mshta.exe`, `rundll32.exe`, `powershell.exe`) or **module loads** post‑render.

#### 5) Fleet Correlation
- Pivot by **destination host**, **hashes** of cached artifacts, and **CLI substrings** (e.g., `.xbap`, `.xaml`) across endpoints.

### Key Artifacts
- **Sysmon EID 1 / 4688:** CLI with remote input and `ParentImage`.  
- **Sysmon EID 11:** File writes under **INetCache**/**%TEMP%**.  
- **Sysmon EID 3 / Proxy:** HTTP(S)/WebDAV egress; **Sysmon EID 22** DNS.  
- **EDR timeline:** Child processes and module loads linked to `PresentationHost.exe`.

### Containment Actions
- **Block** destination; **quarantine** artifacts; **terminate** process chains; consider **host isolation** on execution.

### Prevention Measures
- Egress filtering and **domain allowlists**; disable **WebClient** if unneeded.  
- App control (AppLocker/WDAC) to restrict `PresentationHost.exe` usage on non‑dev endpoints; monitor **rare process → URL** usage.  
- Harden mail/web delivery (block Internet‑origin XBAP).

### Recovery
- Remove staged content/persistence; rotate credentials if exposure suspected; tune detections and allowlists.

### False Positives
- Intranet apps legitimately rendering XBAP from **approved** portals; validate by owner/change tickets and allowlist.

---

## Playbook 2 — Outbound Network Connection (Sysmon EID 3)

### Overview
This playbook investigates **outbound connections** attributed to `PresentationHost.exe`. While local rendering is normal, **remote content** loading
or **secondary fetches** indicate potential **T1105** staging.

### Initial Response
1. **Capture records:** Export **EID 3** (dest IP/host/port/proto) and correlate with **EID 1/4688** for `PresentationHost.exe`.  
2. **Classify destination:** Internal vs external; highlight **raw IPs**, **new/rare domains**, and **non‑standard ports**.  
3. **Scope usage:** Determine if XBAP/WPF apps are expected for the user/asset (often **not** in modern enterprises).

### Investigation Steps
#### 1) Process & Command Context
- Retrieve full **command line** and **parent**; confirm remote path or template.  
- Verify user session/time of day; check for **repeated / scheduled** invocation.

#### 2) Destination Validation
- Enrich destinations and inspect **proxy** logs (method/status/bytes, content-type).  
- For WebDAV, pivot to **WebClient** telemetry on ports **80/443**; for SMB UNC, validate **445** sessions and shares.

#### 3) Artifact Discovery
- Search **EID 11** for newly created cache/temp files; **hash** and analyze.  
- Identify **execution** of downloaded artifacts by child processes within minutes of the connection.

#### 4) Correlation & Fleet
- Pivot on **destinations**, **hashes**, and **CLI** patterns; cluster by **parent** and **user**.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\PresentationHost.exe`, destination details.  
- **Sysmon EID 1 / 4688:** Process creation and CLI context.  
- **Sysmon EID 11:** File writes associated with staging.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.

### Containment Actions
- **Block** endpoints; **quarantine** artifacts; **terminate** activity; consider **host isolation** if execution occurred.

### Prevention Measures
- Restrict `PresentationHost.exe` usage; enforce **egress controls**; monitor **rare process → network** pairs.  
- Alert on `PresentationHost.exe` accessing **Internet‑zone** resources.

### Recovery
- Remove artifacts/persistence; tune detections/allowlists; update runbooks.

### False Positives
- Approved XBAP/WPF apps connecting to **trusted** intranet services; validate and allowlist.