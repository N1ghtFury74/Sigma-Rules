# T1105 — Ingress Tool Transfer · LOLBin: VSLaunchBrowser.exe (Visual Studio Browser Launcher)
**Rules Covered:**  
- CNC-E-2726320-301 — VSLaunchBrowser URL on Command Line (Process Creation)  
- CNC-E-2726320-301 — VSLaunchBrowser Unusual Network Connection (Sysmon EID 3 / DNS EID 22)  
**Last updated:** 2025-10-28 17:32 UTC

> `VSLaunchBrowser.exe` is a signed Windows binary used by Visual Studio to launch browsers to open URLs. When the **URL** is external or remote (such as **WebDAV** or **UNC paths**),
> it can be exploited to fetch remote content (staging payloads for **T1105** — Ingress Tool Transfer). This can be used by adversaries to **stage or execute remote payloads**.
> The command line of `VSLaunchBrowser.exe` may contain **URLs** that fetch remote content, leading to unexpected network connections and data retrieval.

---

## Playbook 1 — URL on Command Line (Process Creation)

### Overview
Investigate **process creation** of `VSLaunchBrowser.exe` where the **command line contains a remote locator**:
- `http(s)://host/path` (flag **raw IPs**, **shorteners**, **non‑standard ports**)  
- `\\server\share\file` (SMB UNC)  
- `\\host@SSL\DavWWWRoot\path\file` (WebDAV over HTTPS)

This behavior indicates a **protocol dispatch** initiated by a Visual Studio component or script, potentially used as a **LOLBIN** to fetch content.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** with full `CommandLine`, `ParentImage`, `User`, IL, CWD, timestamp.  
2. **Parse source:** Identify **scheme/host/port/path** and classify **internal vs external**; flag **raw IPs** and **new domains**.  
3. **Secure artifacts:** Snapshot **INetCache**, `%TEMP%`, and **recent files**; capture any downloaded files, hashes, and metadata.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path/signature (`C:\\Windows\\System32\\VSLaunchBrowser.exe`).  
- Review **parent process** (MSBuild.exe, devenv.exe, PowerShell, scheduled task, etc.) and user context.  
- Check if the execution is **user‑initiated** or automated.

#### 2) Command‑Line Analysis
- Inspect the **command line** for signs of remote resources, i.e., URLs, UNC/WebDAV paths.  
- Look for **parameters** used with `VSLaunchBrowser.exe` and confirm whether any **disguised scripts** are invoked.

#### 3) Network & DNS Correlation
- Correlate **Sysmon EID 3** egress attributed to `VSLaunchBrowser.exe` or **downstream handler** (default browser, WebClient `svchost.exe`).  
- Use **Sysmon EID 22** for DNS queries (proxy FQDN on endpoint in explicit proxy).  
- Inspect **proxy** logs for URL, method/status, bytes, content‑type, and SNI/JA3 anomalies.

#### 4) Artifact & Execution
- Review **Sysmon EID 11** for writes under **INetCache/%TEMP%**; validate **Zone.Identifier** ADS and extension↔MIME mismatches.  
- Identify **child processes** launched (e.g., `msedge.exe`, `chrome.exe`, `iexplore.exe` legacy; or `mshta.exe`/`rundll32.exe` if chained).

#### 5) Fleet Correlation
- Pivot on **destination hosts**, **CLI fragments** (`DavWWWRoot`, `@SSL`), **hashes** of artifacts, and **parent process** across endpoints.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Process creation details and full CLI context.  
- **Sysmon EID 3:** Outbound network connections and egress data.  
- **Sysmon EID 22:** DNS queries matching network connections.  
- **Sysmon EID 11:** File creation or modification in **INetCache/%TEMP%**.

### Containment Actions
- **Block** external destinations/domains and **quarantine** any suspicious files created.  
- **Terminate** processes with abnormal command-line arguments or parent processes.  
- Consider **host isolation** if execution involves rare/external content.

### Prevention Measures
- Apply **AppLocker/WDAC** policies to restrict `VSLaunchBrowser.exe` execution on non‑admin endpoints.  
- Restrict external WebDAV and UNC path usage for Visual Studio projects.  
- Monitor **CLI** patterns for **unexpected URLs** or **raw IPs**.

### Recovery
- Remove any staged content, restore to baseline configurations, and update threat intelligence sources.  
- Tune detection rules to capture all potential Ingress Tool Transfer patterns.

### False Positives
- **Legitimate development workflows** where Visual Studio fetches **approved resources** from trusted intranet WebDAV or file shares.  
- Validate by owner/project context and allowlist approved domains.

---

## Playbook 2 — Unusual Network Connection (Sysmon EID 3 / DNS EID 22)

### Overview
This playbook investigates **network/DNS activity** tied to `VSLaunchBrowser.exe`. As a browser launcher, network egress from this binary is **uncommon** unless used to fetch remote content for processing.

### Initial Response
1. **Capture records:** Export **Sysmon EID 3** (dest IP/host/port/proto) and **Sysmon EID 22** (DNS queries) for the same time window and correlate with **EID 1/4688** for `VSLaunchBrowser.exe`.  
2. **Classify destination:** Internal vs external; flag **raw IPs**, **new/rare domains**, **non‑standard ports**.  
3. **Scope usage:** Determine if the host is a **developer machine** and whether the activity matches normal build/run workflows.

### Investigation Steps
#### 1) Process & Command Context
- Retrieve the **CLI** for `VSLaunchBrowser.exe` and confirm it references a **remote path** or **UNC/WebDAV URL**.  
- Review the **parent** process (MSBuild, script hosts, or RMM) to identify the trigger source.

#### 2) Destination Validation
- Review the **destination** domain/IP reputation (enrich using threat intel) and check **proxy** logs for method/status/bytes.  
- For **WebDAV UNC**, pivot to **WebClient** telemetry and analyze HTTP/S request data.

#### 3) Artifact Discovery
- Review **Sysmon EID 11** for **new file** creations or changes in **INetCache/%TEMP%**.  
- **Hash** these files and check for any **follow‑on processes** spawned by those files.

#### 4) Fleet & Correlation
- Pivot by **destinations**, **file names**, **hashes**, and **parent** processes to detect coordinated activity across hosts.

### Key Artifacts
- **Sysmon EID 3 / 22:** Network and DNS observables linked to the event.  
- **Sysmon EID 1 / 4688:** Process creation with **remote URLs** or **UNC paths**.  
- **Sysmon EID 11:** File writes from extraction or staged download.  
- **EDR timeline:** Downstream handler behavior and child processes.

### Containment Actions
- **Block** suspicious hosts; **quarantine** downloaded content; **terminate** malicious processes.  
- If execution is confirmed, consider **host isolation** and further investigation.

### Prevention Measures
- Maintain **allowlists** for trusted development domains; enforce **egress controls** for Visual Studio processes.  
- Restrict **URL protocol handlers** to **intranet** or approved domains only.

### Recovery
- Remove any suspicious artifacts; reset configurations, and tune detection rules accordingly.

### False Positives
- **Authorized development workflows** that open **approved** intranet resources; validate and adjust detection thresholds per project or owner context.