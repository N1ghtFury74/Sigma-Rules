# T1105 — Ingress Tool Transfer · LOLBin: msxsl.exe (MSXML XSLT Processor)
**Rules:**  
- CNC-E-2726320-190 — MSXSL URL on CLI (Process Creation)  
- CNC-E-2726320-190B — MSXSL Outbound Network Connection (Sysmon EID 3)  
- CNC-E-2726320-190C — MSXSL Suspicious DNS Query (Sysmon EID 22)  
**Last updated:** 2025-10-28 07:03 UTC

> `msxsl.exe` applies an **XSLT stylesheet** to an **XML** source using the MSXML engine. Attackers abuse `msxsl` by pointing the
> **XML or XSL inputs to remote URLs/UNC/WebDAV** so that a Microsoft‑signed binary fetches and processes content. Stylesheets can
> contain scripts or extension objects that trigger **downloads** or auxiliary behaviors, making `msxsl` a useful **Ingress Tool
> Transfer (T1105)** primitive and execution helper in some chains.

---

## Playbook 1 — MSXSL URL on CLI (Process Creation)

### Overview
Investigate `msxsl.exe` **process creation** where the command line includes **remote sources** for XML/XSL (e.g., `http(s)://…`, `\\host\share\…`,
`\\host@SSL\DavWWWRoot\…`) or embeds a **URL** via `-s` param substitution. This indicates a signed **fetch‑and‑transform** flow that can stage
payloads or transform data fetched from the Internet/Intranet.

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688** with `Image`, full `CommandLine`, `ParentImage`, `User`, IL, CWD, timestamp.  
2. **Parse inputs:** Extract **XML** and **XSL** locations from CLI; classify **internal vs external** and note **raw IPs**/**non‑std ports**.  
3. **Secure artifacts:** Capture any **output file** specified (e.g., `-o <file>`), and nearby **INetCache/%TEMP%** artifacts for hashing.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path/signature (`C:\\Windows\\System32\\msxsl.exe` / `SysWOW64`).  
- Review **parent** (Office macro, browser, PowerShell/cmd, script hosts, scheduled task) for the delivery vector.

#### 2) Command‑Line Semantics
- Identify which argument is **XML source** and which is **XSL stylesheet**; both may be remote.  
- Note usage of **parameter injection**: `-s:name=value` wherein **value** may itself be a URL that the XSLT consumes.  
- Check for **output switches** (`-o`) writing to user‑writable paths.

#### 3) Artifact & Content Analysis
- Retrieve the **XSL** and **XML** (offline) where policy permits; scan for **script blocks**, **external entity references**, or **extension objects**.  
- Inspect **output** for embedded binaries/scripts or encoded blobs (Base64) that could be decoded later.

#### 4) Network & DNS Corroboration
- Correlate **Sysmon EID 3** and **proxy** logs for requests to the XML/XSL hosts; **Sysmon EID 22** for DNS lookups.  
- For **WebDAV UNC** patterns (`DavWWWRoot`, `@SSL`), egress may be via **WebClient svchost.exe** over **80/443**.

#### 5) Correlation & Fleet
- Pivot by **destination host**, **CLI substrings** (e.g., `.xsl`, `.xml`, `-s:` patterns), **hashes** of output files across endpoints.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Full CLI with remote paths and `ParentImage`.  
- **Sysmon EID 11:** Output writes; cache/temp artifacts.  
- **Sysmon EID 3 / Proxy:** HTTP(S) or WebDAV flows.  
- **Sysmon EID 22:** DNS for destination hosts.  
- **EDR timeline:** Child processes spawned by follow‑on stages.

### Containment Actions
- **Block** destination hosts/IPs; **quarantine** artifacts; **terminate** process chain; consider **host isolation** if execution is evidenced.

### Prevention Measures
- Egress filtering and **domain allowlists**; disable **WebClient** if unused.  
- AppLocker/WDAC to restrict direct use of `msxsl.exe` on non‑dev endpoints; monitor **rare process → URL** usage.

### Recovery
- Remove staged content/persistence; rotate credentials as needed; tune detections/runbooks.

### False Positives
- Legitimate data transforms in **dev/ETL** contexts pulling XML/XSL from **approved** intranet endpoints.

---

## Playbook 2 — MSXSL Outbound Network Connection (Sysmon EID 3)

### Overview
This playbook investigates **outbound connections** attributed to `msxsl.exe`. Local transforms are common; **remote** XML/XSL sourcing is not typical
for most users and can indicate **T1105** staging or scripted content processing.

### Initial Response
1. **Capture records:** Export **EID 3** (dest IP/host/port/proto) and correlate with **EID 1/4688** for `msxsl.exe`.  
2. **Classify destination:** Internal vs external; flag **raw IPs**, **new/rare domains**, **non‑standard ports**.  
3. **Scope usage:** Determine whether the user/asset normally performs **XSLT transforms** against remote inputs.

### Investigation Steps
#### 1) Process & Command Context
- Retrieve full **command line** to locate the XML/XSL URIs; validate `Image` and **parent**.  
- Check if **output file** paths or **pipes** (`>`) are used for writing results.

#### 2) Destination Validation
- Enrich destination domains/IPs and inspect **proxy** logs (method/status/bytes).  
- For **WebDAV**, pivot to **WebClient** telemetry; for **SMB UNC**, validate **445** sessions and share paths.

#### 3) Artifact Discovery
- Search for **EID 11** file writes near the event; hash/analyze outputs (look for **encoded payloads**).  
- Identify any **execution** of the outputs (child processes shortly after transform).

#### 4) Correlation & Fleet
- Pivot on **destinations**, **hashes**, and **CLI** patterns across hosts; cluster events by **parent/user**.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\msxsl.exe`, destination details.  
- **Sysmon EID 1 / 4688:** Process creation and CLI context.  
- **Sysmon EID 11:** Output writes and cache artifacts.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.

### Containment Actions
- **Block** endpoints; **quarantine** outputs; **terminate** activity; consider **host isolation** if follow‑on execution is observed.

### Prevention Measures
- Restrict `msxsl.exe` usage to sanctioned servers; enforce **egress controls**; monitor **rare process → network** pairs.  
- Alert on `msxsl.exe` accessing **Internet‑zone** URIs.

### Recovery
- Remove artifacts/persistence; tune detections/allowlists; update runbooks.

### False Positives
- Approved ETL/automation jobs performing remote transforms against trusted services.

---

## Playbook 3 — MSXSL Suspicious DNS Query (Sysmon EID 22)

### Overview
Investigate **DNS queries** temporally tied to `msxsl.exe` execution. When XML/XSL inputs are remote, `msxsl` (or underlying components) will resolve
hostnames for those resources. **New/rare** domains, **raw IP URL usage** (seen in command line), and **DGA‑like** patterns are suspicious.

### Initial Response
1. **Capture records:** Export **EID 22** with process attribution; correlate to `msxsl.exe` **EID 1/4688**.  
2. **Classify FQDNs:** Internal vs external; flag **recently registered** domains and **uncommon TLDs** (if TI available).  
3. **Proxy context:** In explicit proxy setups, EID 22 may only show the **proxy FQDN**; pull **proxy logs** to map upstream destinations.

### Investigation Steps
#### 1) Process & Command Context
- Confirm `msxsl.exe` CLI contains remote XML/XSL paths or `-s:` parameters with URLs; review **parent** and user.  
- Identify whether a corresponding **EID 3** egress exists to the same host/IP shortly after.

#### 2) Destination Enrichment
- Enrich FQDNs (age/reputation/hosting).  
- Cross‑reference **proxy** telemetry (Host/SNI, status/bytes, content-type).

#### 3) Artifact & Network Corroboration
- Check **EID 11** for resulting writes (outputs/cache) and hash/analyze them.  
- Look for **child processes** executing or loading the transformed outputs.

#### 4) Fleet & Follow‑On
- Pivot on **FQDN**, **hashes**, and **CLI** patterns across endpoints to assess spread.

### Key Artifacts
- **Sysmon EID 22:** DNS queries attributed to `msxsl.exe` (or proxy FQDN).  
- **Sysmon EID 1 / 4688:** Process creation context and CLI.  
- **Sysmon EID 3 / Proxy:** Network flows for the time window.  
- **Sysmon EID 11:** Output/cache file creation.

### Containment Actions
- **Block** suspicious domains; **quarantine** related files; **terminate** processes; consider **host isolation** if execution observed.

### Prevention Measures
- Domain allowlists; restrict Internet fetching by `msxsl.exe`; disable **WebClient** when unneeded.  
- App control to limit `msxsl.exe` usage; monitor **Internet‑zone** XSL/XML sourcing.

### Recovery
- Remove staged content/persistence; rotate credentials if exposure suspected; tune detections/runbooks.

### False Positives
- Legitimate transforms against trusted intranet endpoints; validate via owners and allowlist where appropriate.