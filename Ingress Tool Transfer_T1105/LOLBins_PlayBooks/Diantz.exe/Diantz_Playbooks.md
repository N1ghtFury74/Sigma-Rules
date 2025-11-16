# T1105 — Ingress Tool Transfer · LOLBin: Diantz.exe  
**Rules:**  
- CNC-E-2726320-142 — Diantz Network Connection (Sysmon EID 3)  
- CNC-E-2726320-143 — Diantz Download and CAB Creation  
**Last updated:** 2025-10-28 04:29 UTC

---

## Playbook 1 — Diantz Network Connection (Sysmon EID 3)

### Overview
This playbook supports investigation of alerts where **`diantz.exe`** establishes **network connections** (Sysmon **EID 3**).
Although **Diantz** (aka **MakeCab**) is a Windows cabinet creation utility, operators can abuse it to **pull source
content from remote locations** (e.g., **UNC/WebDAV/SMB**) while building a CAB, thereby using a trusted binary in an
**Ingress Tool Transfer (T1105)** workflow.

### Initial Response
1. **Preserve context:** Export the **network connection** record (process, dest IP/host/port, timestamp) and the **linked process creation** (EID 1/4688) if present.  
2. **Extract destination:** Identify **domain/IP**, **port**, and **scheme**. Treat **raw IPs**, **non‑standard ports**, or **new domains** as high‑risk.  
3. **Scope the host:** Determine whether CAB creation is expected for this asset/user (build server vs end user).

### Investigation Steps
#### 1) Process & Lineage
- Confirm `Image` path (e.g., `C:\Windows\System32\diantz.exe`) and signer metadata.  
- Review `ParentImage` and `CommandLine` (EID 1/4688) for the active CAB **job** — look for source paths that are **remote** (e.g., `\\host\share\...`, `\\host\DavWWWRoot\...`).  
- Capture **working directory** and any **list files**/directives passed to diantz.

#### 2) Destination Validation
- Enrich **dest host/IP** (internal vs external, age/reputation).  
- If **WebDAV** is suspected, check for parallel egress via **`svchost.exe`** hosting **WebClient**; for **SMB**, validate **445** sessions and **Network Logon (Type 3)**.

#### 3) Artifact Discovery
- Identify **CAB outputs** produced around the event (look for `.cab` under **Temp/Downloads/Public** or job path).  
- Hash and inspect CAB contents (use **expand/extrac32** to preview); look for **executable/script** material.  
- Review for **staging** behavior (multiple small CABs, odd naming, entropy anomalies).

#### 4) Correlation & Follow‑On
- Check for **follow‑on execution** of files **inside** the CAB after extraction.  
- Hunt for adjacent LOLBins (`powershell.exe`, `rundll32.exe`, `regsvr32.exe`, `mshta.exe`) within minutes of CAB creation.  
- Perform **fleet prevalence** for the destination and CAB hashes.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\diantz.exe`, destination `IP/Port` and `Protocol`.  
- **Sysmon EID 1 / Security 4688:** `Image`, `CommandLine`, `ParentImage`, `User`.  
- **Sysmon EID 11:** `.cab` file creation by `diantz.exe`.  
- **Sysmon EID 22 / Proxy logs:** DNS lookups or proxy FQDN; HTTP(S) details if WebDAV/proxy involved.  
- **SMB/NetUse telemetry:** Session and mapping evidence for UNC sources.

### Containment Actions
- **Block** suspicious destinations; **terminate** the diantz job and dependent processes.  
- **Quarantine** any produced CABs and extracted payloads; consider **host isolation** on execution.

### Prevention Measures
- Restrict **WebClient** (WebDAV) where not required; enforce **egress filtering** for endpoints.  
- Apply **application control** (AppLocker/WDAC) to limit LOLBin abuse; restrict execution from **user‑writable** paths.  
- Monitor for **CAB creation** in risky locations and for **remote source paths** used by packaging tools.

### Recovery
- Remove staged payloads/CABs; clean up mappings; rotate credentials used for remote shares; update allowlists.

### False Positives
- Legitimate packaging/build processes that assemble CABs from **approved internal** shares or repositories.  
- Enterprise deployment tools using remote sources under change‑controlled windows. Add **approved hosts/paths** to allowlists.

---

## Playbook 2 — Diantz Download and CAB Creation

### Overview
This playbook guides investigation when **`diantz.exe`** is used to **download** content and **create a CAB** (often writing
to **user‑writable** locations). Adversaries can combine remote source paths with CAB creation to **stage tools/data**
in a compact container and then **extract** them using standard Windows utilities (**expand/extrac32**).

### Initial Response
1. **Capture context:** Export the **process creation** (EID 1/4688) for `diantz.exe` and any **file creation** (EID 11) of the **.cab**.  
2. **Collect artifacts:** Acquire the **CAB** file(s) and any **extracted** outputs (hash, copy, and preserve timestamps).  
3. **Determine intent:** Identify **source inputs** (local vs remote) and **output paths**; note **naming** and **locations**.

### Investigation Steps
#### 1) Command‑Line Semantics
- Parse the **diantz** arguments: input list/spec, directives, and destination **`.cab`** path.  
- Flag **remote inputs** (UNC/WebDAV), **non‑standard ports**, or **raw IP** references.  
- Review **working directory** and any **directive files** (e.g., DDF) that might specify remote items.

#### 2) File & Content Analysis
- Validate the **CAB** integrity and enumerate contents (list with **expand /D** or **extrac32**).  
- Compute **hashes** for embedded files; determine **file types** (PE/script/text/archive) and check for **obfuscation**.  
- Assess **write locations** for the CAB and extracted files (Temp/Downloads/Public).

#### 3) Network & DNS Corroboration
- Check **EID 3** for connections from `diantz.exe`; if WebDAV is used, egress may be visible under **WebClient**’s `svchost.exe`.  
- Review **EID 22** for DNS queries to remote hosts (or proxy FQDN in explicit‑proxy setups).  
- Pull **proxy logs** for **HTTP method**, **status**, and **response size** where available.

#### 4) Follow‑On & Lateral Context
- Search for **extraction** and **execution** of CAB contents (e.g., `expand.exe`, `extrac32.exe`, or `copy`/`xcopy` usage).  
- Pivot to **script engines** or **LOLBins** executing shortly after CAB creation; check **scheduled tasks** or **startup** locations.  
- Run **fleet prevalence** on CAB hash and destination hosts.

### Key Artifacts
- **Sysmon EID 1 / 4688:** `diantz.exe` `CommandLine`, `ParentImage`, `User`.  
- **Sysmon EID 11:** `.cab` creation and subsequent file writes (post‑extraction).  
- **Sysmon EID 3 / Proxy:** Connections tied to `diantz.exe` (or WebClient for WebDAV).  
- **Sysmon EID 22:** DNS requests for remote sources.  
- **EDR timeline:** Parent/child graph and module loads referencing CAB contents.

### Containment Actions
- **Quarantine** the CAB and extracted files; **block** associated destinations.  
- **Terminate** related processes; consider **host isolation** if execution/persistence is confirmed.

### Prevention Measures
- Monitor/alert on **CAB creation** in **user‑writable** locations and on **remote input** usage by packaging tools.  
- Disable **WebClient** where not needed; enforce **egress filtering** and **allowlists** for internal sources.  
- Apply **application control** to limit LOLBin misuse and execution of newly created binaries from risky paths.

### Recovery
- Remove staged content and any persistence; reset mappings/credentials; update detection tuning and runbooks.

### False Positives
- Legitimate software packaging, driver signing/build pipelines, or deployment tasks that produce CABs from internal sources.  
- Approved admin workflows assembling CABs during maintenance windows; tune via **host/path/domain** allowlists.