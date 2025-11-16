# T1046 — Network Service Discovery (Finger) · LOLBin: Finger.exe  
**Rules:**  
- CNC-E-2726320-150 — Finger.exe Invocation (Deprecated Protocol) · Process Creation  
- CNC-E-2726320-151 — Finger.exe Network Connection to TCP/79 · Sysmon EID 3  
- CNC-E-2726320-152 — FileCreate by Finger.exe · Sysmon EID 11  
**Last updated:** 2025-10-28 05:50 UTC

> Although primary mapping is **T1046 (Network Service Discovery)**, in some abuse patterns `finger.exe` can be repurposed for low‑bandwidth
> **ingress/egress** of text (e.g., operator tasking or exfil of short data via crafted finger responses), which may overlap **T1105 (Ingress Tool Transfer)**
> or **T1041 (Exfiltration Over C2 Channel)**. Treat such cases as higher risk.

---

## Playbook 1 — Finger.exe Invocation (Deprecated Protocol) · Process Creation

### Overview
This playbook supports investigations where **`finger.exe`** is launched interactively or by another process. The **Finger** protocol (TCP/79)
is **deprecated** and rarely used in modern enterprises. Any explicit invocation may indicate **reconnaissance** against internal or external
hosts, or creative abuse to retrieve operator **instructions/payload stubs** embedded in server responses.

### Initial Response
1. **Preserve context:** Export **process creation** (EID 1 / 4688): `Image`, full `CommandLine`, `ParentImage`, `User`, integrity level, timestamp.  
2. **Extract target:** Parse **host** (and optional **user** spec, e.g., `user@host` or `@host`); classify as **internal** vs **external**.  
3. **Scope intent:** Determine if this host/user should ever use `finger.exe` (generally **no** on typical endpoints).

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path (e.g., `C:\\Windows\\System32\\finger.exe`) and signer/metadata.  
- Review `ParentImage` for suspicious launch chains (script engines, Office, browsers, other LOLBins).  
- Record arguments (e.g., `finger user@host`, `finger @host`, or batched queries via redirection).

#### 2) Command‑Line Semantics
- Note any **redirections** (`>`, `>>`) or **pipes** which may write outputs to local files or feed downstream tools.  
- Treat **raw IPs**, **FQDNs outside allowlists**, and **unusual user specifiers** as higher risk.

#### 3) Network & DNS Corroboration
- **DNS (EID 22):** Queries for the target host (or proxy FQDN in explicit‑proxy environments).  
- **Network (EID 3):** Outbound **TCP/79** connection attributed to `finger.exe` (or via proxies if present).  
- Pull **proxy/firewall** records for session details where available.

#### 4) Artifact Discovery & Follow‑On
- If output redirection is suspected, look for **new files** in `%TEMP%`, `%USERPROFILE%`, `Downloads`, or working dir.  
- Search for subsequent tools (PowerShell, wscript, mshta, rundll32) that may parse/execute response data.  
- Perform **fleet prevalence** for the same target host and command‑line pattern.

### Key Artifacts
- **Sysmon EID 1 / 4688:** Process launch details for `finger.exe`.  
- **Sysmon EID 3:** `DestinationPort=79`, destination IP/host.  
- **Sysmon EID 22:** DNS queries tied to the execution window.  
- **Sysmon EID 11:** Files created due to output redirection.  
- **EDR timeline:** Parent/child and module loads for downstream use of response data.

### Containment Actions
- **Block** outbound TCP/79 at egress if unused; **terminate** suspicious chains; **quarantine** files produced via redirection.  
- Consider **host isolation** if follow‑on execution or persistence is observed.

### Prevention Measures
- Apply **egress filtering** (deny TCP/79 by default); maintain **domain/IP allowlists**.  
- Restrict rarely‑used network utilities via **AppLocker/WDAC**; monitor for **rare process → port** pairs.  
- Disable legacy services internally that still expose **finger** unless explicitly needed.

### Recovery
- Remove staged artifacts; tune detections/allowlists; document deviations and educate users/admins on legacy protocol risks.

### False Positives
- Very rare: lab/testing by network teams against internal legacy hosts. Validate with change records and system owners.

---

## Playbook 2 — Finger.exe Network Connection to TCP/79 · Sysmon EID 3

### Overview
This playbook covers alerts where **`finger.exe`** establishes an **outbound connection** to **TCP port 79**. On modern networks, this
is almost always anomalous. Treat as **high‑signal reconnaissance** or **data fetch** attempt unless proven otherwise.

### Initial Response
1. **Capture records:** Export **EID 3** (dest IP/host/port, protocol) and correlate to nearby **EID 1/4688** for `finger.exe`.  
2. **Classify destination:** Internal vs external; check **new domain**, **raw IP**, **geolocation**, and **reputation**.  
3. **Scope blast radius:** Search fleet for additional TCP/79 connections in the same timeframe/user context.

### Investigation Steps
#### 1) Linkage & Context
- Confirm the launching **parent process** and **user**; evaluate interactive vs scripted automation.  
- Review the **command line** for user/host spec and any **output redirection** hints.

#### 2) Destination Intelligence
- Enrich host/IP: ownership, age, ASN; compare against **allowlists** and threat intel.  
- If internal, verify whether a **legacy finger service** exists and is sanctioned; collect server logs if possible.

#### 3) Artifact & Follow‑On
- Search for **file creations** after the connection (e.g., redirected outputs); hash and analyze the contents.  
- Look for **downstream tools** that parse or act on the retrieved data.  
- Conduct **prevalence** on the destination and artifacts across the fleet.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\finger.exe`, `DestinationPort=79`.  
- **Sysmon EID 1 / 4688:** Launch context and `CommandLine`.  
- **Sysmon EID 22:** DNS queries to destination.  
- **Sysmon EID 11:** Resulting files from redirection (if any).

### Containment Actions
- **Block** destination; **disable** outbound 79 at the perimeter; **terminate** active sessions; quarantine artifacts.

### Prevention Measures
- Egress filtering default‑deny for **legacy ports**; AppLocker/WDAC controls on `finger.exe`.  
- Alert on **rare port usage** and **rare process** initiating network connections.

### Recovery
- Remove artifacts; update tuning; document and communicate findings to network/security ops.

### False Positives
- Exceptional: legitimate diagnostics against lab systems running finger; verify by ticket/owner.

---

## Playbook 3 — FileCreate by Finger.exe · Sysmon EID 11

### Overview
This playbook supports cases where `finger.exe` is the **image** responsible for a **file creation** event (e.g., via shell redirection
`>`/`>>` of server responses). This can represent **staging** of text instructions or **data smuggling** via legacy protocol responses.

### Initial Response
1. **Secure the artifact:** Copy and **hash** the file; preserve timestamps and **owner**.  
2. **Trace lineage:** Link the **EID 11** to the preceding `finger.exe` **EID 1/4688** to recover the command line and parent.  
3. **Scope:** Identify other hosts/users producing similar artifacts.

### Investigation Steps
#### 1) Artifact Inspection
- Determine **file type** (text/script/binary) and inspect **strings**; look for URLs, IPs, commands, or credential fragments.  
- Check for **encoding** (Base64/Hex) and **obfuscation** markers; measure **entropy**.

#### 2) Process & Command Context
- Retrieve the associated **command line** (target `user@host`), working directory, and **write path** (Temp/Downloads/Public).  
- Assess **user context** (interactive vs service) and **integrity level**.

#### 3) Network & DNS Corroboration
- Confirm **TCP/79** connections (EID 3) to the host queried; collect **DNS (EID 22)** for name resolution evidence.  
- In proxy environments, check **gateway logs** even if the client didn’t resolve the final host directly.

#### 4) Follow‑On & Fleet
- Search for **subsequent execution** of the artifact or parsing by adjacent tools.  
- Run **fleet prevalence** for file hash, name pattern, and destination host to locate additional cases.

### Key Artifacts
- **Sysmon EID 11:** `TargetFilename` created by `finger.exe`.  
- **Sysmon EID 1 / 4688:** Prior `finger.exe` launch and command line.  
- **Sysmon EID 3 & 22:** Network/DNS corroboration to the queried server.  
- **EDR timeline:** Parent/child graph and any process reading the new file.

### Containment Actions
- **Quarantine** the file; **block** the destination host; terminate related processes; consider **host isolation** if code exec observed.

### Prevention Measures
- Deny **TCP/79** egress; restrict `finger.exe` with **application control**; monitor for **redirection** by legacy utilities.  
- Baseline and alert on **rare process → file‑write** patterns into user‑writable locations.

### Recovery
- Remove staged content and any persistence; update runbooks and allowlists/tuning.

### False Positives
- Extremely uncommon: controlled testing capturing finger responses to a file for troubleshooting; validate with change records.