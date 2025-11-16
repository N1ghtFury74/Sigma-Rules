# T1105 — Ingress Tool Transfer · LOLBin: CertUtil.exe  
**Rule:** CNC-E-2726320-133 — CertUtil Suspicious Arguments (verifyctl / urlcache / -url / /url)  
**Last updated:** 2025-10-28 04:17 UTC

---

## Overview
This playbook supports investigation of alerts where **`certutil.exe`** is launched with arguments commonly
abused to **retrieve or stage content**: `verifyctl`, `urlcache`, and URL download flags (`-url` or `/url`).
While CertUtil is a built‑in certificate utility, adversaries frequently leverage it to **download** or **cache**
payloads (sometimes combining with **`-f`** force and **`-split`** options) as part of **Ingress Tool Transfer (T1105)**.

---

## Attack Context
- **Technique:** T1105 — Ingress Tool Transfer  
- **Binary:** `certutil.exe` (typically in `C:\Windows\System32\`)  
- **Behavioral patterns covered by this rule:**
  - **`certutil -url <URL>` / `certutil /url <URL>`** — Direct URL fetch patterns.
  - **`certutil -urlcache`** — Uses the URL cache functionality to download and optionally persist content.
  - **`certutil -verifyctl`** — Certificate chain/content retrieval/verification that can be abused to fetch remote data.
- **Common operator refinements (not necessarily in the rule):** `-f` (force overwrite), `-split` (split downloaded content), output filename redirection, Base64 encode/decode pivots.

---

## Initial Response
1. **Preserve process context**: Export the **process creation** record (image path, full command line, parent, user, time).  
2. **Extract the URL(s)**: Parse the command line for **destination URLs**, noting scheme, host, and **non‑standard ports**.  
3. **Capture artifacts**: Identify **output file names** (explicit or implied) and **collect** those files immediately (hash + copy).  
4. **Classify the host**: Determine whether the endpoint is expected to run CertUtil for PKI tasks; most user workstations are not.

---

## Investigation Steps

### 1) Process and Image Analysis
- Verify `Image` is **`C:\Windows\System32\certutil.exe`** and **OriginalFileName** = `CertUtil.exe`.  
- Review `ParentImage` (browser, script host, Office app, another LOLBin).  
- Confirm the suspicious switches present: `-url` or `/url`, `-urlcache`, `verifyctl`; note if `-f`/`-split` is also used.  
- Record **user**, **session**, and **integrity level** for privilege context.

### 2) Command‑Line Semantics
- Identify **destination URL(s)** and any **output paths**. If none are specified, determine default write location (often **current working directory**).  
- If the command references **Base64** operations, look for subsequent **encode/decode** usage or output hints (e.g., `.b64`).  
- Note chained usage: multiple sequential CertUtil invocations, or piping to other binaries.

### 3) File and Path Analysis
- Search for **newly created/modified files** around the alert time in **Temp**, **Downloads**, **Public**, and the **process CWD**.  
- Compute **hashes**, extract **strings**, and determine **file type** (PE/script/text/archive).  
- Assess risk by **write location** (user‑writable paths are higher risk) and **naming** (random names, extension mismatch).

### 4) Network and DNS Corroboration
- Check **DNS queries (EID 22)** from `certutil.exe` around the event (or proxy FQDN if using explicit proxy).  
- Review **network events (EID 3)** and **proxy telemetry** for connections from `certutil.exe` to the same host/URL.  
- Confirm **HTTP method** (often `GET`) and **response size/status** where available; flag **raw IPs**, **new domains**, **unusual ports**.

### 5) Correlation and Follow‑On Activity
- Look for **follow‑on execution** of the downloaded file (child process of CertUtil or subsequent launcher).  
- Pivot to related **script engines** (`powershell.exe`, `wscript.exe`, `mshta.exe`), **LOLbins**, or **archive tools** used shortly after.  
- Perform **fleet prevalence** checks on the **URL**, **domain**, and **hash**; identify additional affected hosts.

---

## Key Artifacts
- **Process Creation (EID 1 / 4688):** `Image=...\certutil.exe`, `CommandLine` containing `verifyctl` / `urlcache` / `-url` / `/url`.  
- **File Creation (EID 11):** `TargetFilename` written by `certutil.exe`.  
- **DNS (EID 22):** `QueryName` for the destination host (or proxy FQDN).  
- **Network (EID 3 / Proxy):** Destination IP/host/port; method, status code, response size if available.  
- **EDR timeline:** Lineage showing subsequent use or execution of retrieved artifacts.

---

## Containment Actions
- **Quarantine** any retrieved/staged files; **block** the destination domain/IP.  
- **Terminate** suspicious processes and consider **host isolation** if execution/persistence is confirmed.  
- If credentials/cert material may have been exposed, **rotate** or revoke as needed.

---

## Prevention Measures
- Maintain **allowlists** for approved software distribution/CDN domains; alert on **new or unapproved** destinations.  
- Disable or restrict **CertUtil** where feasible with **AppLocker/WDAC**; monitor for alternative LOLBins.  
- Enforce **script controls** (AMSI, PowerShell logging) and egress filtering for non‑admin endpoints.  
- Educate admins to use sanctioned **package managers** or **config‑mgmt** tools instead of ad‑hoc CertUtil downloads.

---

## Recovery
- Remove staged payloads and any **persistence** connected to the event.  
- Update **detections**, **allowlists**, and **host baselines** to reflect findings.  
- Document deviations and add targeted hunt queries for similar command lines.

---

## False Positives
- **Legitimate certificate troubleshooting** where CertUtil queries remote CRLs/OCSP or uses URL/cache operations.  
- **IT automation** or **software deployment** that intentionally uses CertUtil for controlled downloads/cache management.  
- Mitigation: Add **approved domains/paths** and **known scripts** to environment‑specific allowlists; validate **change tickets**.