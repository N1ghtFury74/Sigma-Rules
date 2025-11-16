# T1105 — Ingress Tool Transfer · LOLBin: Desktopimgdownldr.exe  
**Rule:** CNC-E-2726320-140 — Desktopimgdownldr LockScreenURL Fetch  
**Last updated:** 2025-10-28 04:26 UTC

---

## Overview
This playbook supports investigation of alerts where **`Desktopimgdownldr.exe`** is invoked to **fetch a LockScreen/Spotlight image URL**.  
The binary is part of Windows’ Spotlight/Lock screen content pipeline and can retrieve remote content (typically images) over **HTTP/HTTPS**.  
Adversaries can repurpose it to **pull arbitrary content** from attacker-controlled endpoints and **stash** results under user- or system-writable
locations—constituting a **living‑off‑the‑land** **Ingress Tool Transfer (T1105)** step.

---

## Attack Context
- **Technique:** T1105 — Ingress Tool Transfer  
- **Binary:** `Desktopimgdownldr.exe` (signed Microsoft component; normally called by the Content Delivery/Spotlight stack)  
- **Detection intent (this rule):** Process creation with parameters that indicate **direct fetch of a LockScreen/Spotlight URL** (e.g., command line contains a **remote URL** or an explicit operation to **download** spotlight assets).  
- **Operator goal:** Use a **trusted binary** to reach out to remote infrastructure and **stage** the received payload (image or arbitrary content) on disk for later use.

---

## Initial Response
1. **Preserve context:** Export the **process‑creation** record (image, full command line, parent, user, integrity level, timestamp).  
2. **Extract destination:** Parse the command line for **URL/host/port**; record whether it’s an **approved Microsoft endpoint** or a **new/external** host.  
3. **Collect artifacts:** Determine the **write location** (Spotlight/Lock screen cache or a supplied output path) and immediately **acquire** any newly written files (hash + copy).  
4. **Baseline check:** Confirm whether Spotlight/Lock screen content is enabled and whether this host is expected to fetch content **at this time** under this **user** and **parent process**.

---

## Investigation Steps

### 1) Process and Image Analysis
- Validate `Image` path (e.g., `C:\Windows\System32\Desktopimgdownldr.exe` or under a Windows component store path).  
- Review `ParentImage` (typically system processes for legitimate fetches). Parentage from **script engines**, **Office**, or other **LOLBins** is suspicious.  
- Record all command‑line switches and **destination URL**; note **non‑standard ports** or **raw IP** usage.  
- Confirm **user** and **session**; Spotlight actions usually occur in the context of the signed content‑delivery pipeline.

### 2) File and Path Analysis
- Identify the **output/cache path**. Common locations include per‑user Spotlight caches (under the ContentDeliveryManager package directories) or `%ProgramData%`/system data paths.  
- Compute **hashes** of any new files, determine **file type** (image/script/other), check **entropy** and **headers** for mismatch/obfuscation.  
- Elevated risk if files land in **user‑writable** paths (Temp/Downloads/Public) or if **extension** does not match content type.

### 3) Network and DNS Corroboration
- **DNS (EID 22):** Lookups for the destination host; in explicit‑proxy setups you may see only **proxy FQDN** at the endpoint.  
- **Network (EID 3 / Proxy):** Connections from `Desktopimgdownldr.exe` (or via content services). Confirm **method** (GET) and **response size/status** when proxy logs exist.  
- Treat **non‑Microsoft** domains, **newly observed** hosts, **raw IPs**, and **non‑standard ports** as high‑signal.

### 4) Correlation & Follow‑On Activity
- Check for **subsequent execution** of the retrieved files (even if images—operators may smuggle data).  
- Pivot to sibling LOLBins (e.g., `powershell.exe`, `mshta.exe`, `rundll32.exe`) launched shortly after.  
- Perform **fleet prevalence** for the **URL/domain** and **hash**; identify other endpoints/users with similar activity.

---

## Key Artifacts
- **Process Creation (EID 1 / 4688):** `Image=...\Desktopimgdownldr.exe`, full `CommandLine`, `ParentImage`, `User`.  
- **File Creation (EID 11):** `TargetFilename` written by `Desktopimgdownldr.exe` or the calling component.  
- **DNS (EID 22):** `QueryName` to destination (or proxy FQDN) near the process event.  
- **Network (EID 3 / Proxy):** Destination host/port; HTTP method, status, response size if available.  
- **EDR timeline:** Process lineage; reads/opens of the downloaded artifact by other processes.

---

## Containment Actions
- **Quarantine** any retrieved artifacts; **block** the destination domain/IP.  
- **Terminate** suspicious process chains and consider **host isolation** if follow‑on execution or persistence is observed.  
- If sensitive data might have been retrieved or exposed, coordinate **data protection** and **credential rotation**.

---

## Prevention Measures
- Maintain **allowlists** for approved Spotlight/Content Delivery endpoints; alert on **non‑approved** domains or raw IPs.  
- Apply **application control** (AppLocker/WDAC) policies to limit LOLBin misuse on non‑managed endpoints.  
- Restrict execution from **user‑writable** paths; enable **AMSI/script** telemetry for common follow‑on tools.  
- Enforce **egress filtering** and monitor **new domains** contacted by Windows content pipelines.

---

## Recovery
- Remove staged payloads and any persistence; restore Spotlight/Lock screen settings if modified.  
- Update detections and allowlists with environment‑specific baselines; document deviations.

---

## False Positives
- Legitimate Spotlight/Lock screen content refresh contacting **approved Microsoft endpoints**.  
- Enterprise customization tools that manage lock screen assets during **approved** maintenance windows.  
- Mitigation: Add **approved domains/paths** to allowlists; verify **tickets/owners** and timing.