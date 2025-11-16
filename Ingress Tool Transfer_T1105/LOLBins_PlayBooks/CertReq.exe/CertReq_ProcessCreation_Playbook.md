# T1105 — Ingress Tool Transfer · LOLBin: CertReq.exe  
**Rule:** CNC-E-2726320-132 — CertReq ProcessCreation Arguments  
**Last updated:** 2025-10-28 04:15 UTC

---

## Overview
This playbook supports investigation of alerts where **`certreq.exe`** is executed with **process-creation arguments** that indicate potential **file download via HTTP POST** (e.g., `-post -config http(s)://... <src> <dst>`). While CertReq is legitimately used for certificate enrollment, the same flow can be repurposed to transfer arbitrary content to disk using a signed Windows binary—an instance of **Ingress Tool Transfer (T1105)**.

---

## Attack Context
- **Technique:** T1105 — Ingress Tool Transfer  
- **Binary:** `certreq.exe` (typically under `C:\Windows\System32\` and/or `C:\Windows\SysWOW64\`)  
- **Behavioral pattern:** Command lines including **`-post`** and **`-config`** with a **HTTP/HTTPS URL**, taking two additional arguments:
  1) **Local source** file path (payload for the POST body; can be a decoy)
  2) **Output** file path (where the HTTP response body is written)  
- **Operational use:** Fetch small text or script payloads, then trigger **follow-on execution** (PowerShell, wscript, mshta, cmd).

---

## Initial Response
1. **Preserve context**: Export the full **process creation** record (image path, command line, parent, user, timestamp, integrity level).  
2. **Capture artifacts**: Identify the **output file** argument and immediately **collect** it (hash, copy, quarantine if required).  
3. **Scope the host**: Determine whether the endpoint reasonably performs PKI tooling (admin or enrollment server vs user workstation).  
4. **Establish egress intent**: Extract the **URL** from the `-config` argument; note **domain/IP** and **port**.

---

## Investigation Steps

### 1) Process and Image Analysis
- Verify `Image` path and **OriginalFileName** = `CertReq.exe` (to detect renames).  
- Review `ParentImage` and `ParentCommandLine` for suspicious launch chains (script engines, Office, other LOLBins).  
- Confirm presence of **`-post`**, **`-config http(s)://`**, **local source**, and **output file** arguments.  
- Check **user context** and **token** (service vs interactive user).

### 2) File and Path Analysis
- Locate the **output file** (last argument). Record **path**, **size**, **extension**, and **timestamps**.  
- Compute **hash** (MD5/SHA256) and extract **strings** to identify URLs/domains or indicators.  
- Inspect **file type** (text/script/PE/archive); evaluate **entropy** and **headers** for obfuscation.  
- Assess **write location** risk (Temp/Downloads/Public or user profile paths are higher risk).

### 3) Network and DNS Corroboration
- Review per-process **DNS** lookups around the event for the destination host (or proxy FQDN in explicit-proxy setups).  
- Confirm **network connections** from `certreq.exe` or via the enterprise proxy. Where available, pull **HTTP method (POST)**, **host**, **path**, **status**, and **response size** from proxy logs.  
- If the URL uses a **raw IP** or **non-standard port**, increase severity.

### 4) Follow-on Execution & Lateral Context
- Search for **subsequent process creation** where the **output file** is launched or loaded (child of certreq.exe or shortly after by another process).  
- Pivot to concurrent alerts on the host (PowerShell, wscript, mshta, rundll32, regsvr32).  
- Check **fleet prevalence** of the same **URL** or **hash**; identify other impacted hosts/users.

---

## Key Artifacts
- **Process Creation (EID 1 / 4688):** `Image`, `CommandLine`, `ParentImage`, `User`, `IntegrityLevel`.  
- **File Creation (EID 11):** `TargetFilename` (output), `Image=...\certreq.exe`.  
- **DNS (EID 22):** `QueryName` to destination host (or proxy).  
- **Network (EID 3 / proxy telemetry):** Destination IP/host/port; confirm POST and response.  
- **EDR timeline:** Process lineage and module loads referencing the output file.

---

## Containment Actions
- **Quarantine** the output artifact and **block** the destination **domain/IP** at the edge/proxy.  
- **Terminate** related processes; consider **host isolation** if follow-on execution is confirmed.  
- If credentials or certificate material may have been exposed during testing/misuse, **rotate** as appropriate.

---

## Prevention Measures
- Maintain **allowlists** of approved PKI endpoints; alert on **non-approved** destinations.  
- Apply **application control** (AppLocker/WDAC) for script engines and unneeded LOLBins.  
- Enforce **script controls** (AMSI, PowerShell logging) and **outbound filtering** for endpoints without PKI needs.  
- Educate administrators on safer transfer methods and proper tool usage.

---

## Recovery
- Remove staged payloads and any established **persistence**.  
- Re-baseline network and application **allowlists**.  
- Update detections and document environment-specific exceptions.

---

## False Positives
- **Legitimate PKI testing** or **diagnostics** using CertReq with HTTP endpoints explicitly allowed by corporate policy.  
- **Automation** that utilizes CertReq POST internally (rare; verify change tickets, approved destinations, and ownership).