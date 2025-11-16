# T1105 — Ingress Tool Transfer · LOLBin: DTUtil.exe  
**Rule:** CNC-E-2726320-179 — DTUtil Network Connection (Sysmon EID 3)  
**Last updated:** 2025-10-28 04:31 UTC

---

## Overview
This playbook supports investigation of alerts where **`dtutil.exe`** establishes **network connections** (**Sysmon EID 3**).  
`DTUtil.exe` is the SQL Server Integration Services (SSIS) Deployment Utility used to **copy/export/import** SSIS packages between
the **file system**, **SQL Server (msdb/SSIS Catalog)**, and **package stores**. Adversaries may abuse it to **pull SSIS packages** (which can
embed scripts/configs/secrets) from **remote paths** (e.g., SMB/WebDAV/UNC) or to **stage content** to disk as part of an
**Ingress Tool Transfer (T1105)** workflow.

---

## Initial Response
1. **Preserve context:** Export the **network connection** record and the **linked process creation** (EID 1 / 4688) for `dtutil.exe`.  
2. **Extract destination:** Capture **domain/IP**, **port**, and **protocol**; classify as **internal** vs **external**.  
3. **Scope role & user:** Determine if the host is an **SSIS/SQL admin workstation** or a general endpoint; confirm the **user’s role**.

---

## Investigation Steps

### 1) Process & Lineage
- Verify the `Image` path (commonly under `C:\Program Files\Microsoft SQL Server\...\DTUtil.exe`) and signer/metadata.  
- Review `ParentImage` and `CommandLine` (EID 1 / 4688) for **source/target** arguments indicating where packages are coming from/going to:  
  - **/FILE** or **/SOURCEFILE** (local/UNC)  
  - **/SQL** (SQL Server path, e.g., `MSDB\...`) with **/SERVER** specifying instance/host  
  - **/DESTFILE**, **/DESTSQL**, **/COPY**, **/MOVE**, **/EXISTS** operations  
- Record the **working directory** and any referenced **config files** (`.dtsConfig`) or **connection managers**.

### 2) Destination Validation
- If the connection is to **SQL Server**, validate **TCP 1433** (or custom port) to a **legitimate** instance; enrich server ownership.  
- For **UNC/SMB** sources (e.g., `\\host\share\pkg.dtsx`), corroborate **SMB sessions** and **logon type 3** events.  
- For **WebDAV UNC** (e.g., `\\host\DavWWWRoot\...` or `\\host@SSL\DavWWWRoot\...`), expect egress by **WebClient**’s `svchost.exe` over **80/443**; pivot to proxy logs.  
- Flag **raw IPs**, **non‑standard ports**, and **new/unapproved** domains as **high‑signal**.

### 3) Artifact Discovery
- Identify **output locations**:  
  - If **exporting to file**, look for new **`.dtsx`**, **`.dtproj`**, or **archives** under **%TEMP%**, **Downloads**, **Public**, or specified paths.  
  - If **importing**, look for **package deployment** into local stores (SSIS Package Store / MSDB).  
- Compute **hashes**; inspect **package contents** with trusted tooling (look for embedded **scripts**, **credentials**, **connection strings**).

### 4) Correlation & Follow‑On
- Search for **subsequent execution** using retrieved artifacts (e.g., `dtexec.exe` running a newly acquired package).  
- Pivot to **PowerShell**, **wscript**, **mshta**, or **rundll32** launched shortly after the network connection.  
- Perform **fleet prevalence** on destination host and hashes of retrieved/exported packages/files.

---

## Key Artifacts
- **Sysmon EID 3:** `Image=...\DTUtil.exe`, `DestinationIp`, `DestinationPort`, `Protocol`.  
- **Sysmon EID 1 / Security 4688:** `Image`, full `CommandLine` (look for `/COPY`, `/MOVE`, `/FILE`, `/SQL`, `/SERVER`).  
- **Sysmon EID 11:** New files created (`.dtsx`, configs, archives) attributed to `dtutil.exe`.  
- **Sysmon EID 22 / DNS:** `QueryName` for destination (or proxy FQDN).  
- **SQL/SSIS logs:** Package import/export operations and catalog events (if available).  
- **SMB/Proxy telemetry:** UNC/WebDAV corroboration.

---

## Containment Actions
- **Quarantine** exported/imported packages or staged files; **block** suspicious destinations.  
- **Terminate** related processes (`dtutil.exe`, `dtexec.exe`) if malicious use is confirmed; consider **host isolation** on execution.  
- If credentials or connection strings are exposed within packages, **rotate** and **re‑issue** secrets.

---

## Prevention Measures
- Restrict `dtutil.exe` usage with **AppLocker/WDAC** to **admin workstations/servers** only.  
- Limit **SSIS** access via least privilege; enforce **egress filtering** and **allowlists** for trusted package sources.  
- Monitor for **package execution** (`dtexec.exe`) from **user‑writable** paths and unexpected users.  
- Secure **package configurations**; avoid embedding secrets; enable auditing on **SSIS Catalog** operations.

---

## Recovery
- Remove staged payloads/packages and any follow‑on persistence.  
- Re‑baseline SSIS package inventories and connection managers; update allowlists and detections.  
- Document deviations and tune rules based on approved admin workflows.

---

## False Positives
- Legitimate **SSIS package migration** or **backup/restore** operations during **approved maintenance windows**.  
- Admins exporting packages to internal shares for **versioning** or **CI/CD** pipelines.  
- Mitigation: Allowlist **known servers/shares**, enforce **change tickets**, and validate **operator identity**.