# AppInstaller.exe (LOLBin) — T1105 Ingress Tool Transfer: Investigation Playbooks
_Last updated: 2025-10-25 14:29 UTC_

---

## Playbook 1 — T1105 · AppInstaller.exe Ingress via ms-appinstaller (Process Creation)

### Overview
Detects **AppInstaller.exe** invoked via the **`ms-appinstaller://`** protocol (for example, `ms-appinstaller://?source=...`), which causes the App Installer to **download** and stage a package from a remote URL. This is a high-fidelity, process-intent anchor for **Ingress Tool Transfer (T1105)** using a Microsoft-signed binary. Microsoft documents the web-install protocol and the enterprise policy controls; Microsoft also **disabled the handler by default** in Dec 2023, raising the signal of any usage unless explicitly re-enabled by policy.

### Attack Context
- **MITRE ATT&CK:** T1105 — Ingress Tool Transfer  
- **LOLBin:** `AppInstaller.exe` (Windows App Installer)  
- **Tradecraft:** Operators can deliver content via a simple link or command that triggers `ms-appinstaller://` to fetch a package from the web. Downloads typically stage under App Installer’s **INetCache** path prior to installation.  
- **Real-world relevance:** Microsoft disabled the handler by default (Dec 28, 2023) in response to abuse patterns; enterprise admins may re-enable it via the **DesktopAppInstaller** CSP/Group Policy when needed.

### Initial Response
- **Confirm policy posture:** Is `ms-appinstaller` allowed in your environment? If not, treat the alert as high severity.  
- **Capture intent:** Preserve **`CommandLine`** from the `AppInstaller.exe` process (source URL/parameters) and the **parent process** (Explorer/browser/shell).  
- **Scope user/host:** Identify whether this is a developer/packaging workstation or general user endpoint.

### Investigation Steps
1. **Process and Image Analysis**
   - Validate the **`Image`** path under **`C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*\AppInstaller.exe`**.  
   - Record **`ParentImage`**, **`User`**, **integrity level**, and **signer** of `AppInstaller.exe`.  
   - Extract the **source URL** and any flags from the command line.
2. **File and Path Analysis**
   - Inspect **`...\WindowsApps\Microsoft.DesktopAppInstaller_*\AC\INetCache\`** for **new files** around alert time (MSIX/AppX/appinstaller/EXE).  
   - Hash, reputation-check, and detonate suspicious files as needed.
3. **Correlation and Contextual Analysis**
   - **DNS (Sysmon EID 22):** Lookups by `AppInstaller.exe` to the destination host (if direct egress).  
   - **Network (Sysmon EID 3):** Connections to destination host or **enterprise proxy** (if explicit proxy is used).  
   - **Proxy-aware triage:** If an explicit proxy is configured, client DNS may only resolve the **proxy FQDN**; pivot to proxy logs for the real destination.  
   - **Delivery Optimization (DoSvc):** If DO is engaged, **DNS/egress may appear under `svchost.exe` (DoSvc)** instead of `AppInstaller.exe`—include that actor in pivots.

### Key Artifacts
- **Sysmon EID 1 / Security 4688:** `Image`, `CommandLine` (`ms-appinstaller://`), `ParentImage`, `User`.  
- **Sysmon EID 11:** `TargetFilename` under AppInstaller **INetCache**.  
- **Sysmon EID 22:** `Image=AppInstaller.exe`, `QueryName` of package host (or proxy FQDN).  
- **App Installer/MSIX logs** (installation outcomes), and EDR timeline (follow-on execution).

### Containment Actions
- Quarantine staged files; block the **source domain** at egress if malicious.  
- If usage is not sanctioned, **disable `ms-appinstaller`** via Group Policy/CSP and notify stakeholders.

### Prevention Measures
- Maintain Microsoft’s default hardening (**handler disabled**).  
- If business requires it, restrict to **approved source domains** and continuously monitor.  
- Educate users to avoid untrusted web-based installers.

### Recovery
- Remove unauthorized packages and staged files; validate no persistence or side-loading remains.  
- Review and document policy baselines; update allowlists and detections.

### False Positives
- Legitimate MSIX/AppX installs from approved vendor/corporate portals while `ms-appinstaller` is enabled (validate domain, signer, and hashes).

---

## Playbook 2 — T1105 · AppInstaller.exe Staging in INetCache (File Creation)

### Overview
Flags **Sysmon EID 11 (FileCreate)** when **`AppInstaller.exe`** writes into its **INetCache** under the App Installer package directory. This location is commonly used during web-based installs and is strong evidence of **payload ingress to disk**.

### Attack Context
- **MITRE ATT&CK:** T1105 — Ingress Tool Transfer  
- **LOLBin:** `AppInstaller.exe`  
- **Behavioral cue:** Fresh files under **`...\Microsoft.DesktopAppInstaller_*\AC\INetCache\`** contemporaneous with `ms-appinstaller://` usage.

### Initial Response
- Enumerate **new/modified files** under the App Installer **INetCache** path; collect **hashes, sizes, and signers**.  
- Confirm linkages to a recent `AppInstaller.exe` process (same host/user/time window).

### Investigation Steps
1. **Process and Image Analysis**
   - Correlate **EID 11** to the prior **`AppInstaller.exe`** instance using ProcessGUID/PPID/host/time.  
   - Retrieve the originating `CommandLine` and parent process.
2. **File and Path Analysis**
   - Identify file types (`.msix`, `.appx`, `.appinstaller`, `.msixbundle`, or `.exe`).  
   - Check **file metadata** (signer, version, PE timestamp) and **reputation**.  
   - Unpack and inspect if warranted.
3. **Correlation and Contextual Analysis**
   - **DNS (EID 22):** Queries for the source domain around the file write.  
   - **Network (EID 3):** `AppInstaller.exe` egress to host or proxy; verify dest aligns with the source URL.  
   - **Follow-on execution:** Look for `AppInstaller.exe` spawning the installer, or subsequent process creation from cache/output paths.

### Key Artifacts
- **Sysmon EID 11:** `TargetFilename` in AppInstaller **INetCache** with `Image=...\AppInstaller.exe`.  
- **Sysmon EID 1 / 4688:** `Image=AppInstaller.exe` with `ms-appinstaller://` intent.  
- **Sysmon EID 22:** Destination hostname lookups; **proxy** or **DoSvc** involvement where applicable.

### Containment Actions
- Quarantine/delete staged files; block the offending host; isolate the endpoint if execution is confirmed.

### Prevention Measures
- Keep `ms-appinstaller` disabled unless justified; monitor AppInstaller cache writes.  
- Maintain allowlists for trusted distribution domains; enforce content validation (hash/signature).

### Recovery
- Remove unauthorized software; clear caches; re-baseline integrity controls.  
- Update detections and policy controls based on findings.

### False Positives
- Legitimate enterprise software distribution via App Installer. Validate sources, signatures, and change windows.

---

## Playbook 3 — T1105 · AppInstaller.exe DNS Resolution (Sysmon EID 22)

### Overview
Detects **DNS queries** issued by **`AppInstaller.exe`** when resolving remote package hosts as part of web-based installs. This serves as **corroboration** alongside process-creation and file-creation evidence.

### Attack Context
- **MITRE ATT&CK:** T1105 — Ingress Tool Transfer  
- **Behavior:** `AppInstaller.exe` or related services resolve package hostnames prior to download.

### Initial Response
- Determine if the queried domain is **approved** by corporate policy. If not, increase severity.  
- Check whether `ms-appinstaller` usage is **allowed** on the host.

### Investigation Steps
1. **Process and Image Analysis**
   - Link EID 22 to a **recent `AppInstaller.exe`** run (EID 1/4688). Extract the **source URL** from process command line.  
   - Validate the `AppInstaller.exe` origin path under **WindowsApps**.
2. **File and Path Analysis**
   - Inspect App Installer **INetCache** for new artifacts matching the DNS timing; hash and review.  
   - Search for any installer execution that followed the lookup.
3. **Correlation and Contextual Analysis**
   - **Explicit proxy:** Client EID 22 may show only **proxy FQDN**; confirm the true destination via **proxy logs** (CONNECT/SNI/URL).  
   - **Delivery Optimization (DoSvc):** DNS/egress may be performed by **`svchost.exe` (DoSvc)**; include it in your pivots.  
   - **EDR telemetry:** Correlate with network/flow records and process lineage.

### Key Artifacts
- **Sysmon EID 22:** `Image` (`AppInstaller.exe`), `QueryName` (destination or proxy).  
- **Sysmon EID 1 / 4688:** `CommandLine` intent; **Sysmon EID 11:** AppInstaller cache writes.  
- **Proxy/DO telemetry:** Destination host and transfer details.

### Containment Actions
- Block resolution/egress to unapproved domains; disable the protocol if unjustified; consider host isolation.

### Prevention Measures
- Maintain allowlists for **trusted** package sources; keep Microsoft’s default hardening (handler disabled) unless explicitly required.  
- Enforce content validation (hash/signature) and monitor for anomalous sources.

### Recovery
- Purge malicious content from cache; remove unauthorized packages; update policies and detections.

### False Positives
- DNS to legitimate vendor CDNs during sanctioned installs while `ms-appinstaller` is enabled; validate business justification and signatures.

---

## References
- **LOLBAS — AppInstaller.exe** (Download to `INetCache`, WindowsApps path): https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/  
- **Microsoft Learn — Installing Windows apps from a web page** (ms-appinstaller): https://learn.microsoft.com/en-us/windows/msix/app-installer/installing-windows10-apps-web  
- **Microsoft Learn — App Installer overview & security features:** https://learn.microsoft.com/en-us/windows/msix/app-installer/app-installer-root , https://learn.microsoft.com/en-us/windows/msix/app-installer/app-installer-security-features  
- **Microsoft MSRC — “Microsoft addresses App Installer abuse”** (handler disabled by default, Dec 28, 2023): https://www.microsoft.com/en-us/msrc/blog/2023/12/microsoft-addresses-app-installer-abuse  
- **Sysmon — Event ID 1/11/22** (ProcessCreate, FileCreate, DNS Query): https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon