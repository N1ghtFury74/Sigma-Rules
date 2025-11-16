# T1105 — Ingress Tool Transfer · LOLBin: FTP.exe  
**Rules:**  
- CNC-E-2726320-154 — FTP.exe Network Connection (Sysmon EID 3)  
- CNC-E-2726320-155 — FTP.exe Process Execution (Process Creation)  
**Last updated:** 2025-10-28 05:54 UTC

> Notes: `ftp.exe` is a legacy Windows client typically unused in modern enterprises. Adversaries commonly leverage it to
> **download (get/mget)** payloads or **exfiltrate (put/mput)** data. While this package focuses on **T1105 (Ingress Tool Transfer)**,
> also consider **T1041 (Exfiltration Over C2 Channel)** when uploads are observed.

---

## Playbook 1 — FTP.exe Network Connection (Sysmon EID 3)

### Overview
This playbook supports investigations where **`ftp.exe`** initiates **network connections** (Sysmon **EID 3**). FTP uses a **control channel**
to TCP **21** and separate **data channels** which vary by mode:
- **Active mode**: Server opens data connection **back** to client from **TCP/20 → client ephemeral**.
- **Passive mode**: Client opens data connection to a **server‑chosen high port** (advertised in `227 Entering Passive Mode`).

Both patterns can appear in telemetry as additional connections besides TCP/21. Attackers abuse `ftp.exe` for scripted pulls of tools.

### Initial Response
1. **Capture records:** Export **EID 3** for `ftp.exe` (dest IP/host/port, direction) and link to nearby **EID 1/4688** (process creation).  
2. **Classify destination:** Internal vs external; flag **raw IPs**, **new domains**, **non‑standard ports**, and unusual **geos/ASNs**.  
3. **Scope usage:** Determine whether the endpoint/user is expected to run legacy FTP (usually **no** for workstations).

### Investigation Steps
#### 1) Process & Lineage
- Confirm `Image` path (e.g., `C:\\Windows\\System32\\ftp.exe`) and signer/metadata.  
- Review `ParentImage` and `CommandLine` (scripted invocations often use `-s:<file>` for batch commands; `-n` disables auto‑login).  
- Note working directory and any referenced **script files**.

#### 2) Protocol & Ports
- Identify the **control connection** (TCP/21) and any **data connections**:  
  - **Active**: Server → client ephemeral from TCP/20 (may be blocked by host firewalls).  
  - **Passive**: Client → server high port (e.g., 1024–65535). Expect multiple short‑lived connections per transfer.  
- Check for **FTPS** (implicit 990 or explicit AUTH TLS on 21); if seen, TLS inspection may be required at the proxy.

#### 3) Artifact Discovery
- Search for **file creations** (EID 11) around the connection window (downloads land in current directory unless `lcd` is set).  
- Look for **FTP script files** (commonly `.txt`) containing credentials (`user`, `pass` lines).  
- Hash and analyze any retrieved files (type/entropy/header mismatch).

#### 4) Correlation & Follow‑On
- Inspect for subsequent **execution** of downloaded artifacts (e.g., `powershell.exe`, `rundll32.exe`, `mshta.exe`).  
- Run **fleet prevalence** on destination hosts and file hashes; pivot on **credential reuse**.

### Key Artifacts
- **Sysmon EID 3:** Connections from `ftp.exe` to TCP/21 and passive data ports (or server→client in active mode).  
- **Sysmon EID 1 / Security 4688:** Launch context, command line (`-s:`, `-n`, `-A` for anonymous).  
- **Sysmon EID 11:** File creations (downloaded payloads) and any script files.  
- **Sysmon EID 22:** DNS queries for the FTP host (or proxy FQDN in explicit‑proxy environments).  
- **Proxy/Firewall logs:** FTP control transcripts (USER/PASS, RETR/STOR), PASV/PORT negotiations when logged.

### Containment Actions
- **Quarantine** downloaded payloads; **block** the FTP host/IP at perimeter; disable further connections.  
- **Terminate** active `ftp.exe` sessions; consider **host isolation** if execution occurred.

### Prevention Measures
- Default‑deny **FTP egress**; prefer secure managed transfer tools.  
- Apply **AppLocker/WDAC** to restrict `ftp.exe` usage to admin hosts only.  
- Monitor for `ftp.exe` creating **new executables/scripts** in **user‑writable** paths.

### Recovery
- Remove staged content and any persistence; rotate credentials exposed in FTP scripts; update allowlists/tuning.

### False Positives
- Rare **legacy workflows** or **network equipment** maintenance pulling firmware/configs via FTP from internal servers. Validate by ticket/owner.

---

## Playbook 2 — FTP.exe Process Execution (Process Creation)

### Overview
This playbook addresses alerts where **`ftp.exe`** is **launched** (Sysmon **EID 1** / Security **4688**). Scripted misuse often looks like:
`ftp.exe -s:C:\\path\\script.txt -n` with a script containing commands (`open host`, `user <u>`, `pass <p>`, `binary`, `get <file>`, `bye`).  
Adversaries seed scripts in **Temp/Public** and execute them to quietly download payloads (**T1105**).

### Initial Response
1. **Preserve context:** Export process creation including `Image`, full `CommandLine`, `ParentImage`, `User`, integrity level, timestamp.  
2. **Collect script/artifacts:** If `-s:<file>` present, immediately **acquire** the script and any **output files** created.  
3. **Baseline check:** Determine whether the user/device has a legitimate need for FTP. Most should not.

### Investigation Steps
#### 1) Command‑Line Semantics
- Flags of interest:  
  - `-s:<file>` — run commands from file (often includes credentials).  
  - `-n` — no auto‑login (script will provide creds).  
  - `-A` — anonymous login.  
- Parse script content: common steps are `open`, `user`, `pass`, `lcd`, `binary`, `hash`, `prompt`, `cd`, `get`/`mget`, `put`/`mput`, `bye`.  
- Identify **destination host**, **credentials**, and **downloaded file names**.

#### 2) File & Path Analysis
- Locate downloaded files in **working directory** or after `lcd` change; hash and analyze (type/entropy/signing).  
- Check for **execution** shortly after download or for persistence writes (Startup/Run keys, scheduled tasks).

#### 3) Network & DNS Corroboration
- Correlate with **EID 3** for TCP/21 and passive data ports; gather **proxy/firewall** logs for FTP commands if available.  
- Review **DNS (EID 22)** for host lookups aligned with the process start.

#### 4) Follow‑On & Lateral Context
- Pivot to subsequent processes executing the downloaded payload.  
- Run **fleet prevalence** for the script filename/path and downloaded file hashes; look for reuse under multiple users/hosts.

### Key Artifacts
- **Sysmon EID 1 / 4688:** `ftp.exe` launch details and script path; parent lineage (e.g., script host or Office).  
- **Script file content:** Credentials and command sequence.  
- **Sysmon EID 11:** Downloaded artifact writes and script file creation/modification.  
- **Sysmon EID 3 / 22:** Network and DNS corroboration.

### Containment Actions
- **Quarantine** scripts and payloads; **disable** or **blocklist** the FTP destination; **terminate** sessions.  
- Consider **host isolation** if payload execution/persistence is confirmed.

### Prevention Measures
- Block **FTP** at egress; enforce secure alternatives (SFTP/HTTPS) with auditing.  
- Use **application control** to restrict `ftp.exe`; monitor for `-s:` usage and for script files in **Temp/Public**.  
- Alert on `ftp.exe` parentage from **Office**, **browsers**, or **script engines**.

### Recovery
- Remove artifacts and persistence; rotate any credentials found in scripts; tune detections and allowlists.

### False Positives
- Approved internal automation using `ftp.exe` to fetch updates/configs from **internal** servers during maintenance windows.  
- Mitigate by allowlisting **known internal FTP servers** and validating change records.