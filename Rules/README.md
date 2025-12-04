# Detection Rules (Wazuh + Sysmon)

This folder contains the custom detection rules I wrote for my Windows endpoint lab.  
All rules are built to detect real-world attacker behavior mapped to MITRE ATT&CK,  
and each rule was tested on a live Sysmon + Wazuh setup.

---

## 1. PowerShell Encoded Command Execution  
**File:** `powershell_execution.xml`  
**MITRE:** T1059.001 (PowerShell)  

Detects PowerShell processes executed with Base64-encoded commands, including the `-enc` alias,  
and suspicious child-process patterns (cmd → powershell).  
Catches obfuscated or hidden PowerShell payloads used in initial access or post-exploitation.

---

## 2. Account & System Discovery Correlation  
**File:** `discovery.xml`  
**MITRE:** T1087 (Account Discovery), T1033 (System Owner/User Discovery)  

Flags discovery activity using tools such as `net user`, `net1`, `systeminfo`, and `whoami`,  
and raises a higher-severity alert when multiple discovery commands occur inside the same 90-second window.  
Provides early signal on enumeration behavior performed by attackers before lateral movement.

---

## 3. RDP Session Hijacking via tscon.exe  
**File:** `lateral_movement_RDP.xml`  
**MITRE:** T1563.002 (Remote Desktop Protocol)  

Detects suspicious `tscon.exe` usage used for RDP session hijacking, including  
session redirects such as `/1 /dest:2` and `tscon /RDP-Tcp`.  
Highlights potential lateral movement or privilege escalation attempts.

---

## 4. Credential Dumping via comsvcs.dll MiniDump  
**File:** `creds_dumping.xml`  
**MITRE:** T1003.001 (LSASS Memory Dump)  

Identifies LSASS dumping through `rundll32.exe` invoking `comsvcs.dll, MiniDump`.  
A refined rule raises severity when dump files are written to suspicious locations  
(e.g., `C:\Users\Public\`, `C:\Windows\Temp\`) or when the command references LSASS directly.

---

## 5. Scheduled Task Persistence  
**File:** `scheduled_tasks_persistence.xml`  
**MITRE:** T1053.005 (Scheduled Task)  

Detects scheduled task creation via `schtasks.exe /create`.  
A second-stage rule raises severity when the scheduled task executes payloads  
from suspicious directories (`Public`, `ProgramData`, `AppData`) or script files (`.ps1`, `.bat`, `.vbs`, `.js`, `.cmd`).

---
## 6. RunKey Persistence (Registry CurrentVersion\Run)  
**File:** `runkey_persistence.xml`  
**MITRE:** T1547.001 (Registry Run Keys / Startup Folder) 

Detects persistence established via `reg.exe`. modifying the `HKCU\Software\Microsoft\Windows\CurrentVersion\Run key`.
Flags cases where the RunKey value points into suspicious user-writable locations such as `AppData (Roaming/Local)`,
indicating an attempt to launch attacker-controlled payloads on user logon.
Provides early signal on registry-based persistence techniques often used after initial foothold.

---
## Notes
- All rules were tested on a configured Windows endpoint with Sysmon EventID 1 process creation.
- Regex patterns use PCRE2 for flexibility across command-line variations.
- Rules are designed to minimize noise while catching realistic attacker behaviors across several stages of the attack lifecycle.

