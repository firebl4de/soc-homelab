# SOC Home Lab — Security Detection Report

**Environment:** Kali (Attacker) → Windows 10 Pro / Windows Server 2016 (Victims) → Splunk on CentOS (SIEM)  
**Date:** March 2026  
**Analyst:** Home Lab  
**Total Incidents:** 8

---

## Executive Summary

This report documents 8 simulated attack scenarios executed in an isolated home lab environment. Each incident covers the attack technique used, how it was detected using Splunk and event logs, the SPL detection query, key IOCs, and the MITRE ATT&CK mapping.

The attack chain progresses from initial reconnaissance through credential access, execution, persistence, lateral movement, and Active Directory attacks — mirroring a realistic threat actor kill chain.

All detections are based on observable log artifacts, not on attack success. This reflects real SOC practice: defenders alert on access attempts and suspicious behavior, not confirmed damage.

---

## Network Topology

| Machine | Role | IP |
|---|---|---|
| Kali Linux | Attacker | 192.168.15.130 / 192.168.67.24 |
| Windows 10 Pro | Victim (Domain-joined) | 192.168.67.23 |
| Windows Server 2016 | Domain Controller | 192.168.67.22 |
| CentOS | Splunk SIEM | 192.168.15.131 / 192.168.67.11 |

---

## Incident 1: Port Scan / Recon

**Attack Tool:** Nmap (`nmap -sS -A`)  
**Source:** 192.168.15.130 (Kali)  
**Target:** 192.168.15.130 (Windows)  
**Ports Found:** 22, 135, 139, 445

**Detection:** Sysmon Event ID 3 — single source IP hitting more than 5 unique destination ports within a 1-minute window.

**SPL Query:**
```spl
index=main EventCode=3
| bucket _time span=1m
| stats dc(DestinationPort) as unique_ports by _time, SourceIp, DestinationIp
| where unique_ports > 5
```

**IOCs:**
- Single IP hitting 20+ ports within seconds
- Parallel connection attempts (Nmap signature behavior)
- Ports 22, 135, 139, 445 probed simultaneously

**MITRE ATT&CK:** TA0043 Reconnaissance — T1046 Network Service Discovery

---

## Incident 2: Brute Force — Linux SSH

**Attack Tool:** Hydra  
**Source:** 192.168.15.129 (Kali)  
**Target:** 192.168.15.131 (CentOS)

**Detection:** Linux auth logs (`/var/log/secure`) — failed password entries counted per source IP. Any IP exceeding 5 failures flagged.

**SPL Query:**
```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "for (?P<target_user>\w+) from"
| stats count by src_ip, target_user
| where count > 5
| sort -count
```

**IOCs:**
- High volume of failed SSH auth from single IP
- Invalid/non-existent usernames (user enumeration)
- Rapid sequential login attempts

**MITRE ATT&CK:** TA0006 Credential Access — T1110 Brute Force, T1110.001 Password Guessing

---

## Incident 3: Brute Force — Windows SSH

**Attack Tool:** Hydra  
**Source:** 192.168.15.129 (Kali)  
**Target:** 192.168.15.130 (Windows)

**Detection:** Windows Event ID 4625 — multiple failed logon attempts against the same account.

**SPL Query:**
```spl
index=main EventCode=4625 Caller_Process_Name="*sshd*"
| stats count by Account_Name, Logon_Type, Caller_Process_Name
| where count > 5
| sort -count
```

**Logon Types Monitored:** 3 (Network), 8 (NetworkCleartext), 9 (NewCredentials), 10 (RemoteInteractive)

**IOCs:**
- 5+ failed logons from same IP in short window
- Failures immediately followed by a successful logon
- Non-interactive logon types (3, 8, 9)

**Known Limitation:** `Source_Network_Address` field is blank in Event ID 4625 when attack vector is SSH. Detection pivots to `Account_Name` count instead of source IP. This is a known Windows logging limitation — in a production environment, network-layer logging (firewall, IDS) would supplement this gap.

**MITRE ATT&CK:** TA0006 Credential Access — T1110 Brute Force, T1110.001 Password Guessing

---

## Incident 4: Reverse Shell

**Attack Tool:** Netcat listener + PowerShell TCP socket script  
**Source:** 192.168.15.129 (Kali) — listener on port 4444  
**Target:** 192.168.15.130 (Windows)

**Detection:**
- Sysmon Event ID 1 — PowerShell launched with `-ExecutionPolicy Bypass` flag from `cmd.exe`
- Sysmon Event ID 3 — `powershell.exe` establishing outbound TCP connection to non-standard port 4444

**SPL Query:**
```spl
index=main EventCode=3 Image="*powershell*"
| where DestinationPort != 80 AND DestinationPort != 443
| table _time, User, Image, DestinationIp, DestinationPort
| sort _time
```

**IOCs:**
- `powershell.exe` initiating outbound TCP connection
- Non-standard destination port (4444)
- `-ExecutionPolicy Bypass` in command line
- Script executed from Desktop path
- `cmd.exe` spawning `powershell.exe`

**Detection Limitation:** Port-based detection would miss a reverse shell using port 443 to blend with HTTPS traffic. In that case, detection shifts to process-based — flagging `powershell.exe` making any outbound connection, combined with beaconing pattern analysis and DNS reputation checks.

**MITRE ATT&CK:** TA0002 Execution — T1059.001 PowerShell | TA0011 Command and Control — T1571 Non-Standard Port

---

## Incident 5: Persistence — Scheduled Task

**Attack Tool:** `schtasks.exe` executed via reverse shell session  
**Target:** 192.168.15.130 (Windows)

**Detection:** Windows Event ID 4698 — scheduled task created with suspicious keywords in `TaskContent` field.

**SPL Query:**
```spl
index=main EventCode=4698
| search TaskContent="*ExecutionPolicy*" OR TaskContent="*ByPass*"
    OR TaskContent="*shell*" OR TaskContent="*temp*"
| table _time, Account_Name, Task_Name, TaskContent
| sort _time
```

**IOCs:**
- Task named after a legitimate Windows process (masquerading)
- `LogonTrigger` ensures persistence across reboots
- `ExecutionPolicy Bypass` in task payload
- Task runs as `SYSTEM`
- Task created outside business hours

**Incident Response Order:**
1. Snapshot the machine
2. Check active outbound connections — grab C2 IP before isolating
3. Isolate
4. Check for other persistence mechanisms
5. Delete the scheduled task
6. Root cause analysis
7. Document and escalate

**MITRE ATT&CK:** TA0003 Persistence — T1053.005 Scheduled Task/Job

---

## Incident 6: Credential Dumping — LSASS

**Attack Tool:** `comsvcs.dll MiniDump` + Mimikatz  
**Target:** 192.168.15.130 (Windows)

**Detection:**
- Sysmon Event ID 1 — Mimikatz binary execution with credential dumping arguments
- Sysmon Event ID 1 — `rundll32.exe` invoking `comsvcs.dll MiniDump` against LSASS PID

**SPL Queries:**
```spl
index=main EventCode=1 Image="*mimikatz*"
| table _time, User, Image, CommandLine
| sort _time
```
```spl
index=main EventCode=1 Image="*rundll32*" CommandLine="*comsvcs*"
| table _time, User, Image, CommandLine
| sort _time
```

**IOCs:**
- `mimikatz.exe` executed on disk with `sekurlsa` arguments
- `rundll32.exe` calling `comsvcs.dll MiniDump` targeting LSASS PID
- Dump file written to `C:\Users\Public\lsass.dmp`
- All activity under interactive admin session

**Note:** Credential extraction failed due to Windows 11 24H2 LSASS Protected Process Light (PPL) — which prevents any process, including SYSTEM, from reading LSASS memory without kernel-level access. Detection is based on the dumping attempt itself, which is the correct detection model. Defenders alert on access attempts, not successful extractions. The attempt alone confirms the attacker has elevated access.

**MITRE ATT&CK:** TA0006 Credential Access — T1003.001 LSASS Memory

---

## Incident 7: Lateral Movement — PsExec

**Attack Tool:** Impacket PsExec  
**Source:** 192.168.15.129 (Kali)  
**Target:** 192.168.15.130 (Windows)

**How PsExec Works:** Impacket PsExec copies a randomly named binary to the target over SMB (Admin$ share → `C:\Windows\`), creates a temporary Windows service to execute it as SYSTEM, then immediately deletes the service after execution. This is why a random binary appears and a service is created and deleted within seconds.

**Detection:**
- Sysmon Event ID 1 — random named binary spawned by `services.exe` as `NT AUTHORITY\SYSTEM`
- Windows Event ID 7045 — new service created (and immediately deleted)
- Windows Event ID 4624 Logon Type 3 — network logon at time of attack

**SPL Queries:**
```spl
index=main EventCode=1 ParentImage="*services.exe*" Image="C:\\Windows\\*.exe"
| where NOT match(Image, "(?i)(svchost|sppsvc|TrustedInstaller|msiexec)")
| table _time, User, Image, CommandLine, ParentImage
| sort _time
```
```spl
index=main EventCode=4624 Logon_Type=3
| table _time, Account_Name, Logon_Type, IpAddress
| sort _time
```
```spl
index=main EventCode=7045
| table _time, ServiceName, ServiceFileName
| sort _time
```

**IOCs:**
- Randomly named executable dropped in `C:\Windows\` (legitimate PsExec always drops `PSEXESVC.exe`)
- Binary spawned directly by `services.exe` as SYSTEM
- New service created and immediately deleted
- Logon Type 3 from external IP
- Activity under `NT AUTHORITY\SYSTEM`

**MITRE ATT&CK:** TA0008 Lateral Movement — T1021.002 SMB/Windows Admin Shares | T1543.003 Windows Service

---

## Incident 8: Kerberoasting

**Attack Tool:** Impacket GetUserSPNs  
**Source:** 192.168.67.24 (Kali)  
**Target:** 192.168.67.22 (Domain Controller — WIN-N15VPE2DLF9.myhomelab.local)

**How Kerberoasting Works:** Any domain user can request a Kerberos service ticket (TGS) for any account with a registered SPN. The ticket is encrypted with the service account's password hash. The attacker requests the ticket using RC4 encryption (downgrade from AES), takes the hash offline, and cracks it with a wordlist. The DC never flags the request because it is a legitimate AD operation.

**SPNs Targeted:**
```
MSSQLSvc/WIN-N15VPE2DLF9.myhomelab.local:1433  →  sqlsvc
```

**Detection:** Windows Event ID 4769 — Kerberos service ticket requested using RC4 encryption type 0x17 instead of AES. Modern AD environments use AES (0x12). An RC4 request is a forced downgrade — only attackers do this deliberately.

**SPL Query:**
```spl
index=main EventCode=4769 Ticket_Encryption_Type=0x17
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
| sort -_time
```

**Confirmed Log Fields:**
- `Account_Name`: Lisa@MYHOMELAB.LOCAL
- `Service_Name`: sqlsvc
- `Ticket_Encryption_Type`: 0x17 (RC4)
- `Client_Address`: ::ffff:192.168.67.24 (Kali)
- `Failure_Code`: 0x0 (ticket successfully issued)

**IOCs:**
- Kerberos service ticket request using RC4 (0x17) in AES-capable domain
- Domain user account requesting ticket for a service account
- Request originating from a non-Windows IP (Kali)
- TGS-REP hash returned and retrievable offline
- Service account (`sqlsvc`) never logged on interactively (LastLogon: never)

**Note:** Hash cracking was attempted using `rockyou.txt` — unsuccessful as the password (`admin@123`) was not present in the wordlist. Detection is based on the RC4 ticket request itself, not on successful password recovery. In a real environment, any Event ID 4769 with `Ticket_Encryption_Type=0x17` should be treated as a Kerberoasting attempt regardless of whether cracking succeeds.

**MITRE ATT&CK:** TA0006 Credential Access — T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting

---

## Detection Summary

| Incident | Key Event ID | Detection Logic | True Positive Indicator |
|---|---|---|---|
| Port Scan | Sysmon EID 3 | `dc(DestinationPort) > 5` in 1 min | External IP, no change ticket, off hours |
| Brute Force Linux | linux_secure | Failed password count > 5 per IP | Non-existent usernames, followed by success |
| Brute Force Windows | EID 4625 | Failed logon count > 5 per account | Logon Type 3/8/9, followed by EID 4624 |
| Reverse Shell | Sysmon EID 1, 3 | PowerShell outbound non-standard port | `-ExecutionPolicy Bypass`, cmd parent |
| Persistence | EID 4698 | Suspicious keywords in TaskContent | SYSTEM user, off hours, bypass payload |
| Credential Dumping | Sysmon EID 1 | mimikatz / comsvcs.dll in commandline | LSASS PID targeted, dump file on disk |
| Lateral Movement | EID 7045, 4624, Sysmon EID 1 | Random binary from services.exe as SYSTEM | Not PSEXESVC.exe, Logon Type 3 correlated |
| Kerberoasting | EID 4769 | `Ticket_Encryption_Type=0x17` | RC4 in AES domain, service account targeted |

---

*Report generated from hands-on home lab activity. All attacks were performed in an isolated virtual environment.*
