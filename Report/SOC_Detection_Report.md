# SOC Home Lab — Security Detection Report

**Analyst:** Home Lab  
**Date:** March 2026  
**Incidents:** 8 documented  
**Environment:** Kali → Windows 10 Pro / Windows Server 2016 → Splunk on CentOS  
**Framework:** MITRE ATT&CK  
**Tools:** Splunk, Sysmon, Impacket, Hydra, Netcat, Mimikatz, Nmap  

---

## Executive Summary

This report documents 8 simulated attack scenarios executed in an isolated home lab environment. Each incident covers the attack technique, detection method, SPL query, key IOCs, MITRE ATT&CK mapping, Incident Response procedure from a Tier 1 SOC analyst perspective, and Root Cause Analysis with remediation recommendations.

The attack chain progresses from initial reconnaissance through credential access, execution, persistence, lateral movement, and Active Directory attacks — mirroring a realistic threat actor kill chain. All detections are based on observable log artifacts. Defenders alert on access attempts and suspicious behaviour, not confirmed damage.

---

## Network Topology

| Machine | Role | NAT IP | Host-Only IP |
|---|---|---|---|
| Kali Linux | Attacker | 192.168.15.129 | 192.168.67.24 |
| Windows 10 Pro | Victim (domain-joined) | — | 192.168.67.23 |
| Windows Server 2016 | Domain Controller | — | 192.168.67.22 |
| CentOS | Splunk SIEM | 192.168.15.131 | 192.168.67.11 |

---

## Incidents Overview

| # | Incident | Severity | Key Event ID | MITRE Tactic |
|---|---|---|---|---|
| 01 | Port Scan / Recon | MEDIUM | Sysmon EID 3 | TA0043 Reconnaissance |
| 02 | Brute Force — Linux SSH | HIGH | linux_secure | TA0006 Credential Access |
| 03 | Brute Force — Windows SSH | HIGH | EID 4625 | TA0006 Credential Access |
| 04 | Reverse Shell | CRITICAL | Sysmon EID 1, 3 | TA0002 Execution |
| 05 | Persistence — Scheduled Task | HIGH | EID 4698 | TA0003 Persistence |
| 06 | Credential Dumping — LSASS | CRITICAL | Sysmon EID 1 | TA0006 Credential Access |
| 07 | Lateral Movement — PsExec | CRITICAL | EID 7045, 4624, Sysmon 1 | TA0008 Lateral Movement |
| 08 | Kerberoasting | HIGH | EID 4769 | TA0006 Credential Access |

---

## Incident 01 — Port Scan / Recon

**Severity:** MEDIUM  
**Attack Tool:** Nmap (-sS -A)  
**Source:** 192.168.15.129 (Kali)  
**Target:** 192.168.15.130 (Windows)  

### Detection

Sysmon Event ID 3 detected a single source IP hitting more than 5 unique destination ports within a one-minute window. Threshold set above the observed legitimate traffic baseline to minimise false positives. In production this threshold would be baselined over 1–2 weeks before enforcement.

### SPL Query

```spl
index=main EventCode=3
| bucket _time span=1m
| stats dc(DestinationPort) as unique_ports by _time, SourceIp, DestinationIp
| where unique_ports > 5
| sort -unique_ports
```

### Indicators of Compromise

- Single IP hitting 20+ ports within seconds
- Parallel connection attempts — Nmap signature behaviour
- Ports 22, 135, 139, 445 probed simultaneously
- No scheduled scan or change ticket for the source IP
- Activity occurred outside business hours

### MITRE ATT&CK

`TA0043 Reconnaissance` | `T1046 Network Service Discovery`

> **Note:** Threshold of 5 suits this lab. In production, baseline legitimate scanner traffic (Nessus, Qualys) and set the threshold just above the observed maximum to reduce false positives.

### Incident Response — Tier 1 SOC Analyst

| Step | Action |
|---|---|
| 1. Alert Review | Confirm EID 3 shows dc(DestinationPort) > 5 within a 1-minute bucket. Note source IP, destination IP, and exact timestamp. |
| 2. Source IP Check | Is the source IP internal or external? Cross-reference the IT scanner list and change ticket system. Is there an active ticket for a scheduled scan? |
| 3. TP/FP Decision | **TP:** External or unrecognised IP, no change ticket, off-hours, 20+ ports in seconds. **FP:** Known IT scanner with a valid change ticket during business hours. Document reasoning. |
| 4. Pivot Search | Search the same source IP across all other event IDs in the same window. Look for follow-on EID 4625 (brute force) or Sysmon EID 1 (execution) — recon always precedes exploitation. |
| 5. Document | Record: source IP, destination, port list, timestamp, TP/FP decision and rationale. Attach Splunk export to the ticket. |
| 6. Escalate to T2 | If confirmed TP: escalate with source IP, targeted ports, timestamp, and any follow-on activity observed. |

### Root Cause Analysis

| | |
|---|---|
| **Root Cause** | Ports 22, 135, 139, and 445 reachable from the attacker subnet with no network-level controls blocking reconnaissance. |
| **Vulnerability** | No firewall rules or VLAN segmentation preventing external hosts from reaching internal services. Unnecessary ports exposed. |
| **Contributing Factor** | Alert threshold not tuned to the environment — unintuned thresholds generate noise or miss low-and-slow scans. |
| **Remediation** | 1. Firewall: block unsolicited inbound connections from untrusted subnets. 2. VLAN segmentation between attacker-accessible and internal networks. 3. Disable SSH (22) on Windows if not required. 4. Restrict NetBIOS ports to trusted internal ranges. 5. Tune Splunk threshold after baselining legitimate traffic. |
| **Lessons Learned** | Detecting recon early is the highest-value intervention — every subsequent attack in this chain depended on information gathered at this stage. |

---

## Incident 02 — Brute Force — Linux SSH

**Severity:** HIGH  
**Attack Tool:** Hydra  
**Source:** 192.168.15.129 (Kali)  
**Target:** 192.168.15.131 (CentOS / Splunk)  

### Detection

Linux auth logs (linux_secure sourcetype) — failed password entries extracted via regex, counted per source IP and target username. Any IP exceeding 5 failures is flagged. Non-existent usernames indicate wordlist-based enumeration — an attacker cycling through a dictionary who does not know valid account names.

### SPL Query

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "for (?P<target_user>\w+) from"
| stats count by src_ip, target_user
| where count > 5
| sort -count
```

### Indicators of Compromise

- High volume of failed SSH auth from single IP in short window
- Non-existent usernames — attacker cycling wordlist (user enumeration)
- Rapid sequential attempts consistent with automated tooling (Hydra)
- Multiple target usernames attempted from same source IP
- Check for `Accepted password` from same IP — confirms brute force succeeded

### MITRE ATT&CK

`TA0006 Credential Access` | `T1110 Brute Force` | `T1110.001 Password Guessing`

### Incident Response — Tier 1 SOC Analyst

| Step | Action |
|---|---|
| 1. Alert Review | Confirm failed password spike in linux_secure. Note: source IP, target usernames, failure count, timeframe. Are the targeted usernames real accounts or non-existent? |
| 2. Source IP Check | Internal or external? Known admin machine? Any matching change ticket? |
| 3. Check for Success | **CRITICAL:** Search for `Accepted password` from the same source IP. If found, severity escalates immediately — document and flag. |
| 4. TP/FP Decision | **TP:** External IP, non-existent usernames, rapid sequential failures, no change ticket. **FP:** Internal admin IP with a few failures during a maintenance window. |
| 5. Document | Record: source IP, targeted usernames, failure count, timestamps, and whether a successful login followed. Attach Splunk export. |
| 6. Escalate to T2 | Escalate with all findings. If a successful login was found, flag this explicitly — T2 response differs significantly. |

### Root Cause Analysis

| | |
|---|---|
| **Root Cause** | SSH exposed to the attacker machine with password-based authentication enabled and no brute force protection in place. |
| **Vulnerability** | No account lockout or rate limiting after failed attempts. No fail2ban deployed. Password authentication accepted over SSH. |
| **Contributing Factor** | No firewall rules restricting which source IPs can reach SSH on this machine. |
| **Remediation** | 1. Disable password-based SSH — enforce key-based only (`PasswordAuthentication no` in sshd_config). 2. Deploy fail2ban: auto-block after 5 failures. 3. Firewall: restrict SSH to known admin IPs. 4. Disable root SSH login. |
| **Lessons Learned** | Password-based SSH on an internet-facing machine is a critical misconfiguration. Key-based auth eliminates this attack vector entirely. |

---

## Incident 03 — Brute Force — Windows SSH

**Severity:** HIGH  
**Attack Tool:** Hydra  
**Source:** 192.168.15.129 (Kali)  
**Target:** 192.168.15.130 (Windows)  

### Detection

Windows Event ID 4625 (Failed Logon) — multiple failures against the same account. Detection pivots to Account_Name count because Source_Network_Address is blank when SSH is the attack vector — a known Windows logging limitation. Logon Types 3, 8, and 9 indicate non-interactive, network-based authentication typical of remote brute force.

### SPL Query

```spl
index=main EventCode=4625 Caller_Process_Name="*sshd*"
| stats count by Account_Name, Logon_Type, Caller_Process_Name
| where count > 5
| sort -count
```

### Indicators of Compromise

- 5+ failed logons against same account in short window
- Logon Types 3, 8, or 9 — non-interactive, network-based
- Failures followed by a successful logon (EID 4624) from same account
- Activity outside business hours with no change ticket
- Source_Network_Address blank — SSH vector does not populate this field on Windows

### MITRE ATT&CK

`TA0006 Credential Access` | `T1110 Brute Force` | `T1110.001 Password Guessing`

> **Note:** Source IP is blank for SSH-based 4625 events on Windows. To recover the attacker IP, correlate 4625 timestamps with Sysmon EID 3 (inbound network connection) at the same timeframe.

### Incident Response — Tier 1 SOC Analyst

| Step | Action |
|---|---|
| 1. Alert Review | Confirm EID 4625 spike. Note: targeted account name, logon type, failure count, timeframe. Blank Source_Network_Address is expected for SSH attacks — not a data gap. |
| 2. Recover Source IP | Cross-reference the 4625 timestamps against Sysmon EID 3 (network connections) in the same window to identify the attacker IP. |
| 3. Check for Success | **CRITICAL:** Search EID 4624 for the same Account_Name immediately after the failure spike. A successful logon following mass failures is a confirmed breach. |
| 4. TP/FP Decision | **TP:** Rapid failures against one account, Logon Types 3/8/9, off-hours, no change ticket. **FP:** User locked out after a password change with a change ticket. |
| 5. Document | Record: targeted account, logon types, failure count, timestamps, recovered source IP, and whether EID 4624 was observed. |
| 6. Escalate to T2 | Escalate with account name, failure count, logon types, recovered source IP, and whether a successful logon was observed. |

### Root Cause Analysis

| | |
|---|---|
| **Root Cause** | Windows OpenSSH exposed with password authentication enabled and no account lockout policy configured. |
| **Vulnerability** | No account lockout policy — unlimited password attempts permitted. Password-based SSH accepted. |
| **Logging Gap** | Windows does not populate Source_Network_Address in EID 4625 for SSH attacks — known platform limitation. Compensate by correlating with Sysmon EID 3. |
| **Remediation** | 1. Configure account lockout: 5 failures triggers 30-minute lockout (Group Policy > Account Lockout Policy). 2. Disable password-based SSH — enforce key authentication. 3. Restrict inbound SSH to known admin IPs via Windows Firewall. |
| **Lessons Learned** | Knowing to pivot to Sysmon EID 3 to recover the blank source IP demonstrates detection engineering depth beyond running the default query. |

---

## Incident 04 — Reverse Shell

**Severity:** CRITICAL  
**Attack Tool:** Netcat + PowerShell TCP socket  
**Source:** 192.168.15.129 (Kali) — listener port 4444  
**Target:** 192.168.15.130 (Windows)  

### Detection

Sysmon EID 1 detected PowerShell launched with `-ExecutionPolicy Bypass` from cmd.exe. Sysmon EID 3 detected powershell.exe establishing outbound TCP to non-standard port 4444. Legitimate software does not need to bypass execution policy at runtime. cmd.exe spawning powershell.exe with bypass flags is a textbook attacker pattern.

### SPL Query

```spl
# Outbound connection to non-standard port
index=main EventCode=3 Image="*powershell*"
| where DestinationPort != 80 AND DestinationPort != 443
| table _time, User, Image, DestinationIp, DestinationPort
| sort _time

# ExecutionPolicy Bypass in command line
index=main EventCode=1 Image="*powershell*" CommandLine="*ExecutionPolicy*Bypass*"
| table _time, User, Image, CommandLine, ParentImage
| sort _time
```

### Indicators of Compromise

- powershell.exe initiating outbound TCP to external IP
- Non-standard destination port (4444) — not HTTP/HTTPS
- `-ExecutionPolicy Bypass` present in command line
- Script executed from Desktop or Temp path
- cmd.exe as parent process of powershell.exe
- Outbound connection established immediately after script execution

### MITRE ATT&CK

`TA0002 Execution` | `TA0011 Command & Control` | `T1059.001 PowerShell` | `T1571 Non-Standard Port`

> **Note:** Port-based detection misses reverse shells on port 443. Improvement: flag powershell.exe making any outbound connection regardless of port, combined with destination IP reputation and beaconing pattern analysis.

### Incident Response — Tier 1 SOC Analyst

| Step | Action |
|---|---|
| 1. Alert Review | Confirm EID 1 (PowerShell with Bypass) and EID 3 (outbound non-standard port). Verify correlation by User and timestamp — both events should be seconds apart from the same user. |
| 2. Assess Legitimacy | Is there a scheduled task, admin script, or vendor tool that explains this? Legitimate admin scripts are signed and do not require Bypass at runtime. |
| 3. TP/FP Decision | **TP:** powershell.exe connecting outbound on a non-standard port with -ExecutionPolicy Bypass, no change ticket, unexpected user. Almost always a true positive. |
| 4. Record C2 Details | Note the destination IP and port from EID 3 — this is the attacker's C2 address. Critical for T2 and threat intel enrichment. |
| 5. Document | Record: compromised user, C2 IP and port, timestamp, command line from EID 1, parent process. Open a P1 ticket. |
| 6. Escalate to T2 | Escalate immediately as CRITICAL. Include: C2 IP, destination port, compromised user, command line, and timestamp. T2 handles containment and forensic investigation. |

### Root Cause Analysis

| | |
|---|---|
| **Root Cause** | PowerShell execution policy bypassable with a runtime flag. No application whitelisting in place. Attacker had prior code execution capability on the machine. |
| **Vulnerability** | No AppLocker or WDAC policy enforcing Constrained Language Mode. Outbound firewall allowed TCP to arbitrary external IPs on port 4444. |
| **Contributing Factor** | No egress filtering — outbound connections to non-business IPs and ports were permitted without inspection. |
| **Remediation** | 1. Enable PowerShell Constrained Language Mode via AppLocker or WDAC. 2. Set execution policy to AllSigned via Group Policy. 3. Egress firewall: workstations connect outbound only through a proxy — direct TCP to arbitrary ports blocked. 4. Deploy PowerShell Script Block Logging (EID 4104). 5. Enable AMSI for malicious PowerShell detection. |
| **Lessons Learned** | A reverse shell gives the attacker an interactive session with the victim's privileges. Every subsequent incident (5, 6, 7) was possible because this shell was not detected and contained in time. |

---

## Incident 05 — Persistence — Scheduled Task

**Severity:** HIGH  
**Attack Tool:** schtasks.exe via reverse shell  
**Source:** 192.168.15.129 (Kali) — via established reverse shell  
**Target:** 192.168.15.130 (Windows)  

### Detection

Windows Event ID 4698 — scheduled task created with suspicious keywords in the TaskContent field: ExecutionPolicy, Bypass, shell, temp. Legitimate tasks from trusted software do not embed these strings. Task created under SYSTEM, triggers on logon, and executes a PowerShell payload — ensuring the reverse shell reconnects on every reboot.

### SPL Query

```spl
index=main EventCode=4698
| search TaskContent="*ExecutionPolicy*" OR TaskContent="*ByPass*"
       OR TaskContent="*shell*" OR TaskContent="*temp*"
| table _time, Account_Name, Task_Name, TaskContent
| sort _time
```

### Indicators of Compromise

- Task named after a legitimate Windows process (masquerading)
- LogonTrigger — task survives reboots and reconnects automatically
- ExecutionPolicy Bypass embedded in task payload
- Task created and running as SYSTEM account
- Created outside business hours with no change ticket
- Task payload points to script in Temp or Desktop path

### MITRE ATT&CK

`TA0003 Persistence` | `T1053.005 Scheduled Task / Job`

### Incident Response — Tier 1 SOC Analyst

| Step | Action |
|---|---|
| 1. Alert Review | Confirm EID 4698. Review: Task_Name (impersonating a legitimate process?), Account_Name (SYSTEM is immediately suspicious), TaskContent keywords (Bypass, shell, temp). |
| 2. Assess Legitimacy | Is there a change ticket for task creation at this time? Legitimate tasks from trusted software are signed and do not use Bypass in their payload. |
| 3. TP/FP Decision | **TP:** SYSTEM-created task, Bypass/shell keywords, off-hours, no change ticket, masquerading name. **FP:** Software installer creating a legitimate update task — verify vendor and change ticket. |
| 4. Check Active Execution | Is the task already running? Check EID 3 for outbound powershell.exe connections at the same timestamp — the payload may already be calling back. |
| 5. Document | Record: task name, creation time, Account_Name, TaskContent, trigger type, and any correlated C2 activity. |
| 6. Escalate to T2 | Escalate with task details and any observed C2 activity. T2 will determine whether an active session exists and handle removal and investigation. |

### Root Cause Analysis

| | |
|---|---|
| **Root Cause** | Attacker had SYSTEM-level access (via reverse shell in Incident 4) with no policy restricting creation of tasks with malicious payloads. |
| **Vulnerability** | No AppLocker/WDAC policy blocking script execution from user-writable paths. No real-time EID 4698 alerting existed before this rule was created. |
| **Contributing Factor** | Persistence was only possible because the reverse shell (Incident 4) was not contained. Incident 5 is a direct consequence of Incident 4. |
| **Remediation** | 1. AppLocker/WDAC: block script execution from Temp, Desktop, and user-writable paths. 2. Group Policy: restrict schtasks.exe for non-admin users. 3. Real-time EID 4698 alert — any task with Bypass or shell keywords fires immediately. 4. Audit all existing scheduled tasks regularly. |
| **Lessons Learned** | Persistence is established within minutes of initial access. Detect Incident 4 quickly and Incident 5 never occurs. |

---

## Incident 06 — Credential Dumping — LSASS

**Severity:** CRITICAL  
**Attack Tool:** comsvcs.dll MiniDump + Mimikatz  
**Source:** 192.168.15.130 (Windows) — local attack via established session  
**Target:** 192.168.15.130 (Windows) — LSASS process targeted  

### Detection

Sysmon EID 1 detected Mimikatz executed with sekurlsa arguments. Sysmon EID 1 also detected rundll32.exe invoking comsvcs.dll MiniDump targeting the LSASS PID. LSASS (Local Security Authority Subsystem Service) holds NTLM hashes, Kerberos tickets, and sometimes plaintext credentials in memory. Extracting these enables pass-the-hash and lateral movement without requiring the plaintext password.

### SPL Query

```spl
# Mimikatz binary execution
index=main EventCode=1 Image="*mimikatz*"
| table _time, User, Image, CommandLine | sort _time

# comsvcs.dll MiniDump targeting LSASS
index=main EventCode=1 Image="*rundll32*" CommandLine="*comsvcs*"
| table _time, User, Image, CommandLine | sort _time
```

### Indicators of Compromise

- mimikatz.exe executed with sekurlsa arguments
- rundll32.exe invoking comsvcs.dll MiniDump targeting LSASS PID
- Dump file written to `C:\Users\Public\lsass.dmp`
- All activity under interactive admin session
- LSASS access attempt is a critical finding regardless of extraction success
- Follow up: EID 4624 Logon Type 3 on other machines — may indicate stolen credentials in use

### MITRE ATT&CK

`TA0006 Credential Access` | `T1003.001 OS Credential Dumping: LSASS Memory`

> **Note:** Extraction failed due to Windows 11 24H2 LSASS Protected Process Light (PPL). Detection is based on the attempt — the attempt alone confirms SYSTEM-level access, a critical finding regardless of whether extraction succeeded.

### Incident Response — Tier 1 SOC Analyst

| Step | Action |
|---|---|
| 1. Alert Review | Confirm EID 1 with mimikatz in Image, or rundll32 with comsvcs in CommandLine. When mimikatz.exe is executing on disk this is an automatic CRITICAL — no TP/FP debate. |
| 2. Check Dump File | Note whether a dump file path appears in the CommandLine. If it exists, treat credentials as potentially extracted until confirmed otherwise. |
| 3. Pivot to Lateral Move | Search EID 4624 Logon Type 3 across all other machines filtering for the compromised account or machine IP as source. If stolen hashes are in use, it will appear here. |
| 4. Document | Record: compromised user, command line, dump file path if present, whether PPL was active, and any Logon Type 3 events on other machines. Open a P1 ticket. |
| 5. Escalate to T2 | Escalate as CRITICAL immediately. Include: whether dump file exists, active accounts on the machine, and any lateral movement observed. T2 handles isolation and credential resets. |

### Root Cause Analysis

| | |
|---|---|
| **Root Cause** | Attacker had SYSTEM-level access (consequence of Incidents 4 and 5 not being contained). With SYSTEM privileges, LSASS can be targeted directly. |
| **Vulnerability** | LSASS PPL not enabled — default only on Windows 11 24H2+. No Credential Guard deployed. Mimikatz placed on disk without AV detection. |
| **Contributing Factor** | No EDR monitoring LSASS handle access. Credential Guard was not deployed. |
| **Remediation** | 1. Enable Credential Guard via Group Policy — renders LSASS dumps useless even with SYSTEM access. 2. Enable LSASS PPL: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa > RunAsPPL = 1`. 3. EDR: alert on any process opening a handle to LSASS. 4. Block known credential dumping tools at AV/EDR layer. |
| **Lessons Learned** | Once NTLM hashes are obtained the attacker moves laterally using Pass-the-Hash without ever knowing plaintext passwords. Incident 7 is a direct consequence of Incident 6 not being stopped. |

---

## Incident 07 — Lateral Movement — PsExec

**Severity:** CRITICAL  
**Attack Tool:** Impacket PsExec  
**Source:** 192.168.15.129 (Kali)  
**Target:** 192.168.15.130 (Windows)  

### Detection

Impacket PsExec copies a randomly named binary to `C:\Windows\` over SMB (Admin$ share), creates a temporary Windows service as NT AUTHORITY\SYSTEM to execute it, then deletes the service immediately. Legitimate Sysinternals PsExec always drops `PSEXESVC.exe` — Impacket drops a randomly named binary. This is the primary detection differentiator. Three correlated events confirm the attack: EID 7045, Sysmon EID 1, and EID 4624 Logon Type 3.

### SPL Query

```spl
# Random binary spawned by services.exe as SYSTEM
index=main EventCode=1 ParentImage="*services.exe*" Image="C:\\Windows\\*.exe"
| where NOT match(Image, "(?i)(svchost|sppsvc|TrustedInstaller|msiexec)")
| table _time, User, Image, CommandLine, ParentImage | sort _time

# New service created / deleted rapidly
index=main EventCode=7045
| table _time, ServiceName, ServiceFileName | sort _time

# Logon Type 3 — correlate timestamps
index=main EventCode=4624 Logon_Type=3
| table _time, Account_Name, Logon_Type, IpAddress | sort _time
```

### Indicators of Compromise

- Randomly named executable in `C:\Windows\` — legitimate PsExec uses `PSEXESVC.exe`
- Binary spawned directly by services.exe as NT AUTHORITY\SYSTEM
- Service created and deleted within seconds — Impacket cleanup behaviour
- Logon Type 3 from external IP at same timestamp as service creation
- Source IP not belonging to known IT team machines, no change ticket

### MITRE ATT&CK

`TA0008 Lateral Movement` | `T1021.002 SMB/Admin Shares` | `T1543.003 Windows Service`

### Incident Response — Tier 1 SOC Analyst

| Step | Action |
|---|---|
| 1. Alert Review | Correlate all three events by timestamp: EID 7045, Sysmon EID 1 (binary from services.exe), EID 4624 Logon Type 3. All three in the same minute window confirms Impacket PsExec. |
| 2. Binary Name Check | Check the Image field in Sysmon EID 1 — `PSEXESVC.exe` indicates legitimate use. A random string (e.g. xvtqrs.exe) confirms Impacket. This is the key differentiator. |
| 3. Identify Account | Which account was used for Logon Type 3? Cross-reference with any previously compromised accounts. Flag it as fully compromised. |
| 4. TP/FP Decision | **TP:** Random binary name, external source IP, no change ticket. **FP:** IT team using legitimate PsExec — PSEXESVC.exe present, valid change ticket, known IT IP. |
| 5. Scope Assessment | Search for the same Logon Type 3 pattern on ALL other machines. Map every machine the attacker may have reached. |
| 6. Document | Record: binary name, source IP, account used, timestamp, service name from EID 7045, all other machines showing Logon Type 3 from the same source. |
| 7. Escalate to T2 | Escalate as CRITICAL with: attacker IP, account used, binary name, all machines showing Logon Type 3 from attacker IP. |

### Root Cause Analysis

| | |
|---|---|
| **Root Cause** | Attacker obtained NTLM hashes via LSASS dump (Incident 6) and used Pass-the-Hash over SMB. Admin$ share accessible from the attacker machine. |
| **Vulnerability** | Admin$ SMB share reachable from non-domain machines. No SMB signing enforced. Compromised account had local admin rights on the target. |
| **Contributing Factor** | Credential dump in Incident 6 was not contained. Once hashes are exfiltrated, lateral movement follows within minutes. |
| **Remediation** | 1. Disable Admin$ on workstations via Group Policy. 2. Enforce SMB signing. 3. Tiered admin model: admin accounts should not have local admin rights across all workstations. 4. Deploy Credential Guard to prevent pass-the-hash. 5. Network segmentation: workstations should not SMB directly to each other. |
| **Lessons Learned** | The PsExec service creates and deletes itself in seconds. Without real-time correlation of EID 7045 + Sysmon EID 1 + EID 4624, this passes completely unnoticed. |

---

## Incident 08 — Kerberoasting

**Severity:** HIGH  
**Attack Tool:** Impacket GetUserSPNs  
**Source:** 192.168.67.24 (Kali)  
**Target:** 192.168.67.22 (DC — WIN-N15VPE2DLF9.myhomelab.local)  

### Detection

Any domain user can request a Kerberos service ticket for any SPN-registered account — this is by design in Active Directory. The attacker forces RC4 encryption (0x17) instead of AES (0x12) to obtain a hash crackable offline with hashcat. Event ID 4769 with `Ticket_Encryption_Type=0x17` is the detection trigger.

**SPN targeted:** `MSSQLSvc/WIN-N15VPE2DLF9.myhomelab.local:1433` (service account: sqlsvc)

### SPL Query

```spl
index=main EventCode=4769 Ticket_Encryption_Type=0x17
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
| sort -_time
```

### Indicators of Compromise

- EID 4769 with `Ticket_Encryption_Type=0x17` (RC4) — modern AD uses AES (0x12)
- Requesting account: Lisa@MYHOMELAB.LOCAL (low-privilege domain user)
- Targeted service: sqlsvc (LastLogon: never — unmonitored service account)
- Client_Address: `::ffff:192.168.67.24` (Kali — non-domain machine)
- Failure_Code: 0x0 — ticket issued successfully, hash retrievable offline
- SPN publicly enumerable by any domain user — no special permissions required

### MITRE ATT&CK

`TA0006 Credential Access` | `T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting`

> **Note:** Hash cracking via rockyou.txt was unsuccessful (admin@123 not in wordlist). Alert on ANY EID 4769 with 0x17 regardless of cracking outcome — the RC4 request is the attack, not the offline crack.

### Incident Response — Tier 1 SOC Analyst

| Step | Action |
|---|---|
| 1. Alert Review | Confirm EID 4769 with Ticket_Encryption_Type=0x17. Note: requesting account (Lisa), targeted service (sqlsvc), Client_Address (Kali IP), Failure_Code (0x0 = ticket issued). |
| 2. RC4 Significance | Modern AD uses AES (0x12). RC4 (0x17) is only requested when an attacker forces a downgrade to get a crackable hash. No legitimate modern application requests RC4. |
| 3. Scope Check | How many SPNs were requested? One = targeted attack. Multiple in rapid succession = full sweep of all service accounts. Run the query without the encryption filter to check. |
| 4. Check Lisa's Account | Lisa's credentials were used. Is her account showing other unusual activity? Flag Lisa's account alongside the service account. |
| 5. TP/FP Decision | Almost always TP. Only exception: legacy systems (pre-Windows Server 2008) that legitimately use RC4 — verify whether any exist before closing as FP. |
| 6. Document | Record: requesting account, targeted service, Client_Address, timestamp, number of SPNs requested, Failure_Code. |
| 7. Escalate to T2 | Escalate with full details. T2 will reset sqlsvc password immediately, audit all SPNs, and investigate Lisa's account for signs of compromise. |

### Root Cause Analysis

| | |
|---|---|
| **Root Cause** | Service account sqlsvc registered with an SPN and configured with a weak password. RC4 encryption not disabled on the domain. |
| **Vulnerability** | sqlsvc password was weak and offline-crackable. RC4 not disabled — modern environments should enforce AES-only. sqlsvc had no login activity (LastLogon: never) making it an unmonitored target. |
| **Contributing Factor** | sqlsvc over-privileged relative to its function. No alerting on EID 4769 with RC4 before this rule was created. |
| **Remediation** | 1. Use Group Managed Service Accounts (gMSA) — Windows auto-rotates the password every 30 days, rendering Kerberoasting useless. 2. Service account passwords: minimum 25 characters, randomly generated. 3. Enforce AES-only: set `msDS-SupportedEncryptionTypes = 24` on all service accounts. 4. Audit all SPNs and remove those registered on high-privilege accounts. 5. Alert on all EID 4769 with 0x17. |
| **Lessons Learned** | Kerberoasting is silent from the DC — it looks like a normal ticket request. The only detection signal is the RC4 downgrade. gMSA adoption eliminates this attack vector entirely. |

---

## Detection & IR Summary

| # | Incident | Severity | Key Event ID | T1 Action | RCA Fix |
|---|---|---|---|---|---|
| 01 | Port Scan | MEDIUM | Sysmon EID 3 | Pivot to follow-on events, escalate if TP | Firewall + Segmentation |
| 02 | Brute Force Linux | HIGH | linux_secure | Check for success, escalate with findings | fail2ban + Key Auth only |
| 03 | Brute Force Windows | HIGH | EID 4625 | Correlate EID 3 for source IP, escalate | Account Lockout GPO |
| 04 | Reverse Shell | CRITICAL | Sysmon EID 1, 3 | Record C2 IP, escalate as P1 immediately | AppLocker + Egress FW |
| 05 | Persistence Task | HIGH | EID 4698 | Check active C2, escalate with task detail | AppLocker + Least Priv |
| 06 | Cred Dump LSASS | CRITICAL | Sysmon EID 1 | Pivot to Logon Type 3, escalate as P1 | Credential Guard + PPL |
| 07 | Lateral Move PsExec | CRITICAL | EID 7045, 4624 | Check binary name, scope all machines | SMB Signing + Tiered Admin |
| 08 | Kerberoasting | HIGH | EID 4769 | Check SPN scope, flag Lisa, escalate | gMSA + AES-Only |
