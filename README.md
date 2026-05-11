# SOC Home Lab

A hands-on home lab simulating a real-world attack chain from initial reconnaissance through full Active Directory compromise. Built to develop practical detection, investigation, and incident response skills using industry-standard tools.

---

## Lab Environment

| Machine | Role | OS | IP |
|---|---|---|---|
| Kali Linux | Attacker | Kali 2024 | 192.168.15.129 / 192.168.67.24 |
| Windows 10 Pro | Victim (domain-joined) | Windows 10 Pro | 192.168.67.23 |
| Windows Server 2016 | Domain Controller | Windows Server 2016 | 192.168.67.22 |
| CentOS | Splunk SIEM | CentOS 9 | 192.168.15.131 / 192.168.67.11 |

> **Note on IPs:** Windows endpoints are dual-homed. Early incidents (01–07) reference the NAT-side IP (192.168.15.130); domain-joined incidents (08–11) reference the host-only IP (192.168.67.23 / 192.168.67.22).

**Detection stack:** Splunk Enterprise + Sysmon + Windows Event Forwarding + Linux auditd + Wazuh (File Integrity Monitoring)

**Wazuh role:** File Integrity Monitoring (FIM) deployed in real-time on all Windows endpoints — monitoring the `hosts` file, Desktop, and Tools directories for file creation, modification, and deletion. During triage, FIM immediately answers *"did the attacker drop or tamper with any files?"* without manually hunting Sysmon EID 11.

---

## Attack Chain

The lab covers a full threat actor kill chain across 11 incidents:

```
Reconnaissance → Credential Access → Execution → Persistence → Credential Dumping → Lateral Movement → AD Attack → Domain Compromise → Persistent Domain Access
```

| # | Incident | Tool | Severity |
|---|---|---|---|
| 01 | Port Scan / Recon | Nmap | MEDIUM |
| 02 | Brute Force — Linux SSH | Hydra | HIGH |
| 03 | Brute Force — Windows SSH | Hydra | HIGH |
| 04 | Reverse Shell | Netcat + PowerShell | CRITICAL |
| 05 | Persistence — Scheduled Task | schtasks.exe | HIGH |
| 06 | Credential Dumping — LSASS | Mimikatz + comsvcs.dll | CRITICAL |
| 07 | Lateral Movement — PsExec | Impacket PsExec | CRITICAL |
| 08 | Kerberoasting | Impacket GetUserSPNs | HIGH |
| 09 | Pass-the-Hash | Impacket PsExec + NTLM hash | HIGH |
| 10 | DCSync | Impacket secretsdump | HIGH |
| 11 | Golden Ticket | Impacket ticketer + psexec | CRITICAL |

---

## What's Documented

Each incident includes:

- **Detection** — how the attack was identified in Splunk
- **SPL Query** — the exact search used to detect it
- **IOCs** — indicators of compromise to look for
- **MITRE ATT&CK** — tactic and technique mapping
- **Incident Response** — Tier 1 SOC analyst workflow (triage, TP/FP, escalation)
- **Root Cause Analysis** — what enabled the attack and how to fix it

---

## Files

| File | Description |
|---|---|
| `README.md` | This file |
| `Report/SOC_Detection_Report.md` | Full report — all 11 incidents with detection, IR, and RCA |
| `Report/SOC_Detection_Report.pdf` | PDF version of the report |
| `Queries/01_port_scan.spl` | SPL — Port scan detection |
| `Queries/02_brute_force_linux.spl` | SPL — Linux SSH brute force |
| `Queries/03_brute_force_windows.spl` | SPL — Windows SSH brute force |
| `Queries/04_reverse_shell.spl` | SPL — Reverse shell detection |
| `Queries/05_persistence_scheduled_task.spl` | SPL — Scheduled task persistence |
| `Queries/06_credential_dumping_lsass.spl` | SPL — LSASS credential dumping |
| `Queries/07_lateral_movement_psexec.spl` | SPL — PsExec lateral movement |
| `Queries/08_kerberoasting.spl` | SPL — Kerberoasting (RC4 downgrade) |
| `Queries/09_pass_the_hash.spl` | SPL — Pass-the-Hash (NtLmSsp) |
| `Queries/10_dcsync.spl` | SPL — DCSync (DS-Replication GUIDs) |
| `Queries/11_golden_ticket.spl` | SPL — Golden Ticket (EID 4672 for non-existent account) |

---

## Tools Used

| Tool | Purpose |
|---|---|
| Splunk Enterprise | SIEM — log ingestion, search, alerting |
| Sysmon | Enhanced Windows endpoint telemetry |
| Wazuh | File Integrity Monitoring (FIM) on Windows endpoints |
| Nmap | Port scanning / reconnaissance |
| Hydra | SSH brute force simulation |
| Netcat | Reverse shell listener |
| Mimikatz | Credential dumping (LSASS) |
| Impacket | PsExec, GetUserSPNs, secretsdump, ticketer, Pass-the-Hash |
| Windows Server 2016 | Active Directory domain controller |

---

## Key Detections

```spl
# Port Scan — single source hitting multiple ports
index=main EventCode=3
| bucket _time span=1m
| stats dc(DestinationPort) as unique_ports by _time, SourceIp, DestinationIp
| where unique_ports > 5

# Reverse Shell — PowerShell outbound non-standard port
index=main EventCode=3 Image="*powershell*"
| where DestinationPort != 80 AND DestinationPort != 443

# Kerberoasting — RC4 encryption downgrade
index=main EventCode=4769 Ticket_Encryption_Type=0x17

# PsExec Lateral Movement — random binary from services.exe
index=main EventCode=1 ParentImage="*services.exe*" Image="C:\\Windows\\*.exe"
| where NOT match(Image, "(?i)(svchost|sppsvc|TrustedInstaller|msiexec)")

# Pass-the-Hash — NTLM used instead of Kerberos for network logon
index=main EventCode=4624 Logon_Type=3
| search Logon_Process="NtLmSsp" Account_Name="Administrator"

# DCSync — DS-Replication GUIDs from non-DC source
index=main EventCode=4662
| search Properties="*1131f6aa*" OR Properties="*1131f6ab*"

# Golden Ticket — EID 4672 for account with no AD existence, no preceding 4768
index=main EventCode=4672
| stats count by Account_Name
| search NOT [
    search index=main EventCode=4720
    | stats count by Account_Name
    | fields Account_Name
  ]
```

---

## MITRE ATT&CK Coverage

| Tactic | Techniques Covered |
|---|---|
| TA0043 Reconnaissance | T1046 Network Service Discovery |
| TA0006 Credential Access | T1110.001 Password Guessing, T1003.001 LSASS Memory, T1558.003 Kerberoasting, T1003.006 DCSync, T1558.001 Golden Ticket |
| TA0002 Execution | T1059.001 PowerShell |
| TA0011 Command & Control | T1571 Non-Standard Port |
| TA0003 Persistence | T1053.005 Scheduled Task |
| TA0008 Lateral Movement | T1021.002 SMB/Admin Shares, T1543.003 Windows Service, T1550.002 Pass-the-Hash |
