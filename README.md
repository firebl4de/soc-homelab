# SOC Home Lab

A hands-on home lab simulating a real-world attack chain from initial reconnaissance through Active Directory attacks. Built to develop practical detection, investigation, and incident response skills using industry-standard tools.

---

## Lab Environment

| Machine | Role | OS | IP |
|---|---|---|---|
| Kali Linux | Attacker | Kali 2024 | 192.168.15.129 / 192.168.67.24 |
| Windows 10 Pro | Victim (domain-joined) | Windows 10 Pro | 192.168.67.23 |
| Windows Server 2016 | Domain Controller | Windows Server 2016 | 192.168.67.22 |
| CentOS | Splunk SIEM | CentOS 9 | 192.168.15.131 / 192.168.67.11 |

**Detection stack:** Splunk Enterprise + Sysmon + Windows Event Forwarding + Linux auditd

---

## Attack Chain

The lab covers a full threat actor kill chain across 8 incidents:

```
Reconnaissance → Credential Access → Execution → Persistence → Credential Dumping → Lateral Movement → AD Attack
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
| `SOC_Detection_Report.md` | Full report — all 8 incidents with detection, IR, and RCA |
| `SOC_Report_Final.pdf` | PDF version of the report |

---

## Tools Used

| Tool | Purpose |
|---|---|
| Splunk Enterprise | SIEM — log ingestion, search, alerting |
| Sysmon | Enhanced Windows endpoint telemetry |
| Nmap | Port scanning / reconnaissance |
| Hydra | SSH brute force simulation |
| Netcat | Reverse shell listener |
| Mimikatz | Credential dumping (LSASS) |
| Impacket | PsExec lateral movement + Kerberoasting |
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
```

---

## MITRE ATT&CK Coverage

| Tactic | Techniques Covered |
|---|---|
| TA0043 Reconnaissance | T1046 Network Service Discovery |
| TA0006 Credential Access | T1110.001 Password Guessing, T1003.001 LSASS Memory, T1558.003 Kerberoasting |
| TA0002 Execution | T1059.001 PowerShell |
| TA0011 Command & Control | T1571 Non-Standard Port |
| TA0003 Persistence | T1053.005 Scheduled Task |
| TA0008 Lateral Movement | T1021.002 SMB/Admin Shares, T1543.003 Windows Service |
