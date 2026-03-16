# SOC Home Lab — Attack Detection & Incident Response

A hands-on home lab simulating real-world attack scenarios and detecting them using Splunk, Sysmon, and Windows/Linux event logs. Built to develop practical SOC Tier 1 analyst skills.

---

## Lab Environment

```
Kali Linux (Attacker)
    │
    ├──► Windows 10 Pro / Windows 11 (Victim - Endpoint)
    │         └── Sysmon + Splunk Universal Forwarder
    │
    ├──► Windows Server 2016 (Domain Controller - AD)
    │         └── Splunk Universal Forwarder
    │
    └──► CentOS Linux (Splunk SIEM Server)
              └── Splunk Enterprise + auditd
```

| Machine | Role | IP (NAT) | IP (Host-Only) |
|---|---|---|---|
| Kali Linux | Attacker | 192.168.15.130 | 192.168.67.24 |
| Windows 10 Pro | Victim (Domain-joined) | — | 192.168.67.23 |
| Windows Server 2016 | Domain Controller (AD) | — | 192.168.67.22 |
| CentOS | Splunk SIEM | 192.168.15.131 | 192.168.67.11 |

**Tools used:** Splunk Enterprise, Sysmon, Splunk Universal Forwarder, Impacket, Hydra, Netcat, Mimikatz, Nmap

---

## Incidents Documented

| # | Incident | Attack Tool | MITRE Tactic | Detection Method |
|---|---|---|---|---|
| 1 | Port Scan / Recon | Nmap | TA0043 Recon | Sysmon EID 3 |
| 2 | Brute Force — Linux SSH | Hydra | TA0006 Credential Access | linux_secure auth logs |
| 3 | Brute Force — Windows RDP/SSH | Hydra | TA0006 Credential Access | Windows EID 4625 |
| 4 | Reverse Shell | Netcat + PowerShell | TA0002 Execution | Sysmon EID 1, 3 |
| 5 | Persistence — Scheduled Task | schtasks.exe | TA0003 Persistence | Windows EID 4698 |
| 6 | Credential Dumping — LSASS | Mimikatz + comsvcs.dll | TA0006 Credential Access | Sysmon EID 1 |
| 7 | Lateral Movement — PsExec | Impacket PsExec | TA0008 Lateral Movement | Sysmon EID 1, Windows EID 7045, 4624 |
| 8 | Kerberoasting | Impacket GetUserSPNs | TA0006 Credential Access | Windows EID 4769 |

---

## Repository Structure

```
soc-homelab/
│
├── README.md                        ← This file
│
├── report/
│   ├── SOC_Detection_Report.md      ← Full incident report (Markdown)
│   └── SOC_Detection_Report.pdf     ← Full incident report (PDF)
│
└── queries/
    ├── 01_port_scan.spl
    ├── 02_brute_force_linux.spl
    ├── 03_brute_force_windows.spl
    ├── 04_reverse_shell.spl
    ├── 05_persistence_scheduled_task.spl
    ├── 06_credential_dumping_lsass.spl
    ├── 07_lateral_movement_psexec.spl
    └── 08_kerberoasting.spl
```

---

## Key Learnings

- Sysmon is essential for endpoint visibility — Windows native logs alone miss most attacker activity
- Detection logic must be behavior-based, not just signature-based (e.g. process-based C2 detection over port-based)
- Tier 1 response follows triage → context → escalation, not immediate blocking
- Event ID 4769 with RC4 encryption (0x17) is a reliable Kerberoasting indicator regardless of whether cracking succeeds
- LSASS access attempts should be alerted on even if extraction fails — the attempt itself confirms elevated access
- Scheduled tasks with `ExecutionPolicy Bypass` in payload are almost always malicious

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sysmon Configuration](https://github.com/SwiftOnSecurity/sysmon-config)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435)
- [Impacket](https://github.com/fortra/impacket)
