## Tools Used
ProcMon, ProcExp, Regshot, API Logger, APIMonitor

## Sandbox Environment
FlareVM — an isolated environment not connected to production or live 
systems, used to safely execute and observe malware behavior without risk.

## Process Analysis
Executed a malicious executable and filtered network activity in ProcMon, 
observing TCP Connect, Reconnect, and Disconnect operations. In Process 
Explorer, signature verification via the Properties menu returned no valid 
signature, indicating the file is likely malicious. Strings observed in 
memory and on disk were different, which is a key indicator of runtime 
unpacking or injection.

Key concepts:
- Process Masquerading — attackers use legitimate Windows process names 
  to hide malicious activity
- Process Hollowing — malware hollows out a legitimate running process 
  and replaces it with malicious code
- Both can be detected using ProcExp signature verification

## API Calls of Interest
- InternetConnectW — network/C2 communication
- Sleep — sandbox evasion, delays analysis
- CreateFileA — file system manipulation

## Network Indicators
Observed C2 beaconing behavior — repeated TCP Reconnect and Disconnect 
operations indicating malware attempting callback to a hardcoded C2 domain. 
Connection failed due to sandbox isolation.

## Key Takeaways
- Compare strings in memory vs disk — differences indicate unpacking or injection
- Monitor outbound connections and file system changes during execution
- Verify signatures of running processes — legitimate Windows processes 
  should always be signed
