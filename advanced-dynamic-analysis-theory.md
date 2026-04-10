## Advanced Dynamic Analysis

## Malware Evasion — Static Analysis Bypass Techniques

Malware authors use several techniques to evade static analysis:

- **Hash Modification** — Every file has a unique hash. Changing even a single bit produces a different hash, bypassing hash-based detection mechanisms.
- **Signature Evasion** — Static patterns within the malware are modified to avoid detection by antivirus tools that rely on signature-based detection.
- **String Obfuscation** — Strings such as URLs and IP addresses are obfuscated and only decoded at runtime, making them invisible during static analysis.
- **Runtime DLL Loading** — Windows APIs such as `LoadLibrary` and `LoadLibraryEx` are used to load DLLs at runtime, hiding full functionality from static analysis.
- **Packing and Obfuscation** — Packers compress and encrypt the malware payload, which is only decoded at runtime, leaving little to analyze statically.

## Malware Evasion — Dynamic Analysis Bypass Techniques

Malware authors also attempt to detect and evade dynamic analysis environments:

- **VM Identification** — Malware checks for indicators of a virtual machine such as specific registry keys, limited RAM, or a single CPU core, and behaves benignly if detected.
- **Timing Attacks** — Malware uses the `Sleep` API to outlast automated sandbox timeouts. Modern sandboxes manipulate time to counter this. In response, advanced malware compares the timestamp before and after a sleep call — if time was manipulated, it switches to a benign execution path.
- **User Activity Checks** — Malware looks for traces of real user activity such as browser history, system uptime, and connected keyboard and mouse. Absence of these indicators suggests a controlled environment, triggering benign behavior.
- **Analysis Tool Detection** — Malware uses `Process32First` and `Process32Next` to enumerate running processes. If monitoring tools such as ProcMon or ProcExp are detected, it follows a benign execution path.

## Debugging Malware

Analysts often need to debug malware to remove evasion roadblocks and force malicious behavior.

**Types of Debuggers:**

- **Source-Level Debuggers** — Operate at source code level. High-level debuggers that expose local variables and their values.
- **Assembly-Level Debuggers** — Debug compiled code at the assembly level. Allow inspection of register values and the debuggee's memory.
- **Kernel-Level Debuggers** — Operate at the lowest level, debugging programs at the kernel layer.
