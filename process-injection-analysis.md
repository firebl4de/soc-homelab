# Process Injection & Malware Static Analysis

## Scenario
Analyzed a suspicious binary exhibiting process injection behavior.

## Tools Used
- PEStudio
- FLOSS

## Key Indicators Identified
- Imports: VirtualAlloc, WriteProcessMemory, CreateRemoteThread
- Behavior: Classic DLL injection pattern — allocates memory in remote process, writes shellcode, spawns thread to execute it

## Static Analysis Findings
- High entropy (>7.0) in sections indicates packing or encryption
- Minimal string output from FLOSS suggests binary is protected against static analysis
- Next step: dynamic analysis to observe runtime behavior

## Key Takeaway
CreateRemoteThread = DLL injection. Process hollowing uses NtUnmapViewOfSection + ResumeThread. Know the difference.
