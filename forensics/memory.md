# Volatility
- Image via Redline, FTK imager,DumpIt.exe, win32dd.exe / win64dd.exe, Memoryze, FastDump
- In vol3, no os profiles, plugins are os specific
- In vol2, `imageinfo` plugin gave os profile info
- Vol3, just use `windows.info linux.info mac.info` to get specific info
- vol3 -f ./mem_file windows.info
- `vol3 -f ./mem_file windows.pslist`loops throught the process linked list. Some rootkit might unlick themselves, `vol3 -f ./mem_file windows.psscan` does not go through linked list, rather
scans entire memory for `_EPROCESS` structure. `pstree`similar to `pstree`, just shows the parent process as well.
- network info `windows.netstat` and dllinfo `windows.dlllist`. Netstat is said to be buggy, use `https://tools.kali.org/forensics/bulk-extractor`
- `malfind` will attempt to identify injected processes and their PIDs along with the offset address and a Hex, Ascii, and Disassembly view of the infected area. 
The plugin works by scanning the heap and identifying processes that have the executable bit set `RWE` or `RX` and/or no` memory-mapped` file on disk (file-less malware).
Based on what malfind identifies, the injected area will change. An MZ header is an indicator of a Windows executable file. The injected area could also be directed towards shellcode which requires further analysis.
`Syntax: python3 vol.py -f <file> windows.malfind`

- `System Service Descriptor Table;` the Windows kernel uses this table to look up system functions. 
- An adversary can hook into this table and modify pointers to point to a location the rootkit controls.
- There can be hundreds of table entries that ssdt will dump; you will then have to analyze the output further or compare against a baseline. 
- A suggestion is to use this plugin after investigating the initial compromise and working off it as part of your lead investigation.
- `windows.ssdt`

- `windows.modules` will dump a list of loaded kernel modules; this can be useful in identifying active malware. 
- However, if a malicious file is idly waiting or hidden, this plugin may miss it.

- `The driverscan plugin will scan for drivers present on the system at the time of extraction.`
- modscan
- driverirp
- callbacks
- idt
- apihooks
- moddump
- handles

- Other evasion techniques `
IRP Hooks
IAT Hooks
EAT Hooks
Inline Hooks`


- One cool technique from tryhackme lab `vol.py -f <dump> -o /dir/to/store_dump/ windows.memmap.Memmap --pid <suspicious PID> --dump Once the dump is stored use, strings *.dmp | grep -i "user-agent"`
