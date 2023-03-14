# Redline
1. For high level triaging
2. First we need to create a script, the method we can use to create scripts is listed below, then run the audit script `RunRedlineAudit.bat` as admin. 
3. `Standard Collector`: collects minimum methods for analysis, `Comprehensive Collector`: collects much data, `IOC Search Collector`: collects data matched on IOC editor i.e. data that matched the IOCs.
4. Open `AnalysisSession1.mans` file by double clicking. It will be inside the `sessions` folder.
5. Some key points to look at
  - System Information (machine, BIOS (Windows only), operating system, and user information.)
  - Process (Process Name, PID, Path, Arguments, Parent process, Username,)
    - handle (connection from a process to an object or resource in a Windows operating system, like handle to files)
    - Memory Sections will let you investigate unsigned memory sections used by some processes. Many processes usually use legitimate dynamic link libraries (DLLs), which will be signed. This is particularly interesting because if you see any unsigned DLLs then it will be worth taking a closer look. 
    - strings
    - ports
  - File System (not included in this analysis session)
  - Registry
  - Windows Services
  - Tasks (Threat actors like to create scheduled tasks for persistence)
  - Event Logs 
  - ARP and Route Entries 
  - Browser URL History
  - File Download History
