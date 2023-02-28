`NOTE: These notes are derived from the following sources:
1. https://tryhackme.com/room/introtoendpointsecurity
2. `

## Windows
- Normal windows process 
  - System
  - System > smss.exe
  - csrss.exe
  - wininit.exe
  - wininit.exe > services.exe
  - wininit.exe > services.exe > svchost.exe
  - lsass.exe
  - winlogon.exe
  - explorer.exe
- Common tools that could be used
  - Event Viewer (GUI-based application)
  - Wevtutil.exe (command-line tool)
  - Get-WinEvent (PowerShell cmdlet)
  - sysmon
  - osquery (Enter cli with `osqueryi`)
  - wazuh
