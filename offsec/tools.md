# Tools
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
