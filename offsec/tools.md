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
