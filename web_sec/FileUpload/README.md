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
