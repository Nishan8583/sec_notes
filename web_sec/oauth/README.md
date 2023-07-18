# Oauth
### Implicit Grant Type
 - Reference: https://portswigger.net/web-security/oauth
 - When logging in, some client application use POST form with login, Server may just accept the request, change `email`? to gain access to another users permission.
 - If there is no `state` parameter during linking, might be able to perform CSRF.
