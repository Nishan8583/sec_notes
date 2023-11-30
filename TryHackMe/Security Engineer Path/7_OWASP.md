# OWASP Top 10 2021
Awesome Reference: https://book.hacktricks.xyz/welcome/readme
## Broken Access control
- IDOR, should not be directly accessible but it is
- URLs ike https://bank.thm/account?id=111111 , change params.
- https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html

## Cryptgraphic Failures
- MITMs, gets the key.
- Use of weak algorithms, md5 and …
- https://crackstation.net/

## Injection
- SQL/Command

## Insecure Design
- They are not vulnerabilities regarding bad implementations or configurations, but the idea behind the whole application (or a part of it) is flawed from the start.
- Ex: Insecure password reset
- https://owasp.org/Top10/A04_2021-Insecure_Design/


## Security Misconfiguration
- like console given in debug mode in prod.

## Outdated components
    - u know how it is, search for version, find vulnerbility, exploit.
## Identification and Auth failures
- Brute force, weak creds, spaces reregister, weak cookies

## Data Integrity
- JWT, remove signature, keep dot, change alg to "none", change users, see if it works.

## SSRF
- look for urls in params and json requests.