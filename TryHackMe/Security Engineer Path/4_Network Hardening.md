# Common Threats
- Unauthorized Access: RCE, bruteforce, Social Engineering, phishing
- DOS
- MITM: ARP spoofing
- Privelege Escalation
- Bandwidth theft/hotlinking: liking bandwidth intensiev resource (image/video) from external website to original website without permission

# Common Hardenin Techniques
- Updates and Patches
- Disable unnecessary ports and services
- Least Privilege
- Logs Monitoring
- Backups
- Strong Passwords
- MFA

# VPN Hardening
- Strong encryption.
- Updatessssssssssssssss
- Strong authentication, stronger hashing
- Enable Perfect foward Secrecy, in openvpn it means new keys for each session.
- Dedicated user for VPNs.
- Openvpn server config path <!--StartFragment-->

`/etc/openvpn/server/server.conf`.

<!--EndFragment-->

# Harden Firewall
- Remove defualt creds
- Remove unnecessary scripts
- Enable secure protocols.
- Manage traffic rules.
- Monitor Traffic.
- Update firmware.
- Monitor scheduld tasks.
- Port Security.

# Some tools for network Monitoring
- nagios
- solarwinds
- PRTG
- zabbix