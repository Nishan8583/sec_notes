# LLMNR Poisoning
 - Link Local Multicast Name Resolution.
 - Previously known as  NBT-NS.
 - Used to identify hosts when DNS fails.
 - Flaw here is, service responds with username and NTLM-v2 Hash when approiately responded to.
 - Attack process
    1. Victim tries to connec to `\\some_machine`, so it queries DNS server.
    2. If the server does not have, the victim does a broadcast.
    3. The attacker then replies to victim, yes i have `\\some_machine`, send me your hash, and I will connect you to it.
    4. Victim then sends its NTLM hash.
 - Needs lot of traffic, so run first thing. 
 - `sudo ./test/bin/python Responder.py -I vboxnet0 -rdwv`
 - `hashcat -m 5600 hash.txt rockyou.txt`
