# Privilege Escalation

- Use the following tools

    LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/
    
    LinEnum: https://github.com/rebootuser/LinEnum
    
    LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
    
    Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
    
    Linux Priv Checker: https://github.com/linted/linuxprivchecker 

- Use GTFO bin, look at how they can be used to escape. https://gtfobins.github.io/  
- if u have sudo permission to somethings
- also we can check if suid or sgid bit are set in gtfo bins
- find place with suid bit set find /-type f-perm-04000-ls 2>/dev/null
- To crach password use the following command \john.exe --wordlist=C:\D\SecLists-master\Passwords\Common-Credentials\10k-most-common.txt pass.txt
- .\john.exe pass.txt--show
- manipulating $PATH, if a code execute commands like this system("thm"), change path to point to your binary, the calling code must have setuid set to escalate privilige.
- network mound, if no_root_sqash present
`showmount-e victimsIP`
`mount-o rw ip:/victimdir local_dir/`
make file with suid bit set in local_dir
change owner to root
run in victims machine

- Check for any cronjob, that we can manipulate
- check its sudo permissions `sudo-l`
- get capabilites `getcap-r / 2>/dev/null`
- look for `.dockerenv` this lets u know if it is running inside container
- Get environment variables.