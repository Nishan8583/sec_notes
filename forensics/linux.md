# Linux stuffs
- `cat /etc/os-release` OS release information.
- `/etc/passwd` file contains information about the user accounts that exist on a Linux system.
- cat /etc/passwd| column -t -s : `x` means the password is in `/etc/shadow`
- Group info in `/etc/group`
- Sudoers is in `/etc/shadow`
- `/var/log/btmp` failed login attempts, `/var/log/wtmp` login attempts. Need to use `last` to read. Ex: `last -n 500 -f /var/log/wtmp`
- `/var/log/auth.log`
- Hostname in `cat /etc/hostname`
- Timezone in `/etc/timezone`
- Network Configuration `/etc/network/interfaces`. `ip address show `
- Name resolution `/etc/hosts`
- `ps aux`
- Network open sockets and stuffs `netstat -natp`
- Cron jobs `/etc/crontab`
- Startup services in `/etc/init.d d` directory.
- `.bashrc` contains list of commands to be executed when user logs in.

- sudo execution history `cat /var/log/auth.log* |grep -i COMMAND|tail`
- `~/.bash_history`

- `/var/log/syslog`
- `cat /var/log/auth.log* |head`
