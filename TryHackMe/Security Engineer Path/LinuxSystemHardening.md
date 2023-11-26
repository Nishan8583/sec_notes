`from room https://tryhackme.com/room/linuxsystemhardening#`
# Physical
- `grub2-mkpasswd-pbkdf2` to generate grub password, add in proper configuration. Not practical in server and cloud, since we might be physically present.

# Filesystem partition and encryption
- Linux distributions ship with LUKS (Linux Unified Key Setup).
- Parttion ecnrypted with LUKS will have following format:
________________________________________________
| LUKS phdr | KM1 | KM2 | ... | KM8 | Bulk Data |
________________________________________________
- LUKS phdr: It stands for LUKS Partition Header. stores information about the UUID (Universally Unique Identifier), the used cipher, the cipher mode, the key length, and the checksum of the master key.
- KM: KM stands for Key Material, where we have KM1, KM2, …, KM8. Each key material section is associated with a key slot, which can be indicated as active in the LUKS phdr. When the key slot is active, the associated key material section contains a copy of the master key encrypted with a user's password. In other words, we might have the master key encrypted with the first user's password and saved in KM1, encrypted with the second user's password and saved in KM2, and so on.
- Bulk Data: This refers to the data encrypted by the master key. The master key is saved and encrypted by the user's password in a key material section.
- Steps to use it
  - Install cryptsetup-luks. (You can issue apt install cryptsetup, yum install cryptsetup-luks or dnf install cryptsetup-luks for Ubuntu/Debian, RHEL/Cent OS, and Fedora, respectively.)
  - Confirm the partition name using fdisk -l, lsblk or blkid. (Create a partition using fdisk if necessary.)
  - Set up the partition for LUKS encryption: cryptsetup -y -v luksFormat /dev/sdb1. (Replace /dev/sdb1 with the partition name you want to encrypt.)
  - Create a mapping to access the partition: cryptsetup luksOpen /dev/sdb1 EDCdrive.
  - Confirm mapping details: ls -l /dev/mapper/EDCdrive and cryptsetup -v status EDCdrive.
  - Overwrite existing data with zero: dd if=/dev/zero of=/dev/mapper/EDCdrive.
  - Format the partition: mkfs.ext4 /dev/mapper/EDCdrive -L "Strategos USB".
  - Mount it and start using it like a usual partition: mount /dev/mapper/EDCdrive /media/secure-USB.

# Firewall
- At the very core, we have netfilter. The netfilter project provides packet-filtering software for the Linux kernel 2.4.x and later versions. Other tools are based on this.
- iptables
```
iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
```
- nftables, a bit complicated.
- UFW makes things easier.
  - `ufw allow 22/tcp`
  - `sudo ufw status`
