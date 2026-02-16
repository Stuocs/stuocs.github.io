---
title: Online Attacks
date: 2026-02-15 21:00:00 +0100
categories: [03-Password-Attacks, Online]
tags: [hydra, medusa, ssh, rdp]
author: kairos
---

## Hydra

```shell
hydra -l julia -P /usr/share/wordlists/rockyou.txt ssh://merchan.thl -t 64
```

This command uses **Hydra**, a parallelized login cracker, to perform a **brute-force attack** against an SSH service running on `merchan.thl`.

---

## **Detailed Breakdown:**

- `hydra`: A powerful tool for automated password guessing against various network services.
    
- `-l julia`: Specifies the **username** to target, in this case, `julia`.
    
- `-P /usr/share/wordlists/rockyou.txt`: Defines the **password list** (`rockyou.txt`) to use for the brute-force attack. This wordlist is commonly used in penetration testing and contains millions of leaked passwords.
    
- `ssh://merchan.thl`: Targets the **SSH service** on the host `merchan.thl`.
    
- `-t 64`: Sets the number of **parallel threads** to 64, significantly speeding up the attack by attempting multiple logins simultaneously.
    

---

## **Purpose of the Command:**

- Attempts to discover valid SSH credentials for the user `julia` on the system `merchan.thl`.
    
- It brute-forces the SSH service using passwords from the specified wordlist.
    
- If successful, Hydra will output the valid username and password combination.
    

---

## **Additional Useful Hydra Arguments:**

- `-L <userlist>`: Use a file with multiple usernames.
    
- `-p <password>`: Specify a single password to test.
    
- `-s <port>`: Specify a different port if SSH runs on a non-default port (default is 22).
    
- `-vV`: Verbose mode, shows each attempted login.
    
- `-o <file>`: Save successful attempts to a file.
    
- `-f`: Exit after the first valid password is found.
    
- `-w <seconds>`: Set a timeout for responses.
    
- `-u`: Loop through all usernames with one password before moving to the next password (useful for userlist+passwordlist attacks).
    

---

## **Summary**

This Hydra command aggressively brute-forces SSH credentials for user `julia` on `merchan.thl`, using the `rockyou.txt` wordlist with 64 threads. It is a common approach during Red Team operations or Capture The Flag (CTF) challenges to gain initial access to a target system.

---


---

---

