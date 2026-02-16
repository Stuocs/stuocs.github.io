---
title: Offline Cracking
date: 2026-02-15 21:00:00 +0100
categories: [03-Password-Attacks, Offline]
tags: [john, hashcat, keepass, zip]
author: kairos
---

## John

```shell
john --format=Raw-SHA1 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

---

## **Detailed Breakdown**

- `john`: Refers to **John the Ripper**, a widely-used password cracking tool designed for brute-force and dictionary attacks on password hashes.
    

### **Arguments**

- `--format=Raw-SHA1`:
    
    - Specifies the hash type as **Raw SHA-1**, meaning the hash is a straight 160-bit SHA1 digest with no salt or additional encoding.
        
    - Example of such a hash:  
        `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` (hash of the string `"password"`)
        
- `--wordlist=/usr/share/wordlists/rockyou.txt`:
    
    - Provides the path to the **rockyou.txt** wordlist, which contains millions of common passwords.
        
    - The tool iterates through each word, applies SHA1 hashing, and compares the result to the hash in `hash.txt`.
        
- `hash.txt`:
    
    - Input file containing the target SHA1 hash(es), typically one per line.
        

---

## **How It Works**

John reads the hash from `hash.txt`, processes each word from the `rockyou.txt` wordlist by applying SHA1 hashing, and compares the result to the target hash.

- If a match is found, the plaintext password corresponding to the hash is revealed.
    

---

## **Available Additional Arguments for John the Ripper**

|**Argument**|**Description**|
|---|---|
|`--show`|Displays cracked passwords from saved sessions|
|`--session=<name>`|Saves and resumes sessions with a custom identifier|
|`--incremental`|Performs a brute-force attack with increasing complexity|
|`--format=<type>`|Forces specific hash format (e.g., `md5`, `sha512crypt`)|
|`--rules`|Applies password mutation rules to enhance dictionary attacks|
|`--fork=<N>`|Parallel cracking using `N` processes|
|`--pot=<file>`|Specifies alternative potfile to store cracked passwords|
|`--mask=<pattern>`|Defines a mask for custom brute-force attacks (e.g., `?l?l?l?l`)|

---

## **Example Variants**

Brute-force attack using incremental mode:
```bash
john --format=Raw-SHA1 --incremental hash.txt
```
    
- Showing cracked results:
    ```bash
    john --show hash.txt
    ```
    
- Applying mutation rules to the wordlist:
    
    ```bash
    john --format=Raw-SHA1 --wordlist=/usr/share/wordlists/rockyou.txt --rules hash.txt
    ```
    

---

## **Summary**

This command executes a **dictionary attack** using John the Ripper against a SHA1 hash, leveraging the `rockyou.txt` wordlist. It's a reliable and efficient method for cracking unsalted SHA1 hashes during penetration testing, Red Team exercises, or CTF competitions.

This method is particularly effective when dealing with weak or commonly used passwords.

---


---

---



## John

```shell
john --format=Raw-SHA1 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

---

## **Detailed Breakdown**

- `john`: Refers to **John the Ripper**, a widely-used password cracking tool designed for brute-force and dictionary attacks on password hashes.
    

### **Arguments**

- `--format=Raw-SHA1`:
    
    - Specifies the hash type as **Raw SHA-1**, meaning the hash is a straight 160-bit SHA1 digest with no salt or additional encoding.
        
    - Example of such a hash:  
        `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` (hash of the string `"password"`)
        
- `--wordlist=/usr/share/wordlists/rockyou.txt`:
    
    - Provides the path to the **rockyou.txt** wordlist, which contains millions of common passwords.
        
    - The tool iterates through each word, applies SHA1 hashing, and compares the result to the hash in `hash.txt`.
        
- `hash.txt`:
    
    - Input file containing the target SHA1 hash(es), typically one per line.
        

---

## **How It Works**

John reads the hash from `hash.txt`, processes each word from the `rockyou.txt` wordlist by applying SHA1 hashing, and compares the result to the target hash.

- If a match is found, the plaintext password corresponding to the hash is revealed.
    

---

## **Available Additional Arguments for John the Ripper**

|**Argument**|**Description**|
|---|---|
|`--show`|Displays cracked passwords from saved sessions|
|`--session=<name>`|Saves and resumes sessions with a custom identifier|
|`--incremental`|Performs a brute-force attack with increasing complexity|
|`--format=<type>`|Forces specific hash format (e.g., `md5`, `sha512crypt`)|
|`--rules`|Applies password mutation rules to enhance dictionary attacks|
|`--fork=<N>`|Parallel cracking using `N` processes|
|`--pot=<file>`|Specifies alternative potfile to store cracked passwords|
|`--mask=<pattern>`|Defines a mask for custom brute-force attacks (e.g., `?l?l?l?l`)|

---

## **Example Variants**

Brute-force attack using incremental mode:
```bash
john --format=Raw-SHA1 --incremental hash.txt
```
    
- Showing cracked results:
    ```bash
    john --show hash.txt
    ```
    
- Applying mutation rules to the wordlist:
    
    ```bash
    john --format=Raw-SHA1 --wordlist=/usr/share/wordlists/rockyou.txt --rules hash.txt
    ```
    

---

## **Summary**

This command executes a **dictionary attack** using John the Ripper against a SHA1 hash, leveraging the `rockyou.txt` wordlist. It's a reliable and efficient method for cracking unsalted SHA1 hashes during penetration testing, Red Team exercises, or CTF competitions.

This method is particularly effective when dealing with weak or commonly used passwords.

---


---

---

## Hashcat

```shell
hashcat -m 100 -a 0 --force hash.txt /usr/share/wordlists/rockyou.txt
```

---

## **Detailed Breakdown**

- `hashcat`: A powerful and optimized password recovery tool that uses CPU/GPU acceleration for hash cracking.
    

### **Arguments**

- `-m 100`: Specifies the **hash mode**, where:
    
    - `100` corresponds to **SHA1 Hash**.  
        Example hash format:  
        `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` → Hash of "password"
        
- `-a 0`: **Attack mode 0**, which is a **straight attack**:
    
    - Direct comparison of hashes using each word from the wordlist.
        
    - No transformations unless explicitly applied.
        
- `--force`: Forces execution even if the system lacks recommended hardware or compatibility is suboptimal.
    
    - Useful for virtual machines, limited hardware, or environments where Hashcat detects constraints.
        
    - Not recommended for production cracking environments but acceptable for testing, CTFs, and restricted scenarios.
        
- `hash.txt`: Input file containing the hash(es) to crack. Each line typically contains one hash.
    
- `/usr/share/wordlists/rockyou.txt`: Path to the **wordlist**, in this case, `rockyou.txt`:
    
    - Popular wordlist containing millions of common passwords.
        
    - Frequently used in CTFs, Red Team operations, and password auditing.
        

---

## **How It Works**

Hashcat reads each password candidate from `rockyou.txt`, applies the SHA1 hash function, and compares it to the target hash in `hash.txt`. Upon a match, Hashcat outputs the cracked plaintext password.

---

## **Available Additional Arguments for hashcat**

|**Argument**|**Description**|
|---|---|
|`-m <mode>`|Hash type selection (e.g., `0` for MD5, `500` for MD5crypt)|
|`-a <mode>`|Attack mode (e.g., `0` straight, `3` brute-force, `6` hybrid)|
|`-o <file>`|Output cracked hashes to a file|
|`--show`|Displays cracked hashes from a previous session|
|`--username`|Ignores usernames in hash files formatted as `user:hash`|
|`-r <rulefile>`|Apply rule-based mutations to wordlist candidates|
|`-w <level>`|Workload profile (`1` to `4`, low to high performance)|
|`--status`|Shows periodic status updates|
|`--potfile-disable`|Disables storing cracked hashes in potfile|

---

## **Example Variants**

- Cracking MD5 hashes:
    
    ```bash
    hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
    ```
    
- Using a brute-force mask attack for a 6-character lowercase password:
    
    ```bash
    hashcat -m 100 -a 3 hash.txt ?l?l?l?l?l?l
    ```
    
- Showing already cracked results:
    
    ```bash
    hashcat -m 100 --show hash.txt
    ```
    

---

## **Summary**

The command performs a **dictionary-based attack** against SHA1 hashes using `rockyou.txt` as the wordlist. It's a standard approach for initial password recovery attempts during Red Team operations, CTFs, and vulnerability assessments.

Efficient, straightforward, and heavily relies on proper hash identification and the effectiveness of the wordlist.

---


---

# Privilege Escalation

---

