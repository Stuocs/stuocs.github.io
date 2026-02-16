---
title: Web Enumeration
date: 2026-02-15 21:00:00 +0100
categories: [01-Reconnaissance, Web]
tags: [gobuster, ffuf, whatweb, recon]
author: kairos
---

## Dirb

```bash
dirb http://merchan.thl
```

This command uses **DIRB**, a web content scanner, to perform a brute-force discovery of hidden directories and files on the target web server `http://merchan.thl`.

---

### **Breakdown of the Command:**

- `dirb`: The tool for discovering web content via dictionary-based brute-forcing.
    
- `http://merchan.thl`: The target URL or domain to scan. DIRB will attempt to locate hidden directories or files under this domain using its default wordlist.
    

**How it works:**

DIRB sends HTTP requests by appending words from a predefined wordlist to the URL. If the server responds with valid status codes (typically 200 OK or 301/302 redirects), DIRB identifies those resources as existing.

---

### **Other Available Arguments for `dirb`:**

- `<url> <wordlist>` → Specify a custom wordlist. Example: `dirb http://target.com /usr/share/wordlists/dirb/common.txt`.
    
- `-o <output_file>` → Save results to a file.
    
- `-r` → Ignore redirects.
    
- `-S` → Silent mode, minimal output.
    
- `-x <ext>` → Add file extensions to brute-force (e.g., `-x .php,.html,.bak`).
    
- `-z <delay>` → Adds a delay between requests (useful for evading rate limits).
    
- `-f` → Forces a full URL scan, even if wildcards are present.
    
- `-N` → Disables null responses check.
    
- `-w` → Enables recursive scanning (subdirectories).
    

**DIRB** is commonly used in penetration testing and Red Team operations to uncover hidden or forgotten resources within web servers that could expose sensitive functionality, backups, or development files.

---


---

---

## Wfuzz

```shell
wfuzz -c --hc=404 -u http://merchan.thl/FUZZ.js -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
```

This command uses **WFuzz**, a powerful web fuzzing tool, to brute-force and discover possible `.js` (JavaScript) files on the target `http://merchan.thl`.

```shell
wfuzz -c --hl=0 -u 'http://merchan.thl/2e81eb4e952a3268babddecad2a4ec1e.php?FUZZ=/etc/passwd' -H 'Referer: http://merchan.thl/index.html' -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
```

This command uses **WFuzz** to fuzz after bypassing a 403 code error (-H 'Referer: http://merchan.thl/index.html')

```shell
 wfuzz -c --hc=404,400,302 -H "Host: FUZZ.rabbit.thm" -u rabbit.thm -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

This command works for enumerating subdomains.

```shell
wfuzz -c --hc=403 --hl=0 -u 'http://10.80.150.111/live.php?page=FUZZ'  -w /usr/share/wordlists/dirb/common.txt -H "User-Agent: Mozilla/5.0"
```
With -H you choose user agent, that way its possible to bypass certain WAF detection for enumeration (very sensible to failure and being detected)

(With gobuster you can autorecursive paths like this)
```shell
gobuster fuzz -u http://10.80.150.111/live.php?page=FUZZ -w /usr/share/wordlists/dirb/common.txt -a Mozilla/5.0 --xl 1907
```

---

### **Breakdown of the Command:**

- `wfuzz`: The fuzzing tool used for discovering hidden files, parameters, directories, and vulnerabilities in web applications.
    

**Options used:**

- `-c`: Enables colored output for better readability.
    
- `--hc=404`: Hides responses with HTTP status code 404 (Not Found). Only shows valid or interesting responses.
    
- `-u http://merchan.thl/FUZZ.js`: Target URL where `FUZZ` is the keyword replaced by each word from the wordlist, looking specifically for JavaScript files.
    
- `-w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt`: Specifies the wordlist to use for fuzzing, in this case, a medium-sized lowercase wordlist from Seclists, suitable for discovering common directories or files.
    

**How it works:**

WFuzz sends multiple requests, replacing `FUZZ` with each word from the list, effectively searching for JavaScript files such as `admin.js`, `config.js`, `login.js`, etc. Only responses other than 404 are displayed.

---

### **Other Available Arguments for `wfuzz`:**

- `-w <wordlist>` → Specify a custom wordlist.
    
- `--hh=<len>` → Hide responses with a specific length.
    
- `--hw=<lines>` → Hide responses with a specific number of words.
    
- `--hl=<lines>` → Hide responses with a specific number of lines.
    
- `--hc=<code>` → Hide responses with specific HTTP status codes (can chain: `--hc=404,403`).
    
- `-d <data>` → Use POST data for fuzzing.
    
- `-H <header>` → Add custom HTTP headers.
    
- `-b <cookie>` → Send cookies with the requests.
    
- `-t <threads>` → Number of concurrent threads.
    
- `-o <format>` → Output format (html, csv, json, etc.).
    
- `--ss <string>` → Show only responses containing a specific string.
    
- `-z <payload>` → Use different payload types like hex, base64, etc.
    

**WFuzz** is widely used in Red Team assessments, CTFs, and offensive security to find hidden files, API endpoints, parameters vulnerable to injection, or hidden functionality within web servers.

---


---

# Web Exploitation

---

