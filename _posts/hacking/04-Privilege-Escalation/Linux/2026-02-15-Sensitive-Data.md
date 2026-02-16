---
title: Sensitive Data Exposure
date: 2026-02-15 21:00:00 +0100
categories: [04-Privilege-Escalation, Linux]
tags: [bash-history, config-files, ssh-keys, grep]
author: kairos
---

## GPG Keys

### Basic Concepts

GPG (GNU Privacy Guard) is a free implementation of OpenPGP that allows you to encrypt and sign data and communications. It uses both public key (asymmetric) and symmetric cryptography.

**Types of encryption:**

- **Symmetric**: Single password to encrypt and decrypt
- **Asymmetric**: Key pair (public/private)

---

### Basic Operations

#### Decrypt files

```bash
# With interactive password prompt
gpg -d file.gpg

# With password in command (symmetric)
gpg --batch --yes --passphrase "password" -d file.gpg

# With passphrase from stdin
echo "password" | gpg --batch --yes --passphrase-fd 0 -d file.gpg

# Decrypt and save to file
gpg -d file.gpg > decrypted_file.txt
gpg -o output.txt -d file.gpg

# With private key (asymmetric)
gpg --decrypt file.gpg
```

#### Encrypt files

**Symmetric encryption (with password):**

```bash
# Basic
gpg -c file.txt

# With specific algorithm
gpg --cipher-algo AES256 -c file.txt

# Specifying password in command
gpg --batch --yes --passphrase "mypassword" -c file.txt

# Output with specific name
gpg -o file.gpg --symmetric file.txt
```

**Asymmetric encryption (with public key):**

```bash
# Encrypt for a recipient
gpg -e -r name@email.com file.txt

# Encrypt for multiple recipients
gpg -e -r user1@email.com -r user2@email.com file.txt

# Encrypt and sign
gpg -e -s -r recipient@email.com file.txt

# Encrypt with ASCII armor output (plain text)
gpg -a -e -r recipient@email.com file.txt
```

---

### Key Management

#### Generate keys

```bash
# Generate key pair (interactive)
gpg --gen-key

# Generate with full options
gpg --full-generate-key

# Generate key with specific parameters
gpg --batch --generate-key <<EOF
Key-Type: RSA
Key-Length: 4096
Name-Real: Your Name
Name-Email: your@email.com
Expire-Date: 0
%no-protection
%commit
EOF
```

#### List keys

```bash
# List public keys
gpg --list-keys
gpg -k

# List private keys
gpg --list-secret-keys
gpg -K

# View details of specific key
gpg --list-keys user@email.com

# List with fingerprints
gpg --fingerprint
```

#### Export keys

```bash
# Export public key
gpg --export -a "name" > public.key
gpg --armor --export user@email.com > pubkey.asc

# Export private key
gpg --export-secret-keys -a "name" > private.key

# Export all public keys
gpg --export --armor > all_public.asc

# Export specific subkey
gpg --export-secret-subkeys KEY_ID > subkey.gpg
```

#### Import keys

Yes, the most popular key servers with the largest databases are:

**Main servers:**

```bash
# keys.openpgp.org (modern, with email verification)
gpg --keyserver hkps://keys.openpgp.org --search-keys user@email.com

# pgp.mit.edu (one of the oldest and most complete)
gpg --keyserver hkp://pgp.mit.edu --search-keys user@email.com

# keyserver.ubuntu.com (widely used, part of the SKS network)
gpg --keyserver hkp://keyserver.ubuntu.com --search-keys user@email.com

# keys.gnupg.net (official GnuPG server)
gpg --keyserver hkps://keys.gnupg.net --search-keys user@email.com
```

**Servers commonly seen in CTFs/THM:**

```bash
# pgp.mit.edu - The classic
gpg --keyserver pgp.mit.edu --recv-keys KEY_ID

# keyserver.ubuntu.com
gpg --keyserver keyserver.ubuntu.com --recv-keys KEY_ID

# keys.openpgp.org (newer but popular)
gpg --keyserver keys.openpgp.org --recv-keys KEY_ID
```

The one you probably remember from TryHackMe is **pgp.mit.edu**, as it's the most well-known and has the most historical keys stored. It's very common in cryptography and OSINT rooms.

**Typical CTF usage:**

```bash
# Search for all keys of a user
gpg --keyserver pgp.mit.edu --search-keys "username"

# Import directly if you know the KEY_ID
gpg --keyserver pgp.mit.edu --recv-keys 0x1234567890ABCDEF
```

#### Delete keys

```bash
# Delete public key
gpg --delete-key "name"

# Delete private key
gpg --delete-secret-key "name"

# Delete both (private first)
gpg --delete-secret-and-public-key "name"
```

---

### Digital Signatures

#### Sign files

```bash
# Sign file (generates .sig)
gpg --sign file.txt

# Sign in cleartext mode (readable text)
gpg --clearsign file.txt

# Detached signature (original file intact)
gpg --detach-sign file.txt

# Sign with specific key
gpg -u user@email.com --sign file.txt

# Sign in ASCII format
gpg -a --detach-sign file.txt
```

#### Verify signatures

```bash
# Verify signature
gpg --verify file.sig file.txt

# Verify embedded signature
gpg --verify file.txt.gpg

# Verify and extract
gpg file.txt.gpg
```

---

### Forensics and Recovery

#### GPG file information

```bash
# View information without decrypting
gpg --list-packets file.gpg

# View detailed metadata
gpg --list-packets --verbose file.gpg

# Verify integrity
gpg --verify file.gpg

# Identify encryption type used
file file.gpg
gpg --list-packets file.gpg | grep -i algo
```

#### Key and password search

**Dictionary attacks:**

```bash
# With John the Ripper
gpg2john file.gpg > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Extract hash manually
gpg --list-packets file.gpg
```

**Search for keys in system:**

```bash
# Search for GPG key files
find / -name "*.gpg" 2>/dev/null
find / -name "*.asc" 2>/dev/null
find ~/ -name "secring.gpg" 2>/dev/null

# Search in GPG directory
ls -la ~/.gnupg/

# Search for keys in memory (if GPG is running)
strings /proc/$(pgrep gpg-agent)/environ

# Search in command history
history | grep -i gpg
cat ~/.bash_history | grep -i gpg
```

**Configuration analysis:**

```bash
# View GPG configuration
cat ~/.gnupg/gpg.conf
cat ~/.gnupg/gpg-agent.conf

# View stored keys
gpg --list-secret-keys --keyid-format LONG
```

#### Metadata extraction

```bash
# View file headers
hexdump -C file.gpg | head -20

# Extract packet information
gpg --list-packets --verbose file.gpg > metadata.txt

# View creation date and algorithms
gpg --list-packets file.gpg | grep -E "created|algo"

# Identify compression type
gpg --list-packets file.gpg | grep -i compress
```

---

### Pentesting Techniques

#### Enumeration

```bash
# Search for GPG files in remote system
find / -type f -name "*.gpg" 2>/dev/null
find / -type f -name "*.asc" 2>/dev/null

# Search in common directories
ls -la ~/.gnupg/
ls -la /etc/gpg/
ls -la /var/backups/*.gpg

# Search in configuration files
grep -r "gpg" /etc/ 2>/dev/null
grep -r "BEGIN PGP" /home/ 2>/dev/null
```

#### Sensitive information extraction

```bash
# Search for exported private keys
find / -name "*private*" -o -name "*secret*" | grep -i gpg

# Review environment variables
env | grep -i gpg
printenv | grep -i pass

# Search for key backups
find / -name "*.bak" | xargs grep -l "BEGIN PGP" 2>/dev/null
```

#### GPG password cracking

```bash
# Prepare for John the Ripper
gpg2john file.gpg > hash.txt

# Crack with dictionary
john --wordlist=rockyou.txt hash.txt

# Crack with rules
john --rules --wordlist=rockyou.txt hash.txt

# Show cracked passwords
john --show hash.txt

# Hashcat (if correct format available)
hashcat -m 17010 -a 0 hash.txt wordlist.txt
```

---

### Key Servers

#### Upload keys

```bash
# Send public key to server
gpg --keyserver keyserver.ubuntu.com --send-keys KEY_ID

# Send to specific server
gpg --keyserver hkps://keys.openpgp.org --send-keys KEY_ID
```

#### Search for keys

```bash
# Search by email
gpg --keyserver keyserver.ubuntu.com --search-keys user@email.com

# Search by name
gpg --keyserver keyserver.ubuntu.com --search-keys "First Last"

# Receive specific key
gpg --keyserver keyserver.ubuntu.com --recv-keys KEY_ID
```

#### Update keys

```bash
# Update all keys
gpg --refresh-keys

# Update from specific server
gpg --keyserver keyserver.ubuntu.com --refresh-keys
```

---

### Common Troubleshooting

#### Pinentry issues

```bash
# Force loopback mode
gpg --pinentry-mode loopback -d file.gpg

# Use passphrase directly
gpg --batch --passphrase "password" -d file.gpg

# Configure to not use pinentry
echo "pinentry-mode loopback" >> ~/.gnupg/gpg.conf
```

#### Trust errors

```bash
# Trust a key
gpg --edit-key user@email.com
# Then at prompt: trust, select level, quit

# Sign key to trust
gpg --sign-key user@email.com

# List trust level
gpg --list-keys --with-colons | grep -E "^(pub|uid|fpr)"
```

#### Incorrect permissions

```bash
# Fix GPG directory permissions
chmod 700 ~/.gnupg
chmod 600 ~/.gnupg/*
```

---

### Useful Commands for CTFs

```bash
# Search for password fragments in files
grep -r "PASS" . 2>/dev/null
grep -r "PASSWORD" . 2>/dev/null
find . -type f -exec grep -l "FRAG" {} \;

# Combine fragments (example)
PASS="${PASSFRAG1}${PASSFRAG2}${PASSFRAG3}"
echo $PASS | gpg --batch --passphrase-fd 0 -d file.gpg

# Search in Git history
git log --all --full-history --source -- *password*
git log -p | grep -i "pass"

# Recover deleted files in Git
git log --all -- deleted_file.txt
git show COMMIT_HASH:deleted_file.txt

# Search in commits
git grep "password" $(git rev-list --all)
```

---

### Advanced Options

#### Custom configuration

```bash
# Edit configuration
nano ~/.gnupg/gpg.conf

# Useful options in gpg.conf:
# use-agent
# armor
# no-emit-version
# keyid-format 0xlong
# with-fingerprint
# personal-cipher-preferences AES256 AES192 AES
# personal-digest-preferences SHA512 SHA384 SHA256
# cert-digest-algo SHA512
```

#### Automation

```bash
# Script to encrypt multiple files
for file in *.txt; do
    gpg --batch --yes --passphrase "password" -c "$file"
done

# Decrypt multiple files
for file in *.gpg; do
    gpg --batch --yes --passphrase "password" -d "$file" > "${file%.gpg}"
done

# Backup keys
gpg --export-secret-keys -a > backup-$(date +%Y%m%d).asc
```

#### Encryption with multiple options

```bash
# Specify algorithm and compression
gpg --cipher-algo AES256 --compress-algo BZIP2 -c file.txt

# Without compression
gpg --compress-algo none -c file.txt

# With MDC (Modification Detection Code)
gpg --force-mdc -c file.txt
```

---

### Resources and References

**Official documentation:**

- `man gpg` - Complete manual
- `gpg --help` - Quick help
- https://gnupg.org/documentation/

**Public keyservers:**

- keyserver.ubuntu.com
- keys.openpgp.org
- pgp.mit.edu

**Forensic tools:**

- gpg2john (John the Ripper)
- hashcat (mode 17010 for GPG)
- binwalk (file analysis)

**Best practices:**

- Use keys of at least 2048 bits (preferably 4096)
- Set expiration date
- Use strong passphrases
- Keep secure backup of private keys
- Revoke compromised keys immediately


---

# Post-Exploitation

---

