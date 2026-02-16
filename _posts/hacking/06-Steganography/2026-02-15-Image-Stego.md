---
title: Image Steganography
date: 2026-02-15 21:00:00 +0100
categories: [06-Steganography, Images]
tags: [steghide, stegseek, exiftool, ctf]
author: kairos
---

## Steghide

```shell
steghide extract -sf white_rabbit_1.jpg
```

---

## **Detailed Breakdown**

- `steghide`:  
    A steganography tool used to hide or extract data within various file formats such as JPEG, BMP, WAV, or AU. Commonly used in CTFs, forensic investigations, and Red Team engagements to analyze hidden information.
    

---

### **Arguments**

- `extract`:  
    Tells `steghide` to perform **extraction**, retrieving hidden data from a carrier file.
    
- `-sf white_rabbit_1.jpg`:  
    **`-sf`** stands for **stegofile**, indicating the carrier file where hidden data resides. In this case, it's `white_rabbit_1.jpg`.
    

During extraction, if a **passphrase** is required (as in most `steghide` operations), the tool prompts for it. If the passphrase is correct, the hidden data is decrypted and extracted.

**Output Example:**

> wrote extracted data to "hint.txt".

This means `steghide` successfully found hidden information within `white_rabbit_1.jpg` and extracted it as `hint.txt`.

---

## **Available Additional Arguments for Steghide**

|**Argument**|**Description**|
|---|---|
|`--help`|Displays help information and usage details|
|`info -sf <file>`|Shows embedded information in the stego file without extraction|
|`extract -sf <file> -xf <output>`|Extracts hidden data to a specified output file|
|`embed -cf <coverfile> -ef <datafile>`|Embeds datafile into the carrier/cover file|
|`-p <passphrase>`|Supplies the passphrase directly on the command line (use with caution)|
|`-Z`|Displays compression information for the embedded file (if compressed)|

---

## **Example Variants**

- Extract data specifying output file:
    
    ```bash
    steghide extract -sf secret.jpg -xf hidden.txt
    ```
    
- Extract data with passphrase inline (not recommended for OPSEC reasons):
    
    ```bash
    steghide extract -sf secret.jpg -p "mySecretPass"
    ```
    
- Get information about embedded content:
    
    ```bash
    steghide info -sf secret.jpg
    ```
    

---

## **Summary**

The command extracts hidden content from `white_rabbit_1.jpg` using `steghide`, requiring a valid passphrase to reveal the embedded file (`hint.txt`). This method is standard for detecting steganographic payloads during Red Team exercises, CTFs, or digital forensic operations.

---


---

---

