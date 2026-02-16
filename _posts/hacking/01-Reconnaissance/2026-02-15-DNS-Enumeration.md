---
title: DNS Enumeration
date: 2026-02-15 21:00:00 +0100
categories: [01-Reconnaissance, DNS]
tags: [dig, zone-transfer, nmap, recon]
author: kairos
---

## Dig For Pentesting

```shell
dig AXFR bestfestivalcompany.thm @10.10.13.46
```

---

## **What This Command Does**

- `dig`: DNS lookup utility used for querying Domain Name System servers.
    
- `AXFR`: Stands for **Authoritative Zone Transfer**, a DNS operation intended to replicate an entire DNS zone file from a server.
    
- `bestfestivalcompany.thm`: The domain to perform the zone transfer against.
    
- `@10.10.13.46`: Specifies the DNS server to query directly, in this case, IP `10.10.13.46`.
    

### **Purpose**

This command attempts to retrieve **all DNS records** for the domain `bestfestivalcompany.thm` by requesting a **zone transfer**. Zone transfers are typically restricted to authorized servers (secondary DNS servers), but misconfigured DNS servers may allow unauthorized transfers, exposing:

- Subdomains
    
- Internal infrastructure details
    
- Service records
    
- Hostnames
    
- Additional metadata
    

This is often leveraged during reconnaissance phases of Red Team assessments or CTFs to map a target's internal network.

---

## **Example Output (Expected if Vulnerable)**

```python
; <<>> DiG 9.20.9-1-Debian <<>> AXFR bestfestivalcompany.thm @10.10.13.46
;; global options: +cmd
bestfestivalcompany.thm. 600    IN      SOA     bestfestivalcompany.thm. hostmaster.bestfestivalcompany.thm. 1751409901 1200 180 1209600 600
bestfestivalcompany.thm. 600    IN      NS      bestfestivalcompany.thm.
bestfestivalcompany.thm. 600    IN      NS      0.0.0.0/0.
thehub-uat.bestfestivalcompany.thm. 600 IN A    172.16.1.3
thehub-int.bestfestivalcompany.thm. 600 IN A    172.16.1.3
thehub.bestfestivalcompany.thm. 600 IN  A       172.16.1.3
adm-int.bestfestivalcompany.thm. 600 IN A       172.16.1.2
npm-registry.bestfestivalcompany.thm. 600 IN A  172.16.1.2
bestfestivalcompany.thm. 600    IN      SOA     bestfestivalcompany.thm. hostmaster.bestfestivalcompany.thm. 1751409901 1200 180 1209600 600
;; Query time: 58 msec
;; SERVER: 10.10.13.46#53(10.10.13.46) (TCP)
;; WHEN: Tue Jul 01 18:48:35 EDT 2025
;; XFR size: 9 records (messages 1, bytes 451)
```

Such output exposes all known records, significantly aiding network mapping and attack surface identification.

---

## **Available Additional Arguments for `dig`**

|**Argument**|**Description**|
|---|---|
|`@<server>`|Query a specific DNS server|
|`<record type>`|Request specific record types (e.g., `A`, `MX`, `TXT`, `NS`)|
|`+short`|Provides concise output|
|`+trace`|Traces the DNS resolution path step-by-step|
|`+nocmd`|Suppresses the command display in output|
|`ANY`|Queries all record types for a domain (if permitted)|
|`-x <IP>`|Performs reverse DNS lookup|
|`+norecurse`|Prevents recursion in DNS queries|
|`-t <record type>`|Explicitly specify record type (alternative to direct input)|

---

## **Example Variants**

- Query a different record:
    
    ```bash
    dig A www.bestfestivalcompany.thm @10.10.13.46
    ```
    
- Reverse DNS lookup:
    
    ```bash
    dig -x 10.10.13.50 @10.10.13.46
    ```
    
- Tracing DNS resolution:
    
    ```bash
    dig +trace bestfestivalcompany.thm
    ```
    

---

## **Summary**

This command attempts a **DNS Zone Transfer**, a high-value reconnaissance action if the DNS server is improperly configured. Misconfigured AXFR permissions expose complete DNS infrastructure, commonly leading to identification of hidden hosts or services exploitable during further penetration testing activities.

---


---

---

