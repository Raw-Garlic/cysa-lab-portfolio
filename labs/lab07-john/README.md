# Lab 07 — Password Analysis: John the Ripper

**CySA+ CS0-003 Home Lab Portfolio** | Alejandro W. Orellana  
**Cert Stack:** CompTIA Security+ | Network+ | CySA+ | Google Cybersecurity Certificate

---

## Overview

This lab demonstrates offensive credential analysis using John the Ripper against Linux password hashes. The objective was to simulate an attacker extracting and cracking a shadow file, compare wordlist vs brute force attack modes, and map findings to MITRE ATT&CK defensive controls.

---

## Lab Objectives

- Extract Linux password hashes using `unshadow`
- Crack MD5crypt hashes using rockyou.txt wordlist attack
- Demonstrate incremental (brute force) mode vs wordlist mode
- Map techniques to MITRE ATT&CK
- Identify defensive controls that mitigate credential dumping and password cracking

---

## Environment

| Field | Detail |
|---|---|
| **Tool** | John the Ripper 1.9.0-jumbo-1 (OMP, AVX2) |
| **Target** | 3 local test accounts — MD5crypt ($1$) hashed passwords |
| **Wordlist** | rockyou.txt (14.3 million entries) |
| **Platform** | Kali Linux — VirtualBox isolated lab |
| **Hash Format** | md5crypt / crypt(3) $1$ |

---

## Attack Phases

### Phase 1 — Credential Extraction (T1003)

```bash
sudo unshadow /etc/passwd /etc/shadow > /tmp/crackme.txt
grep "testuser" /tmp/crackme.txt
```

**Output:**
```
testuser1:$1$QAQRRnfi$V5f7BNOb3Ek2Zp8q2AtLU0:1002:1002::/home/testuser1:/bin/sh
testuser2:$1$ThS0Qo1i$cCglYzecaOQCCNgSsQq2G0:1003:1003::/home/testuser2:/bin/sh
testuser3:$1$IvRProTh$6WG7aAi0ZepVCqq3Nu0Vq0:1004:1004::/home/testuser3:/bin/sh
```

The `$1$` prefix confirms MD5crypt hashing with unique salts per account.

---

### Phase 2 — Wordlist Attack (T1110.002)

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/crackme.txt
```

**Output:**
```
Loaded 3 password hashes with 3 different salts (md5crypt, crypt(3) $1$)
Will run 4 OpenMP threads
abc123           (testuser2)
letmein          (testuser3)
password123      (testuser1)
3g 0:00:00:00 DONE — 20.00g/s — Session completed.
```

| Metric | Result |
|---|---|
| Passwords cracked | 3 of 3 (100%) |
| Time to crack | Under 1 second |
| Crack speed | 20,000 g/s |
| CPU threads | 4 (OpenMP auto-scaled) |

---

### Phase 3 — Incremental / Brute Force Mode

```bash
john --incremental /tmp/crackme.txt
```

**Output (aborted after 30 seconds):**
```
Loaded 3 password hashes with 3 different salts
Will run 4 OpenMP threads
abc123           (testuser2)
1g 0:00:00:51  0.01945g/s 15452p/s
Session aborted
```

| Mode | Speed | Cracked | Time |
|---|---|---|---|
| Wordlist | 20,000 g/s | 3 of 3 | < 1 second |
| Incremental | 15,452 p/s | 1 of 3 | 51 seconds (aborted) |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Lab Activity |
|---|---|---|---|
| T1003 | OS Credential Dumping | Credential Access | unshadow extracted /etc/passwd + /etc/shadow |
| T1110.002 | Brute Force: Password Cracking | Credential Access | John run in wordlist and incremental modes |
| T1078 | Valid Accounts | Persistence / Lateral Movement | Cracked credentials = valid authenticated access |

---

## Key Findings

**All three passwords cracked in under 1 second** using the rockyou wordlist — demonstrating that common passwords provide zero meaningful protection against dictionary attacks regardless of hashing algorithm.

**Wordlist vs brute force tradeoff:** Wordlist mode is 50x+ faster against common passwords but limited to wordlist contents. Incremental mode is exhaustive but impractical against strong passwords (12+ character random strings would take years on a single machine).

**Credential dumping requires root access** — connecting this lab to Lab 03 (Metasploitable2 had multiple CVSS 9.8–10.0 findings that enable root access). The attack chain is: exploit vulnerability → escalate privileges → dump shadow file → crack offline.

---

## Defensive Controls

| Control | Mitigation |
|---|---|
| Password policy | Minimum 12 characters with complexity; block against known-bad lists |
| Modern hashing | Replace MD5crypt with bcrypt or Argon2id (memory-hard, crack-resistant) |
| Shadow file monitoring | auditd: `-w /etc/shadow -p r -k shadow_read` |
| MFA enforcement | Cracked credentials useless if MFA required — mitigates T1078 impact |
| Account lockout | pam_faillock after 5 failed attempts — blocks online brute force |

---

## Deliverables

| File | Description |
|---|---|
| `Lab07_JohnTheRipper_Orellana.pdf` | Full lab report with terminal output, findings, ATT&CK mapping, and defensive controls |
| `README.md` | This file |

---

## Lab Series Navigation

| Lab | Topic | Status |
|---|---|---|
| Lab 01 | Nmap Network Reconnaissance | ✅ Complete |
| Lab 02 | Wireshark Traffic Analysis | ✅ Complete |
| Lab 03 | Nessus Vulnerability Scanning | ✅ Complete |
| Lab 04 | Splunk SIEM Analysis (BOTSv1) | ✅ Complete |
| Lab 05 | MITRE ATT&CK Threat Intelligence | ✅ Complete |
| Lab 06 | AIDE File Integrity Monitoring | ✅ Complete |
| **Lab 07** | **John the Ripper Password Analysis** | ✅ **Complete** |
| Lab 08 | Nikto Web Vulnerability Scanning | 🔄 Up Next |

---

*All testing performed in an isolated VirtualBox lab environment. No systems were harmed.*  
*CySA+ CS0-003 Home Lab Portfolio — github.com/[your-handle]/cysa-lab-portfolio*
