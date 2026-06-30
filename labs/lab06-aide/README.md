# Lab 06 — File Integrity Monitoring with AIDE

**CySA+ CS0-003 Home Lab Portfolio** | Alejandro W. Orellana
**Cert Stack:** CompTIA Security+ | Network+ | CySA+ | Google Cybersecurity Certificate

---

## Overview

This lab implements file integrity monitoring (FIM) using AIDE (Advanced Intrusion Detection Environment) on Kali Linux. The objective was to establish a cryptographic filesystem baseline, simulate two common attack-related file changes, and confirm AIDE's detection capability — including full hash comparison output across multiple algorithms.

---

## Lab Objectives

- Install and configure AIDE on Kali Linux
- Establish a cryptographic baseline of the monitored filesystem
- Simulate an unauthorized file addition (payload drop scenario)
- Simulate an unauthorized file modification (/etc/hosts DNS tampering)
- Document detection output and map findings to MITRE ATT&CK

---

## Environment

| Component | Detail |
|---|---|
| Host Machine | ASUS ROG Gaming A16 |
| Lab VM | Kali Linux (VirtualBox) — ao11211986@kali |
| Tool | AIDE 0.19.3 |
| Config File | /etc/aide/aide.conf |
| Database | /var/lib/aide/aide.db |
| Monitored Paths | /etc, /bin, /sbin, /usr/bin, /usr/sbin, /boot |
| Hash Algorithms | SHA256, SHA512, RMD160, GOST, SHA3-256, SHA3-512, STRIBOG256, STRIBOG512 |

---

## Baseline Initialization

```bash
sudo aide --init --config=/etc/aide/aide.conf
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

**Result:** 7,876 filesystem entries recorded in 45 seconds. Cryptographic hashes computed across 8 algorithms for every monitored file.

---

## Detection Findings

### Detection 1 — Unauthorized File Addition

**Simulated:** `sudo touch /etc/aide-test-file.txt`

```
AIDE found differences between database and filesystem!!

Summary:
  Total number of entries:      7877
  Added entries:                1
  Removed entries:              0
  Changed entries:              0

Added entries:
f++++++++++++++++++: /etc/aide-test-file.txt
```

| Field | Detail |
|---|---|
| Detection Type | File Addition |
| AIDE Notation | f++++++++++++++++++ (f = file; all + = all attributes new) |
| ATT&CK Technique | T1105 — Ingress Tool Transfer / T1505.003 — Web Shell |
| Analyst Assessment | New file in /etc not present in baseline. In a real environment this warrants immediate investigation — could represent a dropped payload, webshell, or attacker staging file. |

---

### Detection 2 — Unauthorized File Modification (/etc/hosts)

**Simulated:** `echo "# test modification" | sudo tee -a /etc/hosts`

```
AIDE found differences between database and filesystem!!

Summary:
  Total number of entries:      7877
  Added entries:                1
  Removed entries:              0
  Changed entries:              1

Changed entries:
f           H      : /etc/hosts

Detailed information about changes:
File: /etc/hosts
 SHA256    : b9nHvTh6+0RgSga/LleR36nrBYZT3aof | XTSY1HAV7EWMsc8PFXnvadtgAqX1YHzp
             mszS60o2UFU=                     | 4IVM57ZuGKU=
 SHA512    : nYSf6OiiQzVmniWFxaT+xCtBlJcavZ7h | e9WaMog5oizgTNnoGVeWG2kC14sNKsQB
 RMD160    : pa/AhlERYuFFIZelvtsD+AVaC58=     | OXrhj+24d4llFpPmrZKirSI8u7k=
 GOST      : 9nXZqbBTdGcMOrxZPHorDvVE10dlKfT1 | VRjfCuLGjKuh4eVRd37GkAom7djG1NLF
```

| Field | Detail |
|---|---|
| Detection Type | File Modification — Hash Mismatch |
| AIDE Notation | H = hash changed (confirmed across SHA256, SHA512, RMD160, GOST) |
| ATT&CK Technique | T1565.001 — Stored Data Manipulation |
| Real-World Significance | /etc/hosts modification is a high-severity finding. Attackers modify this file to redirect DNS resolution locally — enabling credential harvesting or C2 communication without touching network DNS infrastructure. |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Lab Evidence |
|---|---|---|---|
| T1565.001 | Stored Data Manipulation | Impact | /etc/hosts hash mismatch confirmed across 4 algorithms |
| T1105 | Ingress Tool Transfer | Command & Control | New file addition detected via f++++++++++++++++++ notation |
| T1505.003 | Server Software Component: Web Shell | Persistence | FIM detection of unauthorized file in monitored directory |
| T1036 | Masquerading | Defense Evasion | Multi-algorithm hashing defeats file renaming and timestamp manipulation |

---

## Key Takeaways

**Multi-algorithm hashing is the core strength:** AIDE computed 8 hash algorithms simultaneously. An attacker cannot forge all values — any tampering is cryptographically certain to be detected.

**FIM catches what endpoint detection misses:** Signature-based AV and EDR may miss novel malware and living-off-the-land techniques. AIDE doesn't care about signatures — it detects the filesystem change regardless of cause.

**/etc/hosts is a high-value target:** Modifying this file lets attackers redirect DNS without touching network infrastructure — bypassing network-based detection entirely. AIDE catches it immediately via hash mismatch.

**Compliance relevance:** FIM is a mandatory control in PCI-DSS Requirement 11.5, NIST SP 800-53 SI-7, and CIS Control 3.3.

---

## Deliverables

| File | Description |
|---|---|
| `Lab06_AIDE_FIM_Orellana.pdf` | Full lab report with detection output, findings analysis, and ATT&CK mapping |
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
| **Lab 06** | **AIDE File Integrity Monitoring** | ✅ **Complete** |
| Lab 07 | Password Analysis (John the Ripper) | 🔄 Up Next |

---

*All testing performed in an isolated VirtualBox lab environment.*
*CySA+ CS0-003 Home Lab Portfolio — github.com/[your-handle]/cysa-lab-portfolio*
