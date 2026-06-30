# CySA+ CS0-003 Home Lab Portfolio
### Alejandro W. Orellana

**Cert Stack:** CompTIA Security+ | Network+ | CySA+ (June 2026) | Google Cybersecurity Certificate  
**Background:** 13-year federal employee (DHS/TSA, GS-07) | Transitioning into cybersecurity  
**Target Roles:** SOC Analyst | GRC Analyst | Information Security Analyst | Threat Intelligence  
**Location:** Los Angeles / Southern California

---

## About This Portfolio

This repository documents a 12-lab hands-on cybersecurity home lab built to complement the CompTIA CySA+ CS0-003 certification. Every lab was performed in an isolated VirtualBox environment on Kali Linux against intentionally vulnerable targets, with findings documented, mapped to MITRE ATT&CK, and written up as professional deliverables.

The portfolio is designed to demonstrate not just tool familiarity but analyst-level thinking: understanding *why* a finding matters, connecting it to a threat actor's known tradecraft, and producing documentation that communicates findings clearly to both technical and non-technical audiences.

---

## Lab Environment

| Component | Detail |
|---|---|
| **Host Machine** | ASUS ROG Gaming A16 |
| **Hypervisor** | VirtualBox |
| **Attacker VM** | Kali Linux |
| **Target VM** | Metasploitable2 (192.168.40.3) |
| **SIEM Dataset** | Splunk BOTSv1 (Boss of the SOC v1) |
| **Network** | Host-only isolated network — no external exposure |

---

## Lab Series Overview

| # | Lab | Tools | Key Skills Demonstrated |
|---|---|---|---|
| 01 | Network Reconnaissance | Nmap | Host discovery, port scanning, service enumeration, OS fingerprinting |
| 02 | Traffic Analysis | Wireshark | Packet capture, protocol analysis, credential exposure in cleartext |
| 03 | Vulnerability Scanning | Nessus Essentials | CVE identification, CVSS scoring, vulnerability prioritization, remediation planning |
| 04 | SIEM Investigation | Splunk, BOTSv1 | SPL query authoring, process creation hunting, multi-stage attack chain reconstruction |
| 05 | Threat Intelligence | MITRE ATT&CK, ATT&CK Navigator | Threat actor profiling, TTP mapping, confidence scoring, vulnerability crosswalk |
| 06 | File Integrity Monitoring | AIDE | Baseline establishment, hash-based change detection, cryptographic verification |
| 07 | Password Analysis | John the Ripper | Credential extraction, wordlist vs brute force comparison, defensive controls |
| 08 | Web Vulnerability Scanning | Nikto | Web application reconnaissance, credential exposure, EOL software detection |
| 09 | Intrusion Detection | Suricata 8.0.5 | Custom rule authoring, live traffic detection, alert analysis, IDS vs IPS |
| 10 | Firewall Configuration | iptables | Default-deny policy, stateful tracking, host blocking, drop logging |
| 11 | Vulnerability Assessment | OpenVAS/GVM | Authenticated scanning, NVT-based detection, report generation |
| 12 | Capstone | All tools | Operation BlueShield — end-to-end incident simulation |

---

## Highlighted Findings

### Lab 04 — BOTSv1 Attack Chain (Splunk)
Independent SIEM investigation uncovered a complete multi-stage Joomla exploitation chain from the BOTSv1 dataset after pivoting away from a broken lab premise. Seven ATT&CK techniques mapped from real log data:

| Timestamp | Account | Activity | ATT&CK |
|---|---|---|---|
| 08/10 14:45 | joomla | PHP-CGI spike — RCE landing | T1190 |
| 08/10 14:55 | joomla | Web shell confirmed, blind recon | T1059.003, T1082 |
| 08/10 15:21 | joomla | imnotbatman.jpg payload masquerade | T1036 |
| 08/24 09:43 | bob.smith | Obfuscated VBScript dropper | T1059.005 |
| 08/24 09:48 | bob.smith | taskkill + del anti-forensics cleanup | T1070.004 |

### Lab 05 — APT29 Threat Profile + Nessus Crosswalk
Full threat actor profile built for APT29 (Cozy Bear / G0016) sourced from MITRE, CISA, NCSC, Mandiant, and Google TI. ATT&CK Navigator layer exported with confidence-scored techniques. Two techniques (T1078, T1070) scored at confidence 3 — confirmed via independent BOTSv1 investigation in Lab 04.

### Lab 08 — Nikto Web Scan
27 findings in 22 seconds against Metasploitable2's Apache server including:
- **wp-config.php** accessible via HTTP GET — plaintext database credentials exposed
- **phpinfo()** exposed — complete server configuration disclosed
- **phpMyAdmin** open to network — full database admin access with no IP restriction
- **PHP 5.2.4 EOL** — the exact version exploited in CVE-2015-8562 (Lab 04 BOTSv1 attack chain)

### Lab 09 — Suricata Custom Rules
3 analyst-authored detection rules triggered 19 alerts across ICMP, HTTP, and SSH traffic. Key finding: SSH connection attempt detected even though the session failed — demonstrating IDS detection at the network layer, not application layer.

### Lab 10 — iptables Drop Log
Default-deny firewall policy immediately captured real external traffic — GitHub CDN return packets dropped due to connection state table expiry, demonstrating stateful tracking requirements in a default-deny environment.

---

## MITRE ATT&CK Coverage

Techniques confirmed across this lab portfolio:

| Technique ID | Name | Confirmed In |
|---|---|---|
| T1046 | Network Service Discovery | Lab 01, Lab 09 |
| T1040 | Network Sniffing | Lab 02, Lab 09, Lab 10 |
| T1190 | Exploit Public-Facing Application | Lab 03, Lab 05, Lab 08 |
| T1003 | OS Credential Dumping | Lab 07 |
| T1110.002 | Brute Force: Password Cracking | Lab 07 |
| T1059.003 | Windows Command Shell | Lab 04 |
| T1078 | Valid Accounts | Lab 04, Lab 05, Lab 07, Lab 08 |
| T1082 | System Information Discovery | Lab 04 |
| T1036 | Masquerading | Lab 04 |
| T1059.005 | Visual Basic | Lab 04 |
| T1070.004 | File Deletion | Lab 04, Lab 05 |
| T1592.002 | Gather Victim Host Info: Software | Lab 08 |
| T1083 | File and Directory Discovery | Lab 03, Lab 08 |
| T1552.001 | Credentials in Files | Lab 08 |
| T1505.003 | Server Software Component: Web Shell | Lab 03, Lab 08 |
| T1557 | Adversary-in-the-Middle | Lab 03, Lab 08 |
| T1021 | Remote Services | Lab 03 |
| T1021.004 | Remote Services: SSH | Lab 09 |
| T1105 | Ingress Tool Transfer | Lab 06 |
| T1565.001 | Stored Data Manipulation | Lab 06 |
| T1562.004 | Disable/Modify Firewall | Lab 10 |

---

## Deliverables Per Lab

Each completed lab folder contains:
- **PDF report** — professional write-up with findings, methodology, ATT&CK mapping, and remediation
- **README.md** — GitHub-formatted documentation with commands, output, and analysis
- **Raw artifacts** — scan outputs, rule files, log captures, config files

---

## Professional Background

I bring a unique combination of federal security experience and technical cybersecurity training to this portfolio:

- **13 years DHS/TSA** — Transportation Security Officer at LAX, formerly Lead TSO (GS-09)
- **Federal background investigation** — a genuine competitive differentiator for cleared contractor roles
- **Security regulatory compliance** — direct experience with federal security frameworks and TSA security programs
- **B.A. Cinema Television & Video Arts** — CSUN 2011

The cybersecurity transition is deliberate — targeting roles in the LA/Southern California defense corridor where federal background and technical skills combine.

---

## Contact

**GitHub:** github.com/Raw-Garlic  
**LinkedIn:** linkedin.com/in/alejandro-orellana-278b51235  
**Target locations:** El Segundo | Long Beach | Anaheim | Hawthorne | Inglewood

---

*All lab work performed in an isolated VirtualBox environment. No unauthorized systems were accessed.*  
*Portfolio actively updated as labs complete — Lab 11 (OpenVAS) and Lab 12 (Capstone) in progress.*
