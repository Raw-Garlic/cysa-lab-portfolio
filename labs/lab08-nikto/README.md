# Lab 08 — Web Vulnerability Scanning: Nikto

**CySA+ CS0-003 Home Lab Portfolio** | Alejandro W. Orellana  
**Cert Stack:** CompTIA Security+ | Network+ | CySA+ | Google Cybersecurity Certificate

---

## Overview

This lab demonstrates web application vulnerability scanning using Nikto against Metasploitable2's Apache web server. Nikto completed 8,910 requests in 22 seconds and identified 27 findings — including critical credential exposure, database admin interface access, and multiple EOL software components. All findings are mapped to MITRE ATT&CK and cross-referenced against Labs 03, 04, and 07.

---

## Scan Details

| Field | Detail |
|---|---|
| **Tool** | Nikto v2.5.0 |
| **Target** | 192.168.40.3 (Metasploitable2) — Port 80 |
| **Web Server** | Apache/2.2.8 (Ubuntu) DAV/2 — EOL |
| **PHP Version** | PHP/5.2.4-2ubuntu5.10 — EOL |
| **Scan Duration** | 22 seconds |
| **Requests Made** | 8,910 |
| **Total Findings** | 27 items |

---

## Scan Command

```bash
nikto -h 192.168.40.3 -port 80 -o /tmp/nikto_scan.txt -Format txt
```

---

## Findings Summary by Severity

| Severity | Count | Key Findings |
|---|---|---|
| 🔴 CRITICAL | 3 | wp-config.php credentials, phpinfo() exposed, phpMyAdmin accessible |
| 🟠 HIGH | 7 | Apache EOL, PHP EOL, HTTP TRACE/XST, directory indexing (3 dirs), ETag inode leak |
| 🟡 MEDIUM | 13 | Missing security headers, PHP query string disclosure (x4), mod_negotiation, phpMyAdmin files |
| ⚪ LOW | 4 | Junk HTTP methods, test directory, duplicate references |

---

## Critical Findings Detail

### 1. wp-config.php Exposed
```
GET /#wp-config.php#: file found — contains database credentials
```
WordPress configuration file accessible via HTTP. Contains plaintext database hostname, name, username, and password. No exploitation required — direct credential theft.

### 2. phpinfo() Exposed
```
GET /phpinfo.php: phpinfo() output found (CWE-552)
```
Full PHP and server configuration disclosed including: PHP version, loaded modules, server filesystem paths, environment variables. Complete reconnaissance map for an attacker.

### 3. phpMyAdmin Accessible
```
GET /phpMyAdmin/: directory found — no access restriction
```
Database administration interface exposed to the network with no IP restriction or authentication beyond application-level login. Combined with wp-config.php credentials = full database compromise.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Nikto Finding |
|---|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access | Apache 2.2.8 EOL + PHP 5.2.4 EOL |
| T1592.002 | Gather Victim Host Info: Software | Reconnaissance | phpinfo.php full server disclosure |
| T1083 | File and Directory Discovery | Discovery | Directory indexing on /doc/, /test/, /icons/ |
| T1552.001 | Credentials in Files | Credential Access | wp-config.php plaintext DB credentials |
| T1505.003 | Server Software Component: Web Shell | Persistence | phpMyAdmin persistent database access |
| T1040 | Network Sniffing / Session Hijacking | Credential Access | HTTP TRACE enables XST cookie theft |

---

## Cross-Lab Connections

| Lab 08 Finding | Prior Lab | Connection |
|---|---|---|
| PHP 5.2.4 EOL | Lab 04 BOTSv1 | Exact PHP version in CVE-2015-8562 Joomla exploit chain |
| Apache 2.2.8 EOL | Lab 03 Ubuntu EOL (CVSS 10.0) | Same pattern — EOL = permanent unmitigated exposure |
| Directory indexing (T1083) | Lab 03 NFS World-Readable | Same technique, different protocol |
| wp-config.php credentials | Lab 07 John the Ripper | Plaintext credentials eliminate need for cracking entirely |

---

## Remediation Priority

| Priority | Action |
|---|---|
| IMMEDIATE | Remove wp-config.php from web root or restrict via .htaccess |
| IMMEDIATE | Delete phpinfo.php — never expose in production |
| IMMEDIATE | Restrict phpMyAdmin to localhost or VPN — never open network |
| CRITICAL | Upgrade Apache 2.2.8 → 2.4.x (EOL since 2017) |
| CRITICAL | Upgrade PHP 5.2.4 → 8.x (EOL since 2011) |
| HIGH | Disable HTTP TRACE — add `TraceEnable off` to Apache config |
| HIGH | Disable directory indexing — add `Options -Indexes` globally |
| MEDIUM | Add X-Frame-Options and X-Content-Type-Options security headers |

---

## Deliverables

| File | Description |
|---|---|
| `Lab08_Nikto_Orellana.pdf` | Full lab report — all 27 findings, priority detail, ATT&CK mapping, cross-lab connections, remediation |
| `nikto_scan.txt` | Raw Nikto output (saved during scan) |
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
| Lab 07 | John the Ripper Password Analysis | ✅ Complete |
| **Lab 08** | **Nikto Web Vulnerability Scanning** | ✅ **Complete** |
| Lab 09 | Suricata IDS/IPS | 🔄 Up Next |

---

*All testing performed in an isolated VirtualBox lab environment. No systems were harmed.*  
*CySA+ CS0-003 Home Lab Portfolio — github.com/[your-handle]/cysa-lab-portfolio*
