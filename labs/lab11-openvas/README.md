# Lab 11 — Vulnerability Assessment: OpenVAS/GVM

**CySA+ CS0-003 Home Lab Portfolio** | Alejandro W. Orellana  
**Cert Stack:** CompTIA Security+ | Network+ | CySA+ | Google Cybersecurity Certificate

---

## Overview

This lab demonstrates enterprise vulnerability assessment using OpenVAS/GVM (Greenbone Vulnerability Management) installed and configured entirely from scratch on Kali Linux. GVM 25.04.0 was set up with the full Emerging Threats NVT feed (95,089 vulnerability tests), a Full and Fast scan was executed against Metasploitable2, and 141 findings were identified including 11 Critical. The lab also required production-level troubleshooting of the scanner infrastructure — diagnosing and resolving stale lock files, service restart sequencing, and ospd-openvas crash analysis.

---

## Environment

| Field | Detail |
|---|---|
| **Tool** | GVM 25.04.0 / OpenVAS 23.30.1 / ospd-openvas 22.10.0 |
| **Target** | Metasploitable2 — 192.168.40.3 |
| **Scan Config** | Full and fast — 4 concurrent NVTs per host |
| **NVT Database** | 95,089 NVTs (Emerging Threats Open feed) |
| **Scan Status** | Stopped at 98% — ospd-openvas socket crash (VM resource constraint) |
| **Total Findings** | 141 (11 Critical, 8 High, 33 Medium, 6 Low, 76 Log) |
| **Top Finding** | CVE-2020-1938 Ghostcat (CVSS 9.8) — Active check confirmed file read |

---

## Setup Process

```bash
# Install
sudo apt install openvas -y

# Initialize (certificates, DB, admin user)
sudo gvm-setup

# Sync NVT feed
sudo greenbone-feed-sync
sudo greenbone-nvt-sync

# Validate
sudo gvm-check-setup

# Start services
sudo gvm-start

# Access web interface
# https://127.0.0.1:9392
```

**gvm-check-setup confirmed:**
- OpenVAS Scanner 23.30.1 ✅
- NVT collection: 95,089 NVTs ✅
- SCAP/CERT data ✅
- PostgreSQL DB ✅
- All services active ✅

---

## Findings Summary

| Severity | Count | CVSS Range |
|---|---|---|
| 🔴 CRITICAL | 11 | 9.0 – 10.0 |
| 🟠 HIGH | 8 | 7.0 – 8.9 |
| 🟡 MEDIUM | 33 | 4.0 – 6.9 |
| 🔵 LOW | 6 | 0.1 – 3.9 |
| ⚪ LOG | 76 | 0.0 |
| **TOTAL** | **134** | — |

---

## Confirmed Findings (XML Export — Active Checks)

| # | Vulnerability | CVE | CVSS | Port | Evidence |
|---|---|---|---|---|---|
| 1 | Apache Tomcat AJP RCE (Ghostcat) | CVE-2020-1938 | 9.8 | 8009/tcp | Active — file read confirmed |
| 2 | awiki LFI Vulnerability | None | 5.0 | 80/tcp | Active — /etc/passwd read confirmed |
| 3 | Mail Server VRFY/EXPN Enabled | None | 5.0 | 25/tcp | Active — VRFY root response captured |
| 4 | Cleartext Password Transmission | None | 4.8 | 80/tcp | Active — password fields identified |
| 5 | Apache httpOnly Cookie Disclosure | CVE-2012-0053 | 4.3 | 80/tcp | Version + active check |
| 6 | MySQL Open Access | None | 0.0 | 3306/tcp | Log — remote access confirmed |
| 7-10 | CPE Inventory / Service Detection | None | 0.0 | general | Log — OS/service fingerprinting |

---

## Critical Finding — CVE-2020-1938 Ghostcat

```
Finding: Apache Tomcat AJP RCE Vulnerability (Ghostcat)
CVE: CVE-2020-1938 | CVSS: 9.8 (Critical) | Port: 8009/tcp

Active check result:
It was possible to read the file /WEB-INF/web.xml through the AJP connector.
Content-Type: text/html;charset=ISO-8859-1
<!-- Licensed to the Apache Software Foundation (ASF)...

Confirmed: Unauthenticated file read via AJP on 192.168.40.3:8009
```

OpenVAS performed an **active exploitation check** — not just version detection — and confirmed the vulnerability by reading a protected configuration file. This same CVE was detected by Nessus in Lab 03, making this a cross-tool confirmation.

---

## Cleartext Password Transmission Finding

```
Finding: Cleartext Transmission of Sensitive Information via HTTP
Severity: 4.8 (Medium) | Port: 80/tcp

Password fields identified at:
http://192.168.40.3/dvwa/login.php          :password
http://192.168.40.3/phpMyAdmin/             :pma_password
http://192.168.40.3/phpMyAdmin/?D=A        :pma_password
http://192.168.40.3/tikiwiki/tiki-install.php :pass
http://192.168.40.3/twiki/bin/...           :password
```

---

## Scanner Crash Root Cause Analysis

The scan stopped at 98% due to ospd-openvas crashing mid-scan. Diagnosed via log analysis:

```
WARNING: Could not connect to Scanner at /run/ospd/ospd-openvas.sock
WARNING: Connection lost with the scanner. Trying again in 1 second.
WARNING: OSP get_scan [UUID]: Failed to find scan '[UUID]'
Status changed to Stopped
```

**Root cause:** VM RAM exhaustion — 95,089 NVT checks against Metasploitable2's many open services exceeded available VM memory, causing ospd-openvas to terminate and drop its Unix socket.

**Production mitigation:** Increase VM RAM allocation, reduce concurrent NVTs per host, or deploy on a dedicated Greenbone Enterprise Appliance.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Finding |
|---|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access | CVE-2020-1938 Ghostcat — AJP file read confirmed |
| T1083 | File and Directory Discovery | Discovery | LFI at /mutillidae — /etc/passwd traversal confirmed |
| T1557 | Adversary-in-the-Middle | Credential Access | Cleartext HTTP passwords across 5 applications |
| T1040 | Network Sniffing | Credential Access | MySQL open on 3306/tcp |
| T1110.001 | Brute Force: Password Guessing | Credential Access | VRFY/EXPN enables mail user enumeration |

---

## OpenVAS vs Nessus Comparison

| Dimension | Nessus (Lab 03) | OpenVAS (Lab 11) |
|---|---|---|
| License | Commercial (free tier) | Open source |
| NVT Count | ~170,000+ plugins | 95,089 NVTs |
| Critical findings | 9 Critical | 11 Critical (at 98%) |
| CVE-2020-1938 | Detected (version) | Detected + actively confirmed |
| Scan speed | Faster | Slower on VM |

---

## Deliverables

| File | Description |
|---|---|
| `Lab11_OpenVAS_Orellana.pdf` | Full lab report — setup, findings, Ghostcat deep dive, crash analysis, ATT&CK mapping, tool comparison |
| `results-20260630.xml` | Raw OpenVAS XML export |
| `README.md` | This file |

---

## Lab Series Navigation

| Lab | Topic | Status |
|---|---|---|
| Labs 01–10 | See individual lab folders | ✅ Complete |
| **Lab 11** | **OpenVAS Vulnerability Assessment** | ✅ **Complete** |
| Lab 12 | Capstone — Operation BlueShield | 🔄 Up Next |

---

*All testing performed in an isolated VirtualBox lab environment. No systems were harmed.*  
*CySA+ CS0-003 Home Lab Portfolio — github.com/Raw-Garlic/cysa-lab-portfolio*
