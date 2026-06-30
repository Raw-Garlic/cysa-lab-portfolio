# Lab 05 — MITRE ATT&CK Threat Intelligence: APT29

**CySA+ CS0-003 Home Lab Portfolio** | Alejandro W. Orellana  
**Cert Stack:** CompTIA Security+ | Network+ | CySA+ | Google Cybersecurity Certificate

---

## Overview

This lab focuses on threat intelligence methodology using APT29 (Cozy Bear) as the target threat actor. The objective was to research a real-world nation-state adversary, build a structured threat profile, map confirmed TTPs into ATT&CK Navigator, and crosswalk those techniques against the Nessus vulnerabilities discovered in Lab 03 — connecting vulnerability management data to a live threat actor profile.

---

## Lab Objectives

- Research APT29 (G0016) using MITRE ATT&CK and open-source threat intelligence
- Identify high-confidence TTPs across the full attack lifecycle
- Build a structured threat profile document
- Create and export an ATT&CK Navigator layer with confidence-scored techniques
- Map Lab 03 Nessus findings to APT29 techniques (threat-informed vulnerability prioritization)

---

## Threat Actor Summary

| Field | Detail |
|---|---|
| **Group** | APT29 / Cozy Bear |
| **MITRE ID** | G0016 |
| **Also Known As** | Midnight Blizzard, NOBELIUM, The Dukes, UNC2452, Dark Halo |
| **Attribution** | Russia's Foreign Intelligence Service (SVR) |
| **Active Since** | At least 2008 |
| **Primary Objective** | Intelligence collection in support of Russian foreign policy |
| **Confidence** | High — attributed by NSA, FBI, UK NCSC, and allied agencies |

APT29 is characterized by extreme patience, long dwell times, and a shift toward cloud-native tradecraft. Unlike financially motivated actors, they prioritize stealth and persistence over speed — often maintaining access for months or years without triggering detection.

---

## ATT&CK Navigator Layer

**Layer file:** `apt29_navigator_layer.json`  
**ATT&CK Version:** 19 | **Navigator Version:** 5.3.2

### Color Legend

| Color | Meaning |
|---|---|
| 🟡 Yellow | Score 3 — Confirmed via independent BOTSv1 SIEM investigation (Lab 04) |
| 🟠 Orange | Score 2 — High confidence, attributed in multiple threat intel reports |
| 🔵 Blue | Score 1 — Attributed in reporting, moderate confidence |
| 🔴 Red | APT29 group techniques (Navigator auto-populated from G0016) |

### Scored Techniques (Analyst-Selected)

| Technique ID | Name | Tactic | Score | Basis |
|---|---|---|---|---|
| T1078 | Valid Accounts | Persistence / Lateral Movement / Defense Evasion | 3 | Confirmed in Lab 04 — joomla service account + bob.smith/WAYNECORPINC abused in BOTSv1 attack chain |
| T1070 | Indicator Removal | Defense Evasion | 3 | Confirmed in Lab 04 — bob.smith executed taskkill + del self-cleanup (08/24 09:48:41) |
| T1059 | Command and Scripting Interpreter | Execution | 2 | High confidence — core APT29 execution technique across DNC, SolarWinds, and WINELOADER campaigns |
| T1027 | Obfuscated Files or Information | Defense Evasion | 2 | High confidence — RC4 encryption, anti-analysis hooks used in WINELOADER and BEATDROP |
| T1550 | Use Alternate Authentication Material | Lateral Movement | 2 | High confidence — Golden SAML token forgery confirmed in SolarWinds campaign |
| T1583 | Acquire Infrastructure | Resource Development | 1 | Attributed — actor-controlled domains and compromised WordPress C2 infrastructure |
| T1195 | Supply Chain Compromise | Initial Access | 1 | Attributed — SolarWinds Orion build pipeline compromise (SUNBURST, 2020) |
| T1566 | Phishing | Initial Access | 2 | High confidence — spearphishing is APT29's primary initial access vector across all major campaigns |

### Key Observation
Two techniques in this layer (T1078, T1070) are scored at confidence 3 — meaning they were independently observed during the Lab 04 BOTSv1 Splunk investigation, not sourced solely from threat intelligence reports. This provides an evidence-based foundation that connects real detection findings to a nation-state threat actor profile.

---

## Nessus / APT29 Crosswalk

Full crosswalk document: `Lab05_Nessus_APT29_Crosswalk_Orellana.pdf`

The table below maps all 8 Lab 03 Nessus findings (Metasploitable2 scan) to the APT29 techniques they would enable.

| CVE / Plugin ID | Vulnerability | CVSS | ATT&CK ID | Technique | Tactic |
|---|---|---|---|---|---|
| Nessus 201352 | Ubuntu 8.04 EOL OS | 10.0 | T1190 | Exploit Public-Facing Application | Initial Access |
| Nessus 61708 | VNC Default Password | 10.0 | T1078 | Valid Accounts | Persistence |
| CVE-2020-1745 | Apache Ghostcat (AJP RCE) | 9.8 | T1190 | Exploit Public-Facing Application | Initial Access |
| Nessus 20007 | SSL v2/v3 Detected | 9.8 | T1557 | Adversary-in-the-Middle | Credential Access |
| Nessus 51988 | Bind Shell Backdoor | 9.8 | T1505.003 | Web Shell / Backdoor | Persistence |
| CVE-1999-0651 | rlogin Service | 7.5 | T1021 | Remote Services | Lateral Movement |
| CVE-2016-2118 | Samba Badlock | 7.5 | T1557 | Adversary-in-the-Middle | Credential Access |
| Nessus 42256 | NFS World-Readable Shares | 7.5 | T1083 | File and Directory Discovery | Discovery |

### Threat-Informed Remediation Priority

Standard CVSS ordering and APT29-adjusted ordering differ on one critical point: the Bind Shell Backdoor (Nessus 51988) moves to Priority 1 in a threat-informed context because it indicates potential active compromise — all other remediation is secondary until system integrity is verified.

1. **IMMEDIATE** — Bind Shell Backdoor (active/prior compromise indicator — initiate IR process)
2. **CRITICAL** — Ubuntu 8.04 EOL OS (permanent unmitigated exposure)
3. **CRITICAL** — VNC Default Password (enables T1078 — APT29's core persistence technique)
4. **CRITICAL** — Apache Ghostcat CVE-2020-1745 (unauthenticated RCE)
5. **CRITICAL** — SSL v2/v3 (enables T1557 MitM credential interception)
6. **HIGH** — Samba Badlock CVE-2016-2118 (compounds T1557 risk)
7. **HIGH** — rlogin Service (cleartext credentials, enables lateral movement)
8. **HIGH** — NFS World-Readable Shares (enables T1083 discovery)

---

## Deliverables

| File | Description |
|---|---|
| `apt29_navigator_layer.json` | ATT&CK Navigator layer export (ATT&CK v19, Navigator 5.3.2) |
| `apt29_navigator_layer.svg` | Visual export of the Navigator matrix |
| `Lab05_APT29_Threat_Profile_Orellana.pdf` | Full 9-section APT29 threat profile document |
| `Lab05_Nessus_APT29_Crosswalk_Orellana.pdf` | Nessus-to-ATT&CK crosswalk with threat-informed remediation prioritization |

---

## Tools & References

- [MITRE ATT&CK — APT29 Group G0016](https://attack.mitre.org/groups/G0016/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [UK NCSC — SVR Cyber Actors Adapt Tactics for Initial Cloud Access (Feb 2024)](https://www.ncsc.gov.uk/)
- [Mandiant — UNC2452 Merged into APT29 (April 2022)](https://www.mandiant.com/)
- [Google Threat Intelligence — APT29 WINELOADER (March 2024)](https://cloud.google.com/blog/topics/threat-intelligence/apt29-wineloader-german-political-parties)
- [CISA Advisory AA24-057A — SVR Cloud Targeting (Feb 2024)](https://www.cisa.gov/)
- [HHS HC3 — Midnight Blizzard Threat Profile (June 2024)](https://www.hhs.gov/hc3)

---

## Lab Series Navigation

| Lab | Topic | Status |
|---|---|---|
| Lab 01 | Nmap Network Reconnaissance | ✅ Complete |
| Lab 02 | Wireshark Traffic Analysis | ✅ Complete |
| Lab 03 | Nessus Vulnerability Scanning | ✅ Complete |
| Lab 04 | Splunk SIEM Analysis (BOTSv1) | ✅ Complete |
| **Lab 05** | **MITRE ATT&CK Threat Intelligence** | ✅ **Complete** |
| Lab 06 | AIDE File Integrity Monitoring | 🔄 Up Next |

---

*All testing performed in an isolated VirtualBox lab environment. No systems were harmed.*  
*CySA+ CS0-003 Home Lab Portfolio — github.com/[your-handle]/cysa-lab-portfolio*
