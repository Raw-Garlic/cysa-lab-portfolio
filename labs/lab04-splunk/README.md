# Lab 04 — SIEM Log Analysis: Splunk (BOTSv1 Attack Chain Discovery)

**CySA+ CS0-003 Home Lab Portfolio** | Alejandro W. Orellana  
**Cert Stack:** CompTIA Security+ | Network+ | CySA+ | Google Cybersecurity Certificate

---

## Overview

This lab demonstrates SIEM-based threat hunting and attack chain reconstruction using Splunk and the Boss of the SOC v1 (BOTSv1) dataset. The original scope targeted EventCode 4625 (failed logon) for brute-force detection. Field validation confirmed this event code was absent from the dataset — the lab was pivoted to EventCode 4688 (process creation) hunting, which revealed a fully reconstructed multi-stage attack chain embedded in the data.

---

## Lab Objectives

- Validate data availability before committing to a detection hypothesis
- Hunt for adversary activity using EventCode 4688 (process creation) analysis
- Reconstruct a complete attack chain from raw SIEM logs
- Identify and exclude false-positive noise (Splunk Universal Forwarder artifacts)
- Map confirmed adversary behaviors to MITRE ATT&CK techniques
- Document defensive controls that would have interrupted each attack phase

---

## Environment

| Field | Detail |
|---|---|
| **Tool** | Splunk Enterprise 9.3.2 (Free tier) |
| **Dataset** | BOTSv1 — Boss of the SOC v1 (github.com/splunk/botsv1) |
| **Dataset Period** | August 2016 — static historical dataset, 3.6M+ events |
| **Platform** | Windows host — Splunk running on localhost:8000 |
| **Primary EventCode** | 4688 (Process Creation) — pivoted from original 4625 (Failed Logon) |
| **Accounts of Interest** | joomla (service account), bob.smith (WAYNECORPINC domain user) |

---

## Methodology Pivot

Initial field validation query:

```splunk
index=botsv1 sourcetype=WinEventLog:Security | top EventCode
```

**Output confirmed:**

| EventCode | Description | Present |
|---|---|---|
| 4688 | Process Creation | YES — dominant event type |
| 4703 | Token Right Adjusted | YES — 8 events |
| 4624 | Successful Logon | YES |
| 4625 | Failed Logon | **NOT PRESENT** |

EventCode 4625 was not present in the BOTSv1 dataset. The dataset's attack narrative centers on web application exploitation, not credential brute-forcing. Pivoting to 4688 process-creation hunting was the correct analyst response.

---

## Investigation Phases

### Phase 1 — Process Creation Baselining

```splunk
index=botsv1 EventCode=4688
NOT New_Process_Name="*SplunkUniversalForwarder*"
| stats count by Account_Name, New_Process_Name
| sort -count
```

Excluding the Splunk Universal Forwarder path was required to remove significant noise from internal agent binaries (splunk-powershell.exe, splunk-admon.exe, etc.) that matched naive wildcards.

---

### Phase 2 — Joomla Account Activity Spike

```splunk
index=botsv1 Account_Name="joomla"
| bucket _time span=5m
| stats count by _time
| sort _time
```

**Output (selected windows):**

| Time Window | Count | Assessment |
|---|---|---|
| 07/31 – 08/09 daily | 1–4 / window | Normal CMS baseline |
| 08/10 14:25 | 1 | Attacker begins probing |
| 08/10 14:40 | 10 | Exploit attempts increasing |
| **08/10 14:45** | **22 (PEAK)** | **RCE exploit landing** |
| 08/10 14:55 | 6 | Web shell activity begins |
| 08/10 15:00 | 20 | Continued attacker activity |

---

### Phase 3 — Exploitation Window Detail

```splunk
index=botsv1 Account_Name="joomla"
  earliest="08/10/2016:13:50:00" latest="08/10/2016:15:00:00"
| table _time, New_Process_Name, Process_Command_Line
| sort _time
```

**Key output:**

```
2016-08-10 14:55:22  cmd.exe  cmd.exe /c "echo 24365"      ← shell confirmed
2016-08-10 14:55:24  cmd.exe  cmd.exe /c "dir 2>&1"
2016-08-10 14:55:26  cmd.exe  cmd.exe /c "ls 2>&1"
2016-08-10 14:55:33  cmd.exe  cmd.exe /c "ifconfig 2>&1"
2016-08-10 14:56:18  cmd.exe  cmd.exe /c "3791.exe 2>&1"   ← payload executed
```

---

### Phase 4 — Post-Exploitation & Lateral Movement

```splunk
index=botsv1 Account_Name="joomla"
  earliest="08/10/2016:14:56:00" latest="08/10/2016:15:30:00"
| table _time, New_Process_Name, Creator_Process_Name, Process_Command_Line
| sort _time
```

```splunk
index=botsv1 Account_Name="bob.smith"
| table _time, Account_Name, New_Process_Name, Creator_Process_Name, Process_Command_Line
| sort _time
```

**Key output:**

```
2016-08-10 15:05:42  cmd.exe  cmd.exe /c "echo 63059"           ← second shell session
2016-08-10 15:20:33  cmd.exe  cmd.exe /c "move 2.jpeg imnotbatman.jpg 2>&1"  ← T1036
2016-08-10 15:21:31  cmd.exe  cmd.exe /c "exit 2>&1"

2016-08-24 09:43:21  cmd.exe  cmd.exe /V /C [obfuscated VBScript]  ← bob.smith, T1059.005
2016-08-24 09:48:21  cmd.exe  [121214.tmp executed from AppData\Roaming]
2016-08-24 09:48:41  cmd.exe  taskkill /f /im "121214.tmp" + del   ← T1070.004
```

---

## Full Attack Chain Timeline

| Timestamp | Account | Activity |
|---|---|---|
| 08/10 14:40–14:46 | joomla | php-cgi.exe exploitation burst (CVE-2015-8562) |
| 08/10 14:55:22 | joomla | Web shell confirmed — `echo 24365` |
| 08/10 14:55:24–33 | joomla | Blind recon: `dir`, `ls`, `ifconfig` |
| 08/10 14:56:18 | joomla | Payload executed: `3791.exe` |
| 08/10 14:58–15:05 | joomla | 7-minute silent gap — C2/persistence activity |
| 08/10 15:05:42 | joomla | Second shell session — `echo 63059` |
| 08/10 15:20:33 | joomla | File masquerading — `imnotbatman.jpg` (T1036) |
| 08/10 15:21:31 | joomla | Attacker exits cleanly |
| 08/24 09:43:21 | bob.smith | Obfuscated VBScript dropper executed (T1059.005) |
| 08/24 09:48:21 | bob.smith | Secondary payload executed from AppData\Roaming |
| 08/24 09:48:41 | bob.smith | Anti-forensics: taskkill + file deletion (T1070.004) |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Observed Evidence |
|---|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access | Joomla php-cgi.exe burst — CVE-2015-8562 |
| T1059.003 | Windows Command Shell | Execution | joomla account spawning cmd.exe via web shell |
| T1082 | System Information Discovery | Discovery | dir, ls, ifconfig post-shell recon |
| T1036 | Masquerading | Defense Evasion | imnotbatman.jpg disguising executable payload |
| T1059.005 | VBScript | Execution | Obfuscated VBS dropper under bob.smith |
| T1070.004 | File Deletion | Defense Evasion | taskkill + del of payload after execution |
| T1078 | Valid Accounts | Persistence / Lateral Movement | joomla service account + bob.smith/WAYNECORPINC |

---

## Key Findings

**Field validation before query-building prevented a dead end.** The lab guide's original brute-force detection approach (EventCode 4625) would have produced zero results. Running `| top EventCode` first confirmed which detection surfaces were actually available — a standard analyst practice that saved significant investigative time.

**The joomla service account should never spawn cmd.exe.** The single highest-fidelity detection opportunity in this entire attack chain was a service account launching an interactive shell. A simple Splunk alert on this behavior would have fired at 14:55:22 — the first second of adversary shell access.

**The 7-minute silent gap is a visibility problem, not a false negative.** EventCode 4688 only captures process creation. Whatever 3791.exe did between 14:58 and 15:05 — network connections, file writes, registry changes — required additional telemetry sources (Sysmon Event ID 3 for network connections, Event ID 11 for file creation) to observe. Single-source log analysis has inherent blind spots.

**14 days elapsed between initial access and lateral movement.** The attacker had persistent access from 08/10 through 08/24 before pivoting to bob.smith. This dwell time represents a detection failure — the imnotbatman.jpg masqueraded payload or another persistence mechanism established during the 08/10 intrusion maintained access undetected for two weeks.

---

## Defensive Controls

| Control | Mitigation |
|---|---|
| Patch Management | Joomla 3.4.6+ patches CVE-2015-8562. Web-facing CMS platforms require aggressive patch cycles. |
| Web Application Firewall | WAF rules blocking unusual php-cgi.exe invocation patterns disrupt initial access. |
| Service Account Hardening | AppLocker/WDAC policy blocking cmd.exe execution under service accounts (joomla, IUSR, etc.) stops web shell activity at the OS level. |
| Process Creation Alerting | Real-time Splunk alert: `Account_Name=joomla New_Process_Name=*cmd.exe*` — would have fired at 14:55:22. |
| File Extension Monitoring | Alert on .exe files renamed to image extensions — catches T1036 masquerading at staging. |
| Script Block Logging | Windows Script Host logging captures obfuscated VBScript content at execution — defeats T1059.005 obfuscation. |
| EDR Coverage | Execute-then-delete within seconds is a high-confidence malicious indicator. EDR tools flag this pattern automatically. |
| Network Segmentation | Web server should not have had network access to bob.smith's workstation. DMZ segmentation limits lateral movement. |

---

## Deliverables

| File | Description |
|---|---|
| `Lab04_Splunk_BOTSv1_Orellana.pdf` | Full lab report with attack chain timeline, SPL queries, findings, ATT&CK mapping, and defensive controls |
| `README.md` | This file |

---

## Lab Series Navigation

| Lab | Topic | Status |
|---|---|---|
| Lab 01 | Nmap Network Reconnaissance | ✅ Complete |
| Lab 02 | Wireshark Traffic Analysis | ✅ Complete |
| Lab 03 | Nessus Vulnerability Scanning | ✅ Complete |
| **Lab 04** | **Splunk SIEM Analysis (BOTSv1 Attack Chain)** | ✅ **Complete** |
| Lab 05 | MITRE ATT&CK Threat Intelligence | ✅ Complete |
| Lab 06 | AIDE File Integrity Monitoring | ✅ Complete |
| Lab 07 | John the Ripper Password Analysis | ✅ Complete |
| Lab 08 | Nikto Web Vulnerability Scanning | 🔄 Up Next |

---

*All analysis performed against the BOTSv1 dataset in an isolated lab environment. No live systems were targeted.*  
*CySA+ CS0-003 Home Lab Portfolio — github.com/Raw-Garlic/cysa-lab-portfolio*
