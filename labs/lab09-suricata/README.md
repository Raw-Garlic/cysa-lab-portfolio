# Lab 09 — Network Intrusion Detection: Suricata IDS

**CySA+ CS0-003 Home Lab Portfolio** | Alejandro W. Orellana  
**Cert Stack:** CompTIA Security+ | Network+ | CySA+ | Google Cybersecurity Certificate

---

## Overview

This lab demonstrates network intrusion detection using Suricata 8.0.5 in IDS mode. Suricata was installed, configured with 50,882 Emerging Threats rules, and extended with 3 analyst-authored custom rules targeting ICMP reconnaissance, HTTP traffic, and SSH connection attempts against Metasploitable2. All 3 rules fired successfully generating 19 alerts.

---

## Environment

| Field | Detail |
|---|---|
| **Tool** | Suricata 8.0.5 (IDS mode — passive pcap capture) |
| **Monitor Interface** | eth0 — 192.168.40.7/24 |
| **Target** | Metasploitable2 — 192.168.40.3 |
| **Ruleset** | Emerging Threats Open — 66,813 rules, 50,882 enabled |
| **Custom Rules** | 3 analyst-authored rules (SID 9000001–9000003) |
| **Alert Output** | fast.log + eve.json |
| **Total Alerts** | 19 across 3 rules |

---

## Setup Commands

```bash
# Install Suricata
sudo apt install suricata -y

# Update rules from Emerging Threats
sudo suricata-update

# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Run in IDS mode
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -D --pidfile /var/run/suricata.pid
```

---

## Custom Detection Rules

```
# Rule 1 — ICMP Reconnaissance Detection
alert icmp any any -> any any (msg:"ICMP Ping Detected - Lab 09"; icode:0; itype:8; sid:9000001; rev:1;)

# Rule 2 — HTTP Traffic to Target
alert tcp any any -> 192.168.40.3 80 (msg:"HTTP Traffic to Metasploitable2 - Lab 09"; flow:to_server,established; sid:9000002; rev:1;)

# Rule 3 — SSH Connection Attempt
alert tcp any any -> 192.168.40.3 22 (msg:"SSH Connection Attempt to Metasploitable2 - Lab 09"; flow:to_server; sid:9000003; rev:1;)
```

| SID | Rule | Protocol | Detection Logic | SOC Use Case |
|---|---|---|---|---|
| 9000001 | ICMP Ping Detected | ICMP | itype:8 echo request | Host discovery / recon |
| 9000002 | HTTP to Metasploitable2 | TCP/80 | flow:to_server,established | Web attack detection |
| 9000003 | SSH Connection Attempt | TCP/22 | flow:to_server | Lateral movement detection |

---

## Alert Results

Traffic generated: `ping -c 5`, `curl http://192.168.40.3`, `ssh root@192.168.40.3`

```
06/29/2026-13:05:24 [**] [1:9000001:1] ICMP Ping Detected - Lab 09 [**]
  {ICMP} 192.168.40.7:8 -> 192.168.40.3:0
  ... (5 alerts total — one per ping packet)

06/29/2026-13:05:39 [**] [1:9000002:1] HTTP Traffic to Metasploitable2 - Lab 09 [**]
  {TCP} 192.168.40.7:54018 -> 192.168.40.3:80
  ... (6 alerts total — across HTTP flow packets)

06/29/2026-13:05:58 [**] [1:9000003:1] SSH Connection Attempt to Metasploitable2 - Lab 09 [**]
  {TCP} 192.168.40.7:39918 -> 192.168.40.3:22
  ... (8 alerts total — SSH key negotiation packets)
```

| Rule SID | Alerts Fired | Result |
|---|---|---|
| 9000001 — ICMP | 5 | ✅ Detected |
| 9000002 — HTTP | 6 | ✅ Detected |
| 9000003 — SSH | 8 | ✅ Detected |
| **Total** | **19** | **3 of 3 rules triggered** |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Suricata Detection |
|---|---|---|---|
| T1046 | Network Service Discovery | Discovery | Rule 9000001 — ICMP host discovery |
| T1040 | Network Sniffing | Credential Access | Passive eth0 monitoring capability |
| T1190 | Exploit Public-Facing Application | Initial Access | Rule 9000002 — HTTP to vulnerable web server |
| T1021.004 | Remote Services: SSH | Lateral Movement | Rule 9000003 — SSH connection attempts |

---

## Key Findings

**IDS detects at the network layer, not application layer** — the SSH connection failed due to key type mismatch, but Suricata still generated 8 alerts on the TCP packets. Failed attacks are still detectable.

**Multiple alerts per session is expected** — Suricata fires per packet, not per session. Production SOCs use threshold tuning and alert aggregation to manage volume.

**IDS vs IPS:** This lab ran Suricata in passive IDS mode (`-i eth0`). IPS mode (`-q 0` with NFQUEUE) would actively drop malicious traffic using `drop` rules instead of `alert` rules.

---

## IDS vs IPS Comparison

| Capability | IDS Mode (This Lab) | IPS Mode (Inline) |
|---|---|---|
| Traffic handling | Passive — monitors copy | Inline — traffic passes through |
| Alert action | Log only | Alert + drop/reject |
| Network impact | Zero latency | Minor inspection latency |
| Rule keyword | `alert` | `drop` / `reject` |
| Suricata flag | `-i eth0` | `-q 0` (NFQUEUE) |

---

## Deliverables

| File | Description |
|---|---|
| `Lab09_Suricata_IDS_Orellana.pdf` | Full lab report with rule analysis, alert output, ATT&CK mapping, IDS vs IPS comparison |
| `lab09_alerts.txt` | Raw fast.log output from live detection session |
| `lab09_eve.json` | Structured JSON alert log (eve.json format) |
| `local.rules` | Custom analyst-authored detection rules |
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
| Lab 08 | Nikto Web Vulnerability Scanning | ✅ Complete |
| **Lab 09** | **Suricata IDS/IPS** | ✅ **Complete** |
| Lab 10 | iptables Firewall Rules | 🔄 Up Next |

---

*All testing performed in an isolated VirtualBox lab environment. No systems were harmed.*  
*CySA+ CS0-003 Home Lab Portfolio — github.com/[your-handle]/cysa-lab-portfolio*
