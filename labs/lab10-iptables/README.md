# Lab 10 — Firewall Configuration: iptables

**CySA+ CS0-003 Home Lab Portfolio** | Alejandro W. Orellana  
**Cert Stack:** CompTIA Security+ | Network+ | CySA+ | Google Cybersecurity Certificate

---

## Overview

This lab demonstrates host-based firewall configuration using iptables on Kali Linux. An 8-rule default-deny INPUT policy was implemented covering stateful connection tracking, service allowlisting, host-specific blocking, and drop logging. The drop log immediately captured real external traffic — providing an unplanned but authentic forensic analysis scenario.

---

## Environment

| Field | Detail |
|---|---|
| **Tool** | iptables v1.8.11 (nf_tables backend) |
| **Platform** | Kali Linux — 192.168.40.7 (eth0) |
| **Host Blocked** | Metasploitable2 — 192.168.40.3 |
| **Default Policy** | INPUT: DROP \| FORWARD: DROP \| OUTPUT: ACCEPT |
| **Rules Applied** | 8 rules across INPUT chain |
| **Drop Logging** | IPT-DROP: prefix via kernel log |

---

## Firewall Rule Script

```bash
#!/bin/bash
# Lab 10 — iptables Firewall Rules
# Analyst: Alejandro W. Orellana

# Flush existing rules
iptables -F
iptables -X

# Default policies — default deny inbound
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established/related connections (stateful tracking)
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH inbound
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP inbound
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Allow HTTPS inbound
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Block Metasploitable2 inbound
iptables -A INPUT -s 192.168.40.3 -j DROP

# Allow ICMP ping
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Log all remaining dropped packets
iptables -A INPUT -j LOG --log-prefix "IPT-DROP: " --log-level 4
```

---

## Applied Ruleset

| Order | Rule | Action | Rationale |
|---|---|---|---|
| 1 | Default INPUT policy | DROP | Default-deny — block everything not explicitly allowed |
| 2 | Default FORWARD policy | DROP | Not a router — no packet forwarding |
| 3 | Default OUTPUT policy | ACCEPT | Unrestricted outbound for analyst workstation |
| 4 | Loopback (lo) | ACCEPT | Required for local services |
| 5 | ESTABLISHED/RELATED | ACCEPT | Stateful — allow return traffic for outbound sessions |
| 6 | TCP port 22 | ACCEPT | SSH administrative access |
| 7 | TCP port 80 | ACCEPT | HTTP inbound |
| 8 | TCP port 443 | ACCEPT | HTTPS inbound |
| 9 | Source 192.168.40.3 | DROP | Block Metasploitable2 inbound connections |
| 10 | ICMP echo-request | ACCEPT | Allow ping |
| 11 | All remaining INPUT | LOG | Log dropped packets with IPT-DROP: prefix |

---

## Post-Configuration State

```
Chain INPUT (policy DROP)
 ACCEPT     all  --  lo    *    0.0.0.0/0    0.0.0.0/0
 ACCEPT     all  --  *     *    0.0.0.0/0    0.0.0.0/0    ctstate RELATED,ESTABLISHED
 ACCEPT     tcp  --  *     *    0.0.0.0/0    0.0.0.0/0    tcp dpt:22
 ACCEPT     tcp  --  *     *    0.0.0.0/0    0.0.0.0/0    tcp dpt:80
 ACCEPT     tcp  --  *     *    0.0.0.0/0    0.0.0.0/0    tcp dpt:443
 DROP       all  --  *     *    192.168.40.3 0.0.0.0/0
 ACCEPT     icmp --  *     *    0.0.0.0/0    0.0.0.0/0    icmptype 8
 LOG        all  --  *     *    0.0.0.0/0    0.0.0.0/0    LOG prefix "IPT-DROP: "

Chain FORWARD (policy DROP)
Chain OUTPUT (policy ACCEPT)
```

---

## Drop Log Analysis

The IPT-DROP logging rule immediately captured real traffic within minutes of application:

```
[ 3964.178803] IPT-DROP: IN=eth0 SRC=140.82.114.26 DST=192.168.40.7
  PROTO=TCP SPT=443 DPT=39698 ACK PSH
```

| Field | Value | Analysis |
|---|---|---|
| Source IP | 140.82.114.26 | GitHub CDN server |
| Source Port | 443 (HTTPS) | Return traffic from previous git push |
| Root Cause | State table expiry | conntrack entry expired before return packets arrived |
| Threat Level | None — benign | Expected GitHub return traffic |

This is a real-world firewall tuning scenario — demonstrating that stateful tracking requires conntrack timeout values appropriate for the connection type.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Lab Relevance |
|---|---|---|---|
| T1562.004 | Disable/Modify Firewall | Defense Evasion | Attackers disable iptables post-exploitation — understanding rule structure enables detecting unauthorized changes |
| T1040 | Network Sniffing | Credential Access | Default-deny prevents unsolicited inbound C2 traffic on arbitrary ports |
| T1046 | Network Service Discovery | Discovery | Host-block rule prevents Metasploitable2 from probing Kali's open ports |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | OUTPUT ACCEPT is intentionally permissive — production hardening would also restrict egress |

---

## Deliverables

| File | Description |
|---|---|
| `lab10_rules.sh` | Documented firewall rule script |
| `lab10_rules_backup.txt` | iptables-save output — production restore format |
| `lab10_drop_log.txt` | Raw IPT-DROP kernel log entries |
| `Lab10_iptables_Orellana.pdf` | Full lab report with rule analysis, drop log forensics, ATT&CK mapping |
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
| Lab 09 | Suricata IDS/IPS | ✅ Complete |
| **Lab 10** | **iptables Firewall Configuration** | ✅ **Complete** |
| Lab 11 | OpenVAS Vulnerability Assessment | 🔄 Up Next |
| Lab 12 | Capstone — Operation BlueShield | ⏳ Pending |

---

*All testing performed in an isolated VirtualBox lab environment. No systems were harmed.*  
*CySA+ CS0-003 Home Lab Portfolio — github.com/[your-handle]/cysa-lab-portfolio*
