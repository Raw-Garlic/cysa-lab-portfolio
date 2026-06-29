#!/bin/bash
# Lab 10 — iptables Firewall Rules
# Analyst: Alejandro W. Orellana
# CySA+ Home Lab Portfolio

# ── Flush existing rules ──────────────────────────────
iptables -F
iptables -X

# ── Default policies ──────────────────────────────────
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# ── Allow loopback ────────────────────────────────────
iptables -A INPUT -i lo -j ACCEPT

# ── Allow established/related connections ─────────────
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ── Allow SSH inbound (port 22) ───────────────────────
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# ── Allow HTTP inbound (port 80) ──────────────────────
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# ── Allow HTTPS inbound (port 443) ────────────────────
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# ── Block specific host (Metasploitable2) ─────────────
iptables -A INPUT -s 192.168.40.3 -j DROP

# ── Allow ICMP (ping) ─────────────────────────────────
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# ── Log dropped packets ───────────────────────────────
iptables -A INPUT -j LOG --log-prefix "IPT-DROP: " --log-level 4

echo "Lab 10 iptables rules applied successfully."
iptables -L -v -n
