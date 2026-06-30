# Lab 04 (Revised) — Log Analysis & SIEM Queries with Splunk
**CySA+ Domain:** Security Operations & Vulnerability Management — Log Analysis
**Dataset:** Splunk BOTSv1 (Boss of the SOC v1)
**Tools:** Splunk Free

## Revision Note

The original lab scope targeted EventCode 4625 (failed logon) to demonstrate brute-force
detection. Field analysis (`| top EventCode`) confirmed this event code was not present in
the BOTSv1 dataset — the available Windows Security EventCodes were 4624, 4634, 4674, 4688,
4689, and 4703, with 4688 (process creation) and 4703 (token right adjusted) accounting for
~79% of events. The lab was pivoted to focus on EventCode 4688 process-creation hunting,
with emphasis on PowerShell-based attack chain indicators, since this better matches the
actual investigative surface available in this dataset.

---

## Step 1 — Confirm scope and time range

```
index=botsv1 | stats count by sourcetype
```
Confirm you're pointed at the right index/sourcetype before building queries. Set the time
range picker to **All Time** — BOTSv1 is a static dataset from August 2017, not live traffic.

## Step 2 — Baseline process creation volume

```
index=botsv1 EventCode=4688
| stats count by New_Process_Name
| sort -count
```
This surfaces every process spawned in the environment, ranked by frequency. Scan for
anything unexpected running on a workstation — script interpreters, admin tools, or
unfamiliar binaries.

## Step 3 — Isolate PowerShell process creation

```
index=botsv1 EventCode=4688 New_Process_Name="*powershell.exe*"
| table _time, Account_Name, Creator_Process_Name, New_Process_Name, Process_Command_Line
| sort _time
```
PowerShell is one of the most common living-off-the-land tools attackers use post-compromise.
This pulls every PowerShell launch with its parent process and full command line — the
command line field is where encoded payloads, download cradles, or suspicious flags
(`-enc`, `-nop`, `-w hidden`, `-exec bypass`) will show up.

## Step 4 — Flag suspicious PowerShell command-line flags

```
index=botsv1 EventCode=4688 New_Process_Name="*powershell.exe*"
| regex Process_Command_Line="(?i)(-enc|-encodedcommand|-nop|-noprofile|-w hidden|-windowstyle hidden|-exec bypass|downloadstring|invoke-expression|iex)"
| table _time, Account_Name, Creator_Process_Name, Process_Command_Line
```
This is a classic detection pattern for obfuscated or defense-evading PowerShell usage —
each of these flags/strings is a documented technique under MITRE ATT&CK T1059.001
(Command and Scripting Interpreter: PowerShell).

## Step 5 — Map parent-child process relationships

```
index=botsv1 EventCode=4688
| stats count by Creator_Process_Name, New_Process_Name
| sort -count
```
Look for unusual parent/child pairs — e.g., Office applications (`winword.exe`, `excel.exe`)
spawning `powershell.exe` or `cmd.exe` is a strong phishing/macro-execution indicator and a
textbook initial-access pattern.

## Step 6 — Build a timeline of the suspicious process chain

```
index=botsv1 EventCode=4688 (New_Process_Name="*powershell.exe*" OR Creator_Process_Name="*powershell.exe*")
| table _time, Account_Name, Creator_Process_Name, New_Process_Name, Process_Command_Line
| sort _time
```
Reconstruct the sequence: what ran first, what it spawned next, and whether the chain
escalates (e.g., PowerShell spawning a network connection tool or another script host).

## Step 7 — Build a dashboard

- Dashboards > Create New Dashboard > Classic
- Panel 1: Step 4 query → table or column chart of flagged PowerShell command lines
- Panel 2: Step 5 query → table of parent/child process pairs by count
- Save as: `Lab04_Security_Monitor`

## Step 8 — Document your findings

- Which account(s) launched suspicious PowerShell commands?
- What was the parent process — was it consistent with normal admin activity, or does it
  suggest phishing/macro execution?
- What MITRE ATT&CK technique(s) does this map to?
- What would your next investigative step be (e.g., pivot to network logs for the same host/time)?

---

## Documentation for GitHub/LinkedIn

> Performed log analysis on the Splunk BOTSv1 dataset. Initial hypothesis targeted EventCode
> 4625 (failed logon) for brute-force detection; field validation confirmed this event code
> was not present in the dataset. Pivoted to EventCode 4688 process-creation analysis, hunting
> for PowerShell-based attack chain indicators including encoded commands, hidden window
> flags, and suspicious parent-child process relationships. Mapped findings to MITRE ATT&CK
> T1059.001. Built a Splunk dashboard visualizing flagged command-line activity and process
> lineage.
