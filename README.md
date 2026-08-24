# Splunk BOTS v1 Detection Engineering Lab

A self-guided detection engineering project investigating a simulated web application compromise using the [Splunk BOTS v1](https://github.com/splunk/botsv1) dataset — from manual threat hunting through to built, validated, and saved Splunk detections.

## Overview

Wayne Corp's public website (`imreallynotbatman.com`, running Joomla) was defaced by a threat actor group in the BOTS v1 scenario. I investigated the full attack chain end-to-end using Splunk Search Processing Language (SPL) — reconnaissance, brute-force credential attack, successful compromise, web shell deployment, and defacement — then converted those findings into four repeatable, validated Splunk detections and a summary dashboard.

## What's in this repo

| File | Description |
|---|---|
| `BOTS_v1_Scenario1_Investigation_Report.md` | Full investigation report — timeline, IOCs, SPL methodology, MITRE ATT&CK mapping, and detection engineering writeup |
| `BOTS_v1_Scenario1_Investigation_Report.pdf` | Same report, PDF format |

## Attack Chain Summary

**Target:** `imreallynotbatman.com` (Joomla CMS) — **Date:** August 11, 2016

```
Reconnaissance scan (40.80.148.42, Acunetix)
        ↓
Brute-force login (23.22.63.114, 412 attempts)
        ↓
Successful login (40.80.148.42, credential re-use of original recon IP)
        ↓
Obfuscated PHP web shell uploaded via Joomla com_installer
        ↓
Site defacement (imnotbatman.jpg)
```

Attacker infrastructure: `prankglassinebracket.jumpingcrab.com` (dynamic DNS), resolving to `23.22.63.114`.

## Detections Built

Each detection was built from a real finding in the investigation, then validated against the dataset and saved as a live Splunk alert.

| # | Detection | Attack Stage | Validated Against |
|---|---|---|---|
| 1 | High-volume single-source web requests | Reconnaissance | Correctly flagged the Acunetix scan + surfaced 2 previously unknown leads |
| 2 | Brute-force login attempts | Credential Access | Correctly flagged 412 login attempts from a distinct source IP |
| 3 | Statistical outlier in login response size | Initial Access (hidden success) | Correctly isolated the single successful login among 413 attempts |
| 4 | Connection to known malicious dynamic DNS domain | Command & Control | Correctly flagged victim server contact with attacker infrastructure |

Two of these detections **corrected assumptions made during the manual investigation** — revealing that the attacker split activity across two separate IPs (one for noisy brute-forcing, a separate "clean" one for the actual successful login) as an operational security measure. This is documented in full in the report.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Reconnaissance | T1595 – Active Scanning |
| Resource Development | T1583.001 – Acquire Infrastructure: Domains |
| Initial Access | T1190 – Exploit Public-Facing Application / T1078 – Valid Accounts |
| Credential Access | T1110.001 – Brute Force: Password Guessing |
| Persistence / Execution | T1505.003 – Server Software Component: Web Shell |
| Defense Evasion | T1027 – Obfuscated Files or Information |
| Impact | T1491 – Defacement |

## Tools & Environment

- Splunk Enterprise (local install)
- Splunk BOTS v1 dataset (~33.4M events, ~8.6GB indexed)
- SPL for investigation, statistical anomaly detection, and alerting
- Splunk Dashboard Studio for the summary dashboard

## Skills Demonstrated

- Log ingestion and index management in Splunk
- SPL query writing (search, stats, eventstats, bucket, eval)
- Threat hunting / manual investigation methodology
- Statistical anomaly detection (identifying outliers without relying on status codes alone)
- Detection engineering — converting one-off findings into repeatable, validated alerts
- MITRE ATT&CK mapping
- Incident documentation and reporting

## About This Project

Built as a hands-on self-study project to develop practical detection engineering and SOC analyst skills using a realistic, publicly available attack dataset. Full methodology, SPL queries, and analysis are documented in the report.
