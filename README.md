# CASE-17: Zeek Network Forensics + Beacon Detection

**C2 beacon detection on a 2024 SSLoad + Cobalt Strike PCAP with Zeek 8.2.1, RITA v5.1.2, and Jupyter threat hunting notebooks.**

[![Zeek](https://img.shields.io/badge/Zeek-8.2.1-blue)](https://zeek.org)
[![RITA](https://img.shields.io/badge/RITA-v5.1.2-orange)](https://github.com/activecm/rita)
[![Python](https://img.shields.io/badge/Python-3.12-green)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-REMnux%20Ubuntu%2024.04-purple)](https://remnux.org)

**Repository:** [github.com/ronankongala/zeek-network-forensics-lab](https://github.com/ronankongala/zeek-network-forensics-lab). The OCaml port of the scoring logic (CASE-18) lives in [zeek-beacon-ocaml](https://github.com/ronankongala/zeek-beacon-ocaml).

---

## Overview

I ran a public SSLoad infection PCAP with follow-on Cobalt Strike DLL activity (Malware Traffic Analysis, April 18, 2024) through Zeek and RITA, then checked RITA's beacon ranking by hand in three notebooks.

The analysis confirmed 85.239.53.219 as the primary C2 server with a mean beacon interval of 477 seconds, auto-tagged by RITA as `rare_signature:SSLoad/1.1`. RITA also scored api.openweathermap.org and t.me (Telegram) at 0.682. Nothing in the capture confirms either one as C2, so both stay listed as unconfirmed.

---

## Key Findings

| Indicator | Value |
|---|---|
| C2 Server | 85.239.53.219:80 (HTTP) |
| Beacon Score (RITA) | 0.504 |
| RITA Modifier | `rare_signature:SSLoad/1.1` |
| Total C2 Connections | 11 |
| Mean Beacon Interval | 477 seconds (~8 minutes), 35% jitter |
| Total C2 Connection Time | 5,087 seconds summed across 11 connections |
| Victim Host | 10.4.18.169 |
| DNS Queries | 73 total |
| HTTP Requests | 273 total |
| Zeek Logs Generated | 16 files (220KB) |

The 5,087 seconds is larger than the 4,775-second beacon window (first start to last start) because long sessions overlap short ones.

---

## Environment

| Component | Version |
|---|---|
| OS | REMnux Ubuntu 24.04 |
| Zeek | 8.2.1 |
| RITA | v5.1.2 (Docker + ClickHouse) |
| JupyterLab | 4.6.3 |
| Docker | 29.7.2 |
| Python | 3.12 |
| Host | Windows 11, VMware Workstation, VMnet2 host-only (192.168.100.0/24) |

---

## PCAP Source

**Malware Traffic Analysis, 2024-04-18: Word macro → SSLoad → Cobalt Strike DLL**

- Source: [malware-traffic-analysis.net/2024/04/18/](https://www.malware-traffic-analysis.net/2024/04/18/)
- File: `2024-04-18-SSLoad-with-follow-up-Cobalt-Strike-DLL.pcap`
- Size: 6.4MB
- Password scheme: `infected_YYYYMMDD` (see MTA about page)

---

## Repository Structure

```
zeek-network-forensics-lab/
├── notebooks/
│   ├── notebook1_conn_analysis.ipynb
│   ├── notebook2_dns_analysis.ipynb
│   └── notebook3_beacon_intervals.ipynb
├── phase-6-report/
│   └── CASE-17_Network_Forensics_Investigation_Report.pdf
├── screenshots/
│   ├── 01_zeek_rita_versions.png
│   ├── 02_pcap_verified.png
│   ├── 03_zeek_logs_generated.png
│   ├── 04_conn_log_suspicious.png
│   ├── 05_rita_beacon_scoring.png
│   ├── 06_rita_top_beacons.png
│   ├── 07_notebook1_conn_analysis.png
│   ├── 08_notebook2_dns_analysis.png
│   └── 09_notebook3_beacon_intervals.png
└── README.md
```

The PCAP and the 16 Zeek logs it produces are not committed. The PCAP is a live malware sample and is redistributed under Malware Traffic Analysis terms, so pull it from the PCAP Source link above and regenerate the logs with the Phase 3 command. Every notebook reads from `/home/remnux/case18-zeek-lab/zeek-logs/` (`case18` was the lab's working folder name, and the Sigma rule IDs below kept it); adjust `LOG_PATH` in the first cell if your paths differ. Notebook charts are saved as committed cell outputs and render inline on GitHub without a rerun.

---

## Phase Walkthrough

### Phase 1: Environment Setup

Installed Zeek from the official openSUSE repository for Ubuntu 24.04, RITA v5.1.2 via the tarball installer (requires Docker Engine), and JupyterLab via pip3.

```bash
# Zeek
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' \
  | sudo tee /etc/apt/sources.list.d/zeek.list
sudo apt-get update && sudo apt-get install -y zeek
echo 'export PATH=$PATH:/opt/zeek/bin' >> ~/.bashrc

# RITA
wget https://github.com/activecm/rita/releases/download/v5.1.2/rita-v5.1.2.tar.gz
tar -xzvf rita-v5.1.2.tar.gz
cd rita-v5.1.2-installer && ./install_rita.sh localhost

# Jupyter
pip3 install jupyter pandas matplotlib seaborn --break-system-packages
```

![SS01: Zeek 8.2.1, RITA v5.1.2, JupyterLab 4.6.3 confirmed](screenshots/01_zeek_rita_versions.png)

---

### Phase 2: PCAP Acquisition

```bash
mkdir -p ~/case18-zeek-lab/{pcaps,zeek-logs,rita-output,notebooks,report}
cd ~/case18-zeek-lab/pcaps
wget "https://www.malware-traffic-analysis.net/2024/04/18/2024-04-18-SSLoad-with-follow-up-Cobalt-Strike-DLL.pcap.zip"
unzip -P infected_20240418 2024-04-18-SSLoad-with-follow-up-Cobalt-Strike-DLL.pcap.zip
```

![SS02: PCAP verified on disk (6.4MB)](screenshots/02_pcap_verified.png)

---

### Phase 3: Zeek Analysis

```bash
cd ~/case18-zeek-lab/zeek-logs
/opt/zeek/bin/zeek -r ~/case18-zeek-lab/pcaps/2024-04-18-SSLoad-with-follow-up-Cobalt-Strike-DLL.pcap
ls -lh
```

Zeek generated 16 structured log files totaling 220KB. Key logs for C2 detection:

- `conn.log` (27K): every connection with duration, bytes and state
- `http.log` (81K): 273 HTTP requests, including the SSLoad callbacks
- `dns.log` (19K): 73 DNS queries
- `ssl.log` (12K): TLS sessions, including the Cobalt Strike HTTPS beacon
- `kerberos.log` (2.1K), `ldap.log` (2.8K) and `ldap_search.log` (4.7K) hold the post-exploitation AD activity against partridge-dc.partridgecliff.com

Full set: conn, dce_rpc, dns, files, http, kerberos, ldap, ldap_search, ocsp, packet_filter, pe, smb_files, smb_mapping, ssl, weird, x509.

![SS03: 16 Zeek log files generated from PCAP](screenshots/03_zeek_logs_generated.png)

Sorting conn.log by duration puts the C2 server at the top:

```bash
cat ~/case18-zeek-lab/zeek-logs/conn.log | awk -F'\t' '{print $9, $10, $6, $5}' | sort -rn | head -20
```

![SS04: conn.log showing 85.239.53.219 with 1992s and 1982s connections](screenshots/04_conn_log_suspicious.png)

---

### Phase 4: RITA Beacon Scoring

```bash
rita import --database case18 --logs /home/remnux/case18-zeek-lab/zeek-logs
rita view --stdout case18
```

RITA scored all external connections for beaconing regularity using interval skewness analysis, data size consistency, and connection count. Scores above 0.5 warrant investigation.

![SS05: RITA beacon scoring output](screenshots/05_rita_beacon_scoring.png)

Top beacons ranked by score:

| Destination | Beacon Score | Connections | Verdict |
|---|---|---|---|
| t.me | 0.682 | 9 | Unconfirmed (regular DNS polling) |
| api.openweathermap.org | 0.682 | 9 | Unconfirmed (regular DNS polling) |
| 85.239.53.219 | **0.504** | **11** | **Primary C2 (SSLoad/1.1)** |

RITA ranked t.me and api.openweathermap.org higher on raw score (0.682) and rated all three Low severity, so score alone does not name the primary C2. 85.239.53.219 takes that call on three other pieces of evidence: RITA auto-tagged it `rare_signature:SSLoad/1.1` from the malware's own HTTP user agent, it carried 2,164,635 bytes against 12,013 bytes for api.openweathermap.org, and it holds 5,087 seconds of connection time against a handful of short polls. The two higher-scoring domains likely rank first because 9 evenly spaced DNS lookups are trivially regular. A beacon score tends to over-rate low-volume destinations like these.

![SS06: RITA top beacons ranked by score, 85.239.53.219 tagged rare_signature:SSLoad/1.1](screenshots/06_rita_top_beacons.png)

---

### Phase 5: Threat Hunting Notebooks

**Notebook 1: conn.log analysis**

The first notebook loads conn.log into pandas (199 connections to 39 destination IPs), lists the 15 longest connections, and filters for long duration with low bytes to an external IP. The filter returned 19 candidates, of which two are 85.239.53.219.

![SS07: Notebook 1 conn.log duration chart, with 85.239.53.219:80 the clear outlier at 33.2 minutes](screenshots/07_notebook1_conn_analysis.png)

---

**Notebook 2: DNS analysis**

dns.log has 73 queries across 24 unique domains. wpad.partridgecliff.com tops the list at 17 lookups, which is normal Windows proxy discovery. api.openweathermap.org and t.me flagged at 9 queries each, above the 5-query threshold and ahead of login.microsoftonline.com at 7.

![SS08: Notebook 2: Top 15 DNS queries bar chart](screenshots/08_notebook2_dns_analysis.png)

---

**Notebook 3: Beacon interval visualization**

The 11 connections to 85.239.53.219 give 10 inter-arrival gaps. Mean 477.5s, median 586.4s, std dev 169.2s, min 165.0s, max 606.9s, jitter ratio 35.4%. That fits a Cobalt Strike sleep timer set near 600s with jitter. Six of the ten intervals fall between 579s and 607s, clustering just under a 10-minute sleep; the four short intervals (165s to 430s) are the jitter subtracting from that ceiling, which is why the median sits well above the mean.

![SS09: Notebook 3: C2 beacon timeline and interval regularity chart](screenshots/09_notebook3_beacon_intervals.png)

---

### Phase 6: Investigation Report

The PDF report maps the findings to MITRE ATT&CK and includes the IOC table, Sigma rules and network control recommendations. It was written before the t.me and openweathermap verdicts were downgraded to unconfirmed, so it still calls them C2 channels.

**[Read the report: CASE-17_Network_Forensics_Investigation_Report.pdf](phase-6-report/CASE-17_Network_Forensics_Investigation_Report.pdf)**

---

## MITRE ATT&CK

| Technique | Name | Evidence |
|---|---|---|
| T1071 | Application Layer Protocol | SSLoad C2 over HTTP port 80; 273 HTTP requests |
| T1071.001 | Application Layer Protocol: Web Protocols | Cobalt Strike HTTPS beacon in ssl.log (12K of TLS sessions) |
| T1071.004 | Application Layer Protocol: DNS | Candidate only: 9 queries each to api.openweathermap.org and t.me, unconfirmed as C2 |
| T1008 | Fallback Channels | Candidate only: t.me and api.openweathermap.org, unconfirmed |
| T1557.001 | LLMNR/NBT-NS Poisoning and SMB Relay | Exposure only: 17 wpad.partridgecliff.com lookups seen, no poisoning observed |
| T1018 | Remote System Discovery | 2 lookups for partridge-dc.partridgecliff.com plus ldap_search.log activity |

---

## IOCs

| Type | Value | Context |
|---|---|---|
| IP | 85.239.53.219 | SSLoad C2, port 80 HTTP, beacon score 0.504 |
| IP | 10.4.18.169 | Victim host |
| Domain | api.openweathermap.org | Unconfirmed, beacon score 0.682 |
| Domain | t.me | Telegram, unconfirmed, beacon score 0.682 |
| Domain | wpad.partridgecliff.com | WPAD proxy discovery |
| Domain | partridge-dc.partridgecliff.com | Domain controller, AD enumeration |
| User Agent | SSLoad/1.1 | SSLoad malware HTTP user agent |
| Port | 80/tcp | Primary C2 port |
| Port | 445/tcp | SMB session to 10.4.18.4 (212s, 30.9KB, conn_state S1) |
| Beacon Interval | 477 seconds mean, 35.4% jitter | Cobalt Strike sleep timer |

---

## Detection Logic

```yaml
title: SSLoad C2 Beacon via HTTP
id: case18-001
status: experimental
logsource:
  product: zeek
  service: conn
detection:
  selection:
    proto: tcp
    id.resp_p: 80
    duration|gt: 600
    orig_bytes|lt: 5000
  condition: selection
level: high
tags:
  - attack.t1071
```

```yaml
title: High-Frequency DNS to Non-Corporate Domain
id: case18-002
status: experimental
logsource:
  product: zeek
  service: dns
detection:
  selection:
    qtype_name: A
  timeframe: 10m
  condition: selection | count(query) by query > 8
level: medium
tags:
  - attack.t1071.004
```

---

## Tools Used

| Tool | Purpose |
|---|---|
| Zeek 8.2.1 | Network traffic parsing and structured log generation |
| RITA v5.1.2 | Probabilistic beacon scoring via ClickHouse analytics |
| pandas | Log parsing and data manipulation |
| matplotlib | Connection timeline and interval visualization |
| JupyterLab 4.6.3 | Interactive threat hunting notebooks |
| Docker 29.7.2 | RITA backend container orchestration |
| ReportLab | PDF investigation report generation |

---

## References

- [Malware Traffic Analysis 2024-04-18](https://www.malware-traffic-analysis.net/2024/04/18/)
- [RITA by Active Countermeasures](https://github.com/activecm/rita)
- [Zeek Network Security Monitor](https://zeek.org)
- [MITRE ATT&CK T1071](https://attack.mitre.org/techniques/T1071/)
- [MITRE ATT&CK T1008](https://attack.mitre.org/techniques/T1008/)
- [MITRE ATT&CK T1557.001](https://attack.mitre.org/techniques/T1557/001/)
- [MITRE ATT&CK T1018](https://attack.mitre.org/techniques/T1018/)

---

## Author

**Ronan Kongala**
MS Cybersecurity, Northeastern University (GPA 3.8)
Cybersecurity Intern (AI/ML), Abbott (Exact Sciences)

[LinkedIn](https://linkedin.com/in/ronan-kongala) | [GitHub](https://github.com/ronankongala) | [Portfolio](https://ronankongala.github.io)
