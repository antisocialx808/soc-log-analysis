# SOC Log Analysis

Practice analysis of public server logs, written up as a SOC analyst report. Built and run on Android using Termux and Python.

## Reports
- [Incident Report 001: SSH brute force and web reconnaissance](reports/incident-report-001_ssh_bruteforce_recon.md)

## Data
Three public sample log files from secrepo.com. They are not logs from any employer and not a live incident. The log files are not stored in this repository.

| File | What it is |
|---|---|
| `ssh_log.gz` | Zeek SSH log, 7,143 connections, timestamps from March 2012 |
| `access_log_2026-05-08.gz` | Apache access log, 20,145 requests |
| `error_log_2026-05-30.gz` | Apache error log, 3 ModSecurity lines |

Downloaded from the site's /self.logs/ directory. Add the download date here.

## Method
`scripts/parse_logs.py` reads the three files and prints the counts used in the report: SSH outcomes and top failure sources, failures before a first success, access log status codes, top IPs, .php requests, and ModSecurity lines. No data is changed or uploaded.

## How to run
```
python scripts/parse_logs.py --ssh ssh_log.gz --access access_log_2026-05-08.gz --error error_log_2026-05-30.gz
```
Python 3 only, no extra packages. Any option can be left out.

