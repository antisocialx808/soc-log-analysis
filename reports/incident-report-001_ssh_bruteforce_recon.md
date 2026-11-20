# Incident Report 001: SSH Brute Force and Web Reconnaissance

**Practice report on public sample logs from secrepo.com. Not an incident at an employer.**

| | |
|---|---|
| **Data** | Three public log files from secrepo.com: an SSH log (Zeek format, timestamps from March 2012), an Apache access log (8 to 9 May 2026) and an Apache error log (30 May 2026) |
| **Date of analysis** | June 30, 2026. Revised with a script, November 2026 |
| **Status** | Practice exercise. Findings open |
| **Prepared by** | Samuel, practice report |

The three logs cover different dates, so this report treats them as separate datasets. It does not claim the SSH activity and the web activity are connected.

## At a glance

- **SSH:** 71% of 7,143 connections failed. One internal address, 192.168.202.141, caused 2,365 of the 5,069 failures (46.7%) and never logged a success. The pattern fits an automated brute force.
- **The better lead:** 192.168.204.45 and 192.168.202.110 each logged hundreds of failures and then successful logins. That is the pattern that suggests a guessed credential.
- **Web:** scanning for .php files returned no 200s. Three of the top five IPs were archiving bots downloading the server's public log directory.

## 1. SSH log analysis

7,143 connections between 2012-03-16 12:30 and 2012-03-17 20:56 UTC.

| Outcome | Count | Share |
|---|---|---|
| Failure | 5,069 | 71.0% |
| Success | 301 | 4.2% |
| Undetermined | 1,773 | 24.8% |

**Top failure sources**

| Source IP | Failures | Share of all failures | Total attempts |
|---|---|---|---|
| 192.168.202.141 | 2,365 | 46.7% | 2,380 |
| 192.168.202.110 | 613 | 12.1% | 986 |
| 192.168.204.45 | 574 | 11.3% | 839 |
| 192.168.202.140 | 433 | 8.5% | 894 |
| 192.168.202.68 | 161 | 3.2% | 176 |

**Failures before a first success.** 15 source IPs logged at least one failure before their first success. The largest:

| Source IP | Failures before first success | Total successes |
|---|---|---|
| 192.168.204.45 | 208 | 2 |
| 192.168.202.110 | 164 | 6 |
| 192.168.203.45 | 85 | 18 |
| 192.168.202.108 | 59 | 4 |

**Analysis.** The failure volume does not look like people mistyping passwords. 192.168.202.141 produced 2,365 failures and no successful login. The remaining 15 of its 2,380 connections are undetermined. It looks like an unsuccessful automated attack, or a misconfigured scanner.

192.168.204.45 and 192.168.202.110 matter more. Hundreds of failures followed by a success is what a working brute force or credential-guessing run looks like. This log can't show whether those logins were legitimate users who forgot a password or an attacker who got in. They need follow-up.

All source addresses are internal, so each could be a compromised host or an internal scanning tool. The log alone can't confirm which. Zeek records one row per connection, and a single connection can contain several password attempts, so the true number of guesses is likely higher than the failure counts.

## 2. Web log analysis

20,145 requests between 8 May 2026 01:06 and 9 May 2026 00:51 (UTC-7).

| Status | Count |
|---|---|
| 200 | 19,030 |
| 429 | 811 |
| 301 | 166 |
| 404 | 135 |
| 304 | 3 |

**IP classification**

| IP | Requests | Classification | Basis |
|---|---|---|---|
| 74.7.243.240 | 8,904 | Archiving bot | Sequential log downloads, 8,318 × 200, 578 × 429 |
| 1.162.11.44 | 6,360 | Archiving bot | Sequential log downloads, 6,360 × 200 |
| 79.101.171.152 | 3,403 | Archiving bot | robots.txt check, Apache sort links, log downloads, 3,345 × 200 |
| 4.228.101.41 | 106 | Malicious scanner | WordPress and PHP probing, 53 × 429, 53 × 301, zero 200s |
| 107.136.138.10 | 48 | Benign | Favicon, apple-touch-icon and one directory listing, each requested 12 times |

**PHP probing.** 115 requests targeted 59 distinct .php paths, including wp-trackback.php, xmlrpc.php, z.php, x.php and yellow.php. Results: 56 × 301, 55 × 429, 4 × 404. None returned a 200. The mix of non-standard filenames and WordPress-specific paths is a fingerprinting pass to map the stack. The 429s show rate limiting engaged against an automated client.

## 3. Error log analysis

The error log has three ModSecurity lines, all at Warning level.

| Source IP | Lines | Rule message | URI |
|---|---|---|---|
| 42.193.171.36 | 2 | Request content type is not allowed by policy | / |
| 91.219.237.39 | 1 | URL file extension is restricted by policy | /dump.sql |

The /dump.sql request is a known low-effort probe, checking for database backup files left in public web directories. If a backup existed and was served, it could expose credentials and personal data. A Warning means the rule matched and was logged. These lines don't show whether the request was refused, and the access log covers a different day, so I can't check the response code. This is worth confirming (see recommendations).

## 4. Configuration risk: exposed log directory

The three archiving bots were downloading the server's public /self.logs/ directory. Together they received 18,023 successful responses, and 18,517 of their 18,667 requests targeted that directory.

The exposure is not the bots. It is that the server's logs are publicly readable. Anyone downloading them learns what attacks the server has seen, how far ModSecurity coverage reaches, internal paths and recurring visitor IPs. On a production server this would be a serious misconfiguration. Here it is intentional, since the site exists to share logs.

## 5. Impact assessment

No confirmed compromise in the web data. In the SSH data, successful logins after repeated failures are unexplained and need investigation before any all-clear.

## 6. Recommendations

1. Investigate the successful logins from 192.168.204.45 and 192.168.202.110. Check what each session did and whether the user and device are known.
2. Identify the host behind 192.168.202.141, then block it or fix it, depending on whether it is a scanner or a compromised machine.
3. If SSH is reachable from untrusted networks, disable password login and use key-based authentication. Add rate limiting or a tool like fail2ban.
4. Confirm that dump.sql and any other backup files are absent from the web root, and check whether ModSecurity is blocking or only detecting. The logs show warnings.
5. Review the PHP probe patterns against current rule coverage, and consider blocking 4.228.101.41, 42.193.171.36 and 91.219.237.39 after review.
6. Restrict access to log directories unless the exposure is intended.

**Escalation required:** Yes, for the SSH items above.

## Method and limits

Counts come from `scripts/parse_logs.py` in this repository, run on the three files named above. The script, the files and the date they were downloaded are listed in the README.

- The SSH log is from 2012 and the web logs are from 2026. Treat them as separate exercises.
- "Undetermined" is Zeek's label for connections where it couldn't tell whether authentication succeeded. I don't interpret them further.
- Classifying an IP as a bot or scanner is a judgement from its behaviour in this log, not from threat intelligence.
