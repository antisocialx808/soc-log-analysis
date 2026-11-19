# Incident Report 001: Brute Force and Reconnaissance Activity

**Practice report on public sample logs from secrepo.com. Not an incident at an employer.**

| | |
|---|---|
| **Log source** | secrepo.com, a security research site that publishes server logs for educational use |
| **Date of analysis** | June 30, 2026 |
| **Severity** | High (unresolved internal source of SSH attempts) |
| **Status** | Findings open. The internal host cannot be resolved from this dataset |
| **Prepared by** | Samuel, practice report |

## At a glance

- 48% of failed SSH logins came from one internal address, 192.168.229.101. The pattern fits automated brute force, but the logs alone can't say whether that host is compromised or a misconfigured scanner.
- Web activity was reconnaissance only. No PHP probe returned a 200, and ModSecurity blocked a request for /dump.sql.
- Three of the top five access-log IPs were archiving bots, not attackers. The bigger issue they exposed is a publicly readable log directory.

## 1. Summary

SSH brute force activity was detected: 2,444 of 5,069 failed authentication attempts (48%) came from internal host 192.168.229.101. There were 7,143 total connection attempts, with a 4.2% success rate. An internal source needs verification. It could be a compromised host or a misconfigured internal scanning tool, and this is not yet confirmed.

Web reconnaissance was logged against the application server at the same time: automated scanning, PHP file probing consistent with WordPress fingerprinting, and a direct request for an exposed database backup file (dump.sql). ModSecurity blocked the dump.sql request and flagged two external IPs for repeated rule violations. There is no evidence of successful data exfiltration.

## 2. Evidence

**SSH log:** 7,143 total connections. 301 succeeded, 5,069 failed, 1,773 undetermined. Top source: 192.168.229.101 (2,444 attempts, internal address).

**Access log, status code distribution:**

| Status | Count |
|---|---|
| 200 | 19,030 |
| 429 | 811 |
| 301 | 166 |
| 404 | 135 |
| 304 | 3 |

125 requests targeted .php files outside the known application stack, including wp-trackback.php, /z.php, /x.php and /yellow.php. All PHP probe requests returned 301, 404 or 429. No 200 responses were recorded.

**Error log:** ModSecurity blocked a request for /dump.sql. Two external IPs were flagged: 42.193.171.36 (4 hits) and 91.219.237.39 (2 hits).

## 3. Analysis

**SSH.** The failure volume and rate don't match manual login behaviour and fit an automated brute force pattern. The concentration of attempts from a single internal address is the finding that needs follow-up. It could mean an internal host is compromised and being used as a launch point, or it could be a misconfigured internal scanning tool. This log set alone can't confirm which.

Undetermined sessions are connections that opened without a clean success or fail outcome, typically a dropped connection or a timeout mid-handshake. They don't change the overall picture but should be accounted for in escalation.

**Web layer.** The activity reads as reconnaissance, not exploitation. The 429 volume shows the server's rate limiting engaged against an automated client. The PHP probing used non-standard filenames plus a WordPress-specific path on a server that may not run WordPress. That looks like a fingerprinting pass to map the application stack and find a known vulnerability set. None of the probes returned a 200, so none of the probed files were confirmed to exist on the server. The scanner was working blind.

**dump.sql.** This is the most serious web-layer finding. It is a known low-effort probe that attackers run routinely, checking for database backup files accidentally left in public web directories. A successful response would have returned full database contents, which could include credentials, personal data and transaction records. If the server held personal data of Nigerian residents, that would likely be a reportable breach under the Nigeria Data Protection Act 2023. ModSecurity blocked it.

## 4. IP Classification: Access Log

| IP | Requests | Classification | Basis |
|---|---|---|---|
| 74.7.243.240 | 8,904 | Archiving bot | Sequential log downloads, 8,318 × 200 |
| 1.162.11.44 | 6,360 | Archiving bot | Sequential log downloads, 6,360 × 200 |
| 79.101.171.152 | 3,403 | Archiving bot | robots.txt check, Apache sort links, log downloads |
| 4.228.101.41 | 106 | Malicious scanner | WordPress/PHP probing, 53 × 429, 53 × 301, zero 200s |
| 107.136.138.10 | 48 | Clean | Favicon and apple-touch-icon requests only |

## 5. Impact Assessment

No confirmed compromise.

**Web layer:** rate limiting returned 429s to the scanner, no PHP probe returned a 200, and ModSecurity blocked the dump.sql request.

**SSH:** this report has not yet checked whether any of the 301 successful sessions followed repeated failures from the same IP, or came from 192.168.229.101. Until that check is done, SSH authentication controls can't be called effective.

**Open item:** the status of 192.168.229.101, compromised host or misconfigured internal tool, is unresolved and must be escalated before this incident can be closed.

## 6. Configuration Risk: Exposed Log Directory

Investigation of the top five source IPs showed that three of them (74.7.243.240, 1.162.11.44 and 79.101.171.152) were not threat actors. They were archiving bots systematically downloading the server's publicly accessible /self.logs/ directory. Combined, the three made 18,667 requests. The first two alone account for 14,678 successful (200) responses.

The root exposure is not the bots. It is that months of server logs are publicly readable. Anyone downloading this archive learns what attack patterns the server has seen, how far ModSecurity rule coverage reaches, internal path structures and recurring visitor IPs. On a production server this would be a serious misconfiguration.

## 7. Recommendations

1. Isolate and inspect 192.168.229.101 to confirm whether it is a compromised host or a misconfigured internal scanner. This is the priority action before closing this report.
2. For every IP in the SSH log, check for failed attempts followed by a success. Report any match.
3. Confirm dump.sql and any other backup files are not present in the web root on this or any other server in the environment.
4. Review WAF and ModSecurity rule coverage for the PHP probe patterns observed, and confirm 42.193.171.36 and 91.219.237.39 are blocklisted.
5. Review the SSH authentication method. If internet-facing, disable password login and move to key-based authentication.
6. Restrict access to any log directories via .htaccess or server configuration, and confirm no equivalent exposure exists across the organisation's web infrastructure.

**Escalation required:** Yes, internal host investigation pending.

*Practice exercise on public sample logs. Not a live production incident.*
