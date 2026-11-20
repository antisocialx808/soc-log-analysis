#!/usr/bin/env python3
"""Summarise three public sample logs from secrepo.com.

  --ssh     Zeek ssh.log (tab-separated; auth_success is column 7)
  --access  Apache access log, combined format
  --error   Apache error log (ModSecurity lines)

Usage:
    python parse_logs.py --ssh ssh_log.gz --access access_log.gz --error error_log.gz

Any option can be left out. .gz files work as they are. Lines that don't
match the expected format are counted, not silently dropped.
"""
import argparse
import gzip
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

ACCESS_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) ')
ERR_CLIENT_RE = re.compile(r'\[client ([\d.]+):\d+\]')
ERR_FIELD_RE = {
    "msg": re.compile(r'\[msg "([^"]*)"\]'),
    "uri": re.compile(r'\[uri "([^"]*)"\]'),
}
ERR_LEVEL_RE = re.compile(r'ModSecurity: (\w[\w ]*?)\.')


def open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def analyse_ssh(path):
    outcomes = Counter()
    fails = Counter()
    per_ip = Counter()
    seq = defaultdict(list)  # source IP -> [(timestamp, outcome)]
    bad = 0
    first = last = None
    with open_log(path) as f:
        for line in f:
            c = line.rstrip("\n").split("\t")
            if len(c) < 8:
                bad += 1
                continue
            ts, src, outcome = float(c[0]), c[2], c[6]
            first = ts if first is None else min(first, ts)
            last = ts if last is None else max(last, ts)
            outcomes[outcome] += 1
            per_ip[src] += 1
            if outcome == "failure":
                fails[src] += 1
            seq[src].append((ts, outcome))
    d = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M")
    total = sum(outcomes.values())
    print("== SSH LOG ==")
    print(f"connections: {total}   unparsed: {bad}")
    print(f"time range (UTC): {d(first)} to {d(last)}")
    for k in ("success", "failure", "undetermined"):
        n = outcomes.get(k, 0)
        print(f"  {k:<13}{n:>6}  ({n / total * 100:.1f}%)")
    nf = outcomes.get("failure", 0)
    print("top failure sources:")
    for ip, n in fails.most_common(5):
        print(f"  {ip:<18}{n:>6} failures ({n / nf * 100:.1f}% of all failures), {per_ip[ip]} attempts in total")
    print("sources with failures before a first success:")
    rows = []
    for ip, events in seq.items():
        events.sort()
        before = 0
        for _, o in events:
            if o == "success":
                if before:
                    rows.append((before, ip))
                break
            if o == "failure":
                before += 1
    for before, ip in sorted(rows, reverse=True)[:10]:
        print(f"  {ip:<18}{before:>6} failures before first success")
    if not rows:
        print("  none")
    print(f"  ({len(rows)} sources in total)")


def analyse_access(path):
    status = Counter()
    by_ip = Counter()
    ip_status = defaultdict(Counter)
    php = Counter()
    php_status = Counter()
    bad = total = 0
    first = last = None
    with open_log(path) as f:
        for line in f:
            total += 1
            m = ACCESS_RE.match(line)
            if not m:
                bad += 1
                continue
            ip, when, _method, url, code = m.groups()
            first = first or when
            last = when
            status[code] += 1
            by_ip[ip] += 1
            ip_status[ip][code] += 1
            path_only = url.split("?")[0]
            if path_only.lower().endswith(".php"):
                php[path_only] += 1
                php_status[code] += 1
    print("\n== ACCESS LOG ==")
    print(f"lines: {total}   unparsed: {bad}")
    print(f"time range: {first} to {last}")
    print("status codes:", dict(sorted(status.items())))
    print("top IPs:")
    for ip, n in by_ip.most_common(5):
        print(f"  {ip:<18}{n:>6}   {dict(sorted(ip_status[ip].items()))}")
    print(f".php requests: {sum(php.values())}   by status: {dict(sorted(php_status.items()))}")
    print(f"  distinct .php paths: {len(php)}")
    print("  examples:", ", ".join(sorted(php)[:8]))


def analyse_error(path):
    by_ip = Counter()
    rows = []
    with open_log(path) as f:
        for line in f:
            if "ModSecurity" not in line:
                continue
            ip = (ERR_CLIENT_RE.search(line) or [None, "?"])[1]
            level = (ERR_LEVEL_RE.search(line) or [None, "?"])[1]
            msg = (ERR_FIELD_RE["msg"].search(line) or [None, "?"])[1]
            uri = (ERR_FIELD_RE["uri"].search(line) or [None, "?"])[1]
            by_ip[ip] += 1
            rows.append((ip, level, uri, msg))
    print("\n== ERROR LOG ==")
    print(f"ModSecurity lines: {len(rows)}")
    for ip, n in by_ip.most_common():
        print(f"  {ip:<18}{n} line(s)")
    for ip, level, uri, msg in rows:
        print(f"  {ip}  [{level}]  uri={uri}  msg={msg}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ssh")
    p.add_argument("--access")
    p.add_argument("--error")
    a = p.parse_args()
    if not (a.ssh or a.access or a.error):
        p.error("give at least one of --ssh, --access, --error")
    if a.ssh:
        analyse_ssh(a.ssh)
    if a.access:
        analyse_access(a.access)
    if a.error:
        analyse_error(a.error)


if __name__ == "__main__":
    main()
