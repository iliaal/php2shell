#!/usr/bin/env python3
"""Map HTTP requests to the php-fpm worker that served them.

Fires requests at an nginx front end against www/echo_pid.php (prints
"PID:<n>"), then reports worker affinity statistics.

Usage:
  affinity_probe.py BASE_URL [--requests N] [--burst K] [--mode fresh|ka]
                          [--path /echo_pid.php] [--gap S]

Modes:
  fresh   new client TCP connection per request (urllib-style)
  ka      one client connection reused for the whole run (browser-style)

Stats printed:
  - pid sequence and per-worker counts
  - run-length histogram
  - all-same rate for windows of size K (chain shape), versus the
    1/n^(K-1) rate expected if workers were chosen uniformly at random
  - burst view: the sequence split into consecutive K-request bursts
"""
import argparse
import collections
import http.client
import json
import re
import sys
import time
from urllib.parse import urlsplit

PID_RE = re.compile(rb"PID:(\d+)")


def one_request(conn, path):
    conn.request("GET", path, headers={"Connection": "keep-alive"})
    resp = conn.getresponse()
    body = resp.read()
    m = PID_RE.search(body)
    if not m:
        raise SystemExit("no PID in response: status=%d body=%r" % (resp.status, body[:200]))
    return int(m.group(1)), resp.status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("--requests", type=int, default=200)
    ap.add_argument("--burst", type=int, default=4)
    ap.add_argument("--mode", choices=("fresh", "ka"), default="ka")
    ap.add_argument("--path", default="/echo_pid.php")
    ap.add_argument("--gap", type=float, default=0.0, help="sleep between requests")
    ap.add_argument("--label", default="")
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    u = urlsplit(args.base)
    host, port = u.hostname, u.port or 80
    path = (u.path.rstrip("/") if u.path else "") + args.path
    if u.query:
        path += "?" + u.query

    pids = []
    times = []
    conn = None
    try:
        for _ in range(args.requests):
            t0 = time.monotonic()
            if args.mode == "fresh" or conn is None:
                conn = http.client.HTTPConnection(host, port, timeout=30)
            pid, status = one_request(conn, path)
            pids.append(pid)
            times.append(time.monotonic() - t0)
            if args.mode == "fresh":
                conn.close()
                conn = None
            if args.gap:
                time.sleep(args.gap)
    finally:
        if conn is not None:
            conn.close()

    n = len(pids)
    counts = collections.Counter(pids)
    workers = len(counts)

    runs = []
    cur = 1
    for a, b in zip(pids, pids[1:]):
        if a == b:
            cur += 1
        else:
            runs.append(cur)
            cur = 1
    runs.append(cur)

    def same_rate(k):
        tot = max(0, n - k + 1)
        if tot == 0:
            return 0, 0, 0.0
        hits = sum(1 for i in range(tot) if len(set(pids[i:i + k])) == 1)
        return hits, tot, hits / tot

    k = args.burst
    hits, tot, rate = same_rate(k)
    expect = (1.0 / workers ** (k - 1)) if workers else 0.0

    bursts = [pids[i:i + k] for i in range(0, n - k + 1, k)]
    burst_hits = sum(1 for b in bursts if len(set(b)) == 1)

    transitions = collections.Counter(zip(pids, pids[1:]))

    print("== affinity probe %s ==" % (args.label or args.mode))
    print("url=%s mode=%s requests=%d workers_seen=%d" % (args.base, args.mode, n, workers))
    print("pids=%s" % " ".join(str(p) for p in pids))
    print("counts=%s" % " ".join("%d:%d" % (p, c) for p, c in sorted(counts.items())))
    print("runs=%s" % ",".join(str(r) for r in runs))
    print("same-%d sliding=%d/%d (%.3f)  uniform-random=%.3f" % (k, hits, tot, rate, expect))
    print("same-%d bursts=%d/%d" % (k, burst_hits, len(bursts)))
    print("mean_ms=%.1f max_ms=%.1f" % (
        1000 * sum(times) / n if n else 0.0,
        1000 * max(times) if times else 0.0))
    if transitions:
        print("transitions=%s" % " ".join("%d>%d:%d" % (a, b, c) for (a, b), c in sorted(transitions.items())))

    if args.json:
        with open(args.json, "w") as f:
            json.dump({
                "base": args.base, "mode": args.mode, "label": args.label,
                "pids": pids, "counts": {str(p): c for p, c in counts.items()},
                "runs": runs, "window": k, "hits": hits, "windows": tot,
                "rate": rate, "uniform": expect,
                "bursts": len(bursts), "burst_hits": burst_hits,
                "mean_ms": 1000 * sum(times) / n if n else 0.0,
            }, f, indent=1)


if __name__ == "__main__":
    main()
