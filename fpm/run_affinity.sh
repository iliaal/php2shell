#!/usr/bin/env bash
# Worker-affinity measurement for the multi-worker FPM landing question.
#
# Spins a fresh php-fpm pool (pm = static, N workers) behind nginx with NO
# published fpm port, then maps each request to a worker PID with
# fpm/affinity_probe.py (www/echo_pid.php).
#
# Usage: run_affinity.sh [stock|keepalive] [pool_size] [requests]
#   stock      nginx default (new upstream connection per request)
#   keepalive  upstream { keepalive 1; } + fastcgi_keep_conn on
#
# Env: AFF_PORT (9105), REQUESTS (200), POOL (4), IMAGE (php:8.5.11-fpm),
#      NGINX_IMAGE (nginx:alpine), NO_SETUP=1 (reuse containers).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
VARIANT=${1:-stock}
POOL=${2:-${POOL:-4}}
REQUESTS=${3:-${REQUESTS:-200}}
FPM_NAME=${FPM_NAME:-p2s-aff-fpm}
NGINX_NAME=${NGINX_NAME:-p2s-aff-nginx}
NET=${NET:-p2s-fpm-net}
AFF_PORT=${AFF_PORT:-9105}
IMAGE=${IMAGE:-php:8.5.11-fpm}
NGINX_IMAGE=${NGINX_IMAGE:-nginx:alpine}
INI=${INI:-/usr/local/etc/php/php.ini-production}
NO_SETUP=${NO_SETUP:-0}

case "$VARIANT" in
    stock)     NGINX_CONF=nginx-aff-stock.conf ;;
    keepalive) NGINX_CONF=nginx-aff-keepalive.conf ;;
    *) echo "variant must be stock|keepalive" >&2; exit 2 ;;
esac

if [ "$NO_SETUP" != 1 ]; then
    docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
    docker rm -f "$FPM_NAME" "$NGINX_NAME" >/dev/null 2>&1 || true
    cat > /tmp/zz-aff.conf <<EOF
[www]
pm = static
pm.max_children = $POOL
pm.max_requests = 0
pm.status_path = /status
clear_env = no
catch_workers_output = yes
access.log = /tmp/fpm-access.log
access.format = "%p %m %r %s %{milli}d"
EOF
    docker run -d --name "$FPM_NAME" --network "$NET" --network-alias p2s-aff-fpm \
        -v "$ROOT/www:/var/www/html:ro" \
        -v /tmp/zz-aff.conf:/usr/local/etc/php-fpm.d/zz-aff.conf:ro \
        "$IMAGE" php-fpm -F -c "$INI" >/dev/null
    sleep 1.5
    docker run -d --name "$NGINX_NAME" --network "$NET" \
        -p 127.0.0.1:"$AFF_PORT":80 \
        -v "$HERE/$NGINX_CONF:/etc/nginx/conf.d/default.conf:ro" \
        "$NGINX_IMAGE" >/dev/null
fi

URL="http://127.0.0.1:$AFF_PORT"
for _ in $(seq 1 50); do
    if curl -fsS --max-time 2 "$URL/echo_pid.php" >/dev/null 2>&1; then break; fi
    sleep 0.2
done
curl -fsS --max-time 5 "$URL/echo_pid.php" >/dev/null || {
    echo "[aff] front end did not come up at $URL" >&2; exit 2; }

docker exec "$FPM_NAME" sh -c ': > /tmp/fpm-access.log'
echo "[aff] variant=$VARIANT pool=$POOL image=$IMAGE nginx=$NGINX_IMAGE"
docker exec "$FPM_NAME" sh -c 'php-fpm -v 2>/dev/null | head -1 || /usr/local/sbin/php-fpm -v | head -1' || true
docker exec "$NGINX_NAME" nginx -v 2>&1 || true
uname -r

python3 "$HERE/affinity_probe.py" "$URL" --requests "$REQUESTS" --mode ka \
    --label "$VARIANT/ka/pool$POOL" --json /tmp/aff-$VARIANT-$POOL-ka.json
python3 "$HERE/affinity_probe.py" "$URL" --requests "$REQUESTS" --mode fresh \
    --label "$VARIANT/fresh/pool$POOL" --json /tmp/aff-$VARIANT-$POOL-fresh.json

echo "[aff] fpm-side access log (pid method path status ms), last $REQUESTS:"
docker exec "$FPM_NAME" sh -c "tail -n $((REQUESTS * 2)) /tmp/fpm-access.log" | awk '{print $1}' | uniq -c | tail -20
