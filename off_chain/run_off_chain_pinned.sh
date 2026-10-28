#!/usr/bin/env bash
# Validate the display-errors-off chain on a multi-child prefork Apache by
# pinning all but one child (attacker-side), not by changing the target config.
#
# Usage: [CONTAINER=name] [PINS=n] ./off_chain/run_off_chain_pinned.sh [port] [proof]
# The target still runs stock KeepAlive settings; the chain's bailout responses
# close their connections, so affinity across them comes from pinning.
set -euo pipefail
PORT=${1:-8093}
PROOF=${2:-/tmp/off_proof}
CONTAINER=${CONTAINER:-}
PINS=${PINS:-9}
DIR=$(cd "$(dirname "$0")" && pwd)

python3 "$DIR/pin_workers.py" "$PORT" "$PINS" &
PIN_PID=$!
trap 'kill "$PIN_PID" 2>/dev/null || true' EXIT
sleep 0.7

CONTAINER="$CONTAINER" "$DIR/run_off_chain.sh" "$PORT" "$PROOF"
