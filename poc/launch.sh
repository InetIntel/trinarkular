#!/usr/bin/env bash
#
# Launch the POC measurement run detached, as root.
#
# ZMap needs raw sockets, so the run must be privileged. Run this under sudo in
# the FOREGROUND so sudo can prompt for a password on the terminal:
#
#     sudo bash poc/launch.sh
#
# Backgrounding sudo itself does not work: it tries to read the prompt from the
# terminal, receives SIGTTIN and is suspended before it ever gains privilege.
# This script instead runs as root already and detaches the measurement process
# itself, so sudo returns immediately and the run continues in the background.
#
# Extra arguments are passed through to run_experiment.py, e.g.
#     sudo bash poc/launch.sh --rounds 4 --interval 60

set -euo pipefail

cd "$(dirname "$0")/.."

PYTHON=${PYTHON:-/usr/bin/python3}
ZMAP=${ZMAP:-/opt/homebrew/sbin/zmap}
IFACE=${IFACE:-en0}
LOG=poc/results/run.log

if [[ $EUID -ne 0 ]]; then
  echo "error: must run as root, e.g. 'sudo bash poc/launch.sh'" >&2
  exit 1
fi

# clear out any earlier attempt (including one suspended awaiting a password)
pkill -f 'run_experiment\.py' 2>/dev/null || true

mkdir -p poc/results

nohup "$PYTHON" poc/run_experiment.py \
  --interface "$IFACE" \
  --zmap "$ZMAP" \
  "$@" >"$LOG" 2>&1 &

pid=$!
sleep 2

# hand the log back to the invoking user so it stays readable after the run
if [[ -n ${SUDO_UID:-} && -n ${SUDO_GID:-} ]]; then
  chown "$SUDO_UID:$SUDO_GID" "$LOG" 2>/dev/null || true
fi

if kill -0 "$pid" 2>/dev/null; then
  echo "launched pid $pid"
  echo "log: $LOG"
else
  echo "error: process exited immediately; see $LOG" >&2
  tail -20 "$LOG" >&2
  exit 1
fi
