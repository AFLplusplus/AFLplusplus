#!/usr/bin/env bash
# separate launcher for guifuzz_clicks.py

# resolve the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# check for python3 or python in PATH
PYTHON=$(command -v python3 || command -v python)
if [ -z "$PYTHON" ]; then
    echo "Python not found in PATH. Aborting."
    exit 1
fi

# args passed from forkserver
OUT_FILE="$1"
GUI_PID="$2"

# launch guifuzz_clicks.py, python PID same as this sh PID for use later.
exec "$PYTHON" "$SCRIPT_DIR/guifuzz_clicks.py" -o "$OUT_FILE" -p "$GUI_PID"
