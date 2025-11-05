#!/bin/sh
# separate launcher for guifuzz_clicks.py

# resolve the directory of this script
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

# require python3 explicitly
PYTHON=$(command -v python3) || {
    echo "python3 not found in PATH." >&2
    exit 1
}

# check session type, GUIFuzz requires X11
if [ -n "${XDG_SESSION_TYPE:-}" ] && [ "${XDG_SESSION_TYPE}" != "x11" ]; then
    echo "GUIFuzz requires an X11 session (XDG_SESSION_TYPE='${XDG_SESSION_TYPE}')." >&2
    exit 2
fi

# args passed from forkserver
OUT_FILE="$1"
GUI_PID="$2"

# launch guifuzz_clicks.py, python PID same as this sh PID for use later.
exec "$PYTHON" "$SCRIPT_DIR/guifuzz_clicks.py" -o "$OUT_FILE" -p "$GUI_PID"
