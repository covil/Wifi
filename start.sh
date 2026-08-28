#!/usr/bin/env sh
# wifiaudit launcher.
#
# On first run this creates a local virtual environment (.venv) and installs
# wifiaudit into it; after that it just opens the interactive menu.
#
#   ./start.sh          # normal use
#   sudo ./start.sh     # for live WiFi runs (scanning/capture need root)
#
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"
VENV="$SCRIPT_DIR/.venv"

# Locate the venv's python (POSIX uses bin/, Windows/Git-Bash uses Scripts/).
venv_py() {
    if [ -x "$VENV/bin/python" ]; then
        echo "$VENV/bin/python"
    elif [ -x "$VENV/Scripts/python.exe" ]; then
        echo "$VENV/Scripts/python.exe"
    else
        return 1
    fi
}

find_python() {
    for c in python3.13 python3.12 python3.11 python3 python; do
        if command -v "$c" >/dev/null 2>&1; then
            if "$c" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
                echo "$c"
                return 0
            fi
        fi
    done
    return 1
}

install_into_venv() {
    echo "  installing wifiaudit and its dependencies..."
    "$PY" -m pip install --upgrade pip >/dev/null 2>&1 || true
    if ! "$PY" -m pip install -e "$SCRIPT_DIR"; then
        echo "error: installation failed. See the pip output above." >&2
        exit 1
    fi
}

# 1. Create the virtualenv if it isn't there yet.
if ! PY=$(venv_py); then
    echo "First run: setting up wifiaudit (one-time)..."
    BASE=$(find_python) || {
        echo "error: Python 3.11+ is required but was not found on PATH." >&2
        echo "       Install it (e.g. 'sudo apt install python3 python3-venv') and retry." >&2
        exit 1
    }
    echo "  creating a local environment with $BASE ..."
    if ! "$BASE" -m venv "$VENV"; then
        echo "error: could not create the virtualenv. On Debian/Ubuntu you may need:" >&2
        echo "       sudo apt install python3-venv" >&2
        exit 1
    fi
    PY=$(venv_py) || {
        echo "error: could not find the virtualenv's python after creation." >&2
        exit 1
    }
    install_into_venv
    echo "  setup complete."
    echo
fi

# 2. Safety net: if the env exists but the package isn't importable, (re)install.
if ! "$PY" -c 'import wifiaudit' 2>/dev/null; then
    echo "Repairing the wifiaudit install..."
    install_into_venv
fi

# 3. Launch the interactive menu.
exec "$PY" -m wifiaudit menu "$@"
