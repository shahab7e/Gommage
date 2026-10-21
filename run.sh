#!/bin/sh
# Gommage on Linux: first run makes a venv with pywebview (seeing the system's GTK bindings), then starts the app.
set -e
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
    python3 -m venv --system-site-packages .venv
    .venv/bin/pip install -r requirements.txt
fi
exec .venv/bin/python gommage.py "$@"
