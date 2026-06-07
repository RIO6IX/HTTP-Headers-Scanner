#!/usr/bin/env sh
set -eu

python -m venv .venv
. .venv/Scripts/activate 2>/dev/null || . .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

echo "Installed HTTP Headers Scanner. Run: headers https://example.com"
