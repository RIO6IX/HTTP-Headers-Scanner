default:
    @just --list

run *args:
    python http_headers_scanner.py {{args}}

test:
    python -m pytest

install:
    python -m pip install -e ".[dev]"
