#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python3 benchmark.py run
python3 benchmark.py compare || true
