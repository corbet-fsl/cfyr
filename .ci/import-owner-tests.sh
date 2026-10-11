#!/usr/bin/env bash
# Import the exact resolved owner fixture before formatting or compiling tests.
set -euo pipefail
cargo metadata --locked --format-version 1 > dependency-metadata.json
python3 .github/copy-owner-tests.py
