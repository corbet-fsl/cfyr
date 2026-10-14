#!/usr/bin/env bash
# cfyr verification, run by `ccid` (check "rust"). Builds against the newest main of our own crates first.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
rustc --version
bash .ci/update-our-crates.sh
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo check --locked --target wasm32-unknown-unknown
