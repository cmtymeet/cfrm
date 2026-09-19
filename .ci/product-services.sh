#!/usr/bin/env bash
set -euo pipefail
rustc --version
cargo --version
node --version
timeout 1200 cargo test --locked --features sqlite,discovery-api,discovery-valkey --tests -- --test-threads=2
timeout 1200 cargo check --locked --target wasm32-unknown-unknown --no-default-features --lib
timeout 180 node --test test/*.test.js
timeout 600 npm ci --prefix runtime/accounting --ignore-scripts --no-audit --no-fund
timeout 180 node --test runtime/accounting/test/*.test.mjs
