#!/usr/bin/env bash
set -euo pipefail
rustc --version
cargo --version
node --version
artifact_dir="${ARTIFACT_ROOT:?}/${CI_COMMIT_SHA:?}/product-services"
mkdir -p "$artifact_dir"
if test "${RESOLVE_DEPENDENCIES:-0}" = 1; then
  cargo generate-lockfile
  date -u +%FT%TZ > "$artifact_dir/dependency-resolution-time.txt"
fi
cp Cargo.lock "$artifact_dir/Cargo.lock"
result=0
if command -v pkg-config >/dev/null && pkg-config --exists openssl; then
  OPENSSL_INCLUDE_DIR="$(pkg-config --variable=includedir openssl)"
  OPENSSL_LIB_DIR="$(pkg-config --variable=libdir openssl)"
  export OPENSSL_INCLUDE_DIR OPENSSL_LIB_DIR
fi
timeout 1200 cargo test --locked --all-features --tests -- --test-threads=2 2>&1 | tee "$artifact_dir/native.log" || result=$?
timeout 1200 cargo check --locked --target wasm32-unknown-unknown --no-default-features --lib 2>&1 | tee "$artifact_dir/wasm.log" || result=$?
timeout 180 node --test test/*.test.js 2>&1 | tee "$artifact_dir/browser-js.log" || result=$?
if timeout 600 npm ci --prefix runtime/accounting --ignore-scripts --no-audit --no-fund; then
  timeout 180 node --test runtime/accounting/test/*.test.mjs 2>&1 | tee "$artifact_dir/accounting-js.log" || result=$?
else result=$?; fi
cargo fmt --all
tar -cf "$artifact_dir/formatted-source.tar" src/*.rs src/accounting_ledger/*.rs tests/*.rs tests/common/mod.rs tests/accounting_ledger/*.rs examples/*.rs
printf '%s\n' "$result" > "$artifact_dir/validation-status.txt"
(cd "$artifact_dir" && find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
exit "$result"
