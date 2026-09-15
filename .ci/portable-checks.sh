#!/usr/bin/env bash
set -euo pipefail
rustc --version
cargo --version
node --version
artifact_dir="$ARTIFACT_ROOT/$CI_COMMIT_SHA"
mkdir -p "$artifact_dir"
cargo generate-lockfile
cp Cargo.lock "$artifact_dir/Cargo.lock"
date -u +%FT%TZ > "$artifact_dir/dependency-resolution-time.txt"
result=0
timeout 1200 cargo test --locked --features sqlite --all-targets -- --test-threads=2 || result=$?
timeout 120 node --test test/*.test.js || result=$?
cargo fmt --all
tar --create --file "$artifact_dir/formatted-source.tar" src/*.rs tests/*.rs tests/common/mod.rs
(cd "$artifact_dir" && sha256sum Cargo.lock formatted-source.tar > SHA256SUMS)
printf 'Validation status: %s\n' "$result"
exit "$result"
