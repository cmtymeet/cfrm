#!/usr/bin/env bash
# Isolated feasibility experiment; production private accounting remains closed.
set -euo pipefail
rustc --version
cargo --version
node --version
artifact_dir="$ARTIFACT_ROOT/$CI_COMMIT_SHA/private-accounting"
export HASH_SCHEME="${HASH_SCHEME:-sha256-v1}"
case "$HASH_SCHEME" in
  sha256-v1) ;;
  poseidon2-bn254-fixed-128-v1) artifact_dir="$artifact_dir-$HASH_SCHEME" ;;
  *) printf 'Unknown accounting commitment scheme\n'; exit 2 ;;
esac
case "${CHECK_PHASE:-full}" in
  full) ;;
  profile)
    [[ "${CIRCUIT_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || exit 2
    artifact_dir="$artifact_dir-profile-$CIRCUIT_SHA256"
    ;;
  *) printf 'Unknown private accounting check phase\n'; exit 2 ;;
esac
mkdir -p "$artifact_dir"
artifact_dir="$(realpath "$artifact_dir")"
cd experiments/private-accounting
capture() {
  local result=$?
  trap - EXIT
  set +e
  printf '%s\n' "$result" > "$artifact_dir/validation-status.txt"
  test ! -f package-lock.json || cp package-lock.json "$artifact_dir/package-lock.json"
  test ! -f native/Cargo.lock || cp native/Cargo.lock "$artifact_dir/native-Cargo.lock"
  test ! -f setup-lock.json || cp setup-lock.json "$artifact_dir/setup-lock.json"
  for name in manifest.json circuit.json; do
    test ! -f "public/$name" || cp "public/$name" "$artifact_dir/$name"
  done
  if test -d dist; then tar --create --file "$artifact_dir/browser-package.tar" dist; fi
  (
    cd "$artifact_dir"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
  )
  printf 'Private accounting experiment status: %s\n' "$result"
  exit "$result"
}
trap capture EXIT
if test "${RESOLVE_DEPENDENCIES:-0}" = 1; then
  timeout 600 npm install --package-lock-only --ignore-scripts --no-audit --no-fund \
    2>&1 | tee "$artifact_dir/npm-resolution.log"
  if test -f native/Cargo.lock; then
    cargo update --manifest-path native/Cargo.toml --workspace
  else
    cargo generate-lockfile --manifest-path native/Cargo.toml
  fi
  date -u +%FT%TZ > "$artifact_dir/dependency-resolution-time.txt"
fi
test -f package-lock.json
test -f native/Cargo.lock
# Both configured CI executors are Linux x86_64 with glibc. Pin that optional
# binary selection: the bundler's autodetection selects musl on this Nix worker.
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64
timeout 600 npm ci --libc=glibc --ignore-scripts --no-audit --no-fund \
  2>&1 | tee "$artifact_dir/npm-install.log"
if test "${CHECK_PHASE:-full}" = profile; then
  test -n "$CIRCUIT_PATH"
  test -n "$CIRCUIT_SHA256"
  export CIRCUIT_PATH CIRCUIT_SHA256
  PROFILE_ARTIFACT_DIR="$artifact_dir" timeout 300 node profile.mjs \
    2>&1 | tee "$artifact_dir/circuit-profile.log"
  exit 0
fi
test -x "$BROWSER_BIN"
timeout 1200 cargo build --locked --manifest-path native/Cargo.toml --release \
  2>&1 | tee "$artifact_dir/native-build.log"
cargo fmt --manifest-path native/Cargo.toml
tar --create --file "$artifact_dir/formatted-native-source.tar" native/src
CFRM_BUNDLER_BINDING="$PWD/node_modules/@rolldown/binding-linux-x64-gnu" \
  timeout 900 npm run build 2>&1 | tee "$artifact_dir/browser-build.log"
export ACCOUNTING_FIXTURE="$CARGO_TARGET_DIR/release/cfrm-private-accounting-fixture"
export BROWSER_EVIDENCE="$artifact_dir/browser-evidence.json"
export ACCOUNTING_ARTIFACT_DIR="$artifact_dir"
export BROWSER_BIN
test -x "$ACCOUNTING_FIXTURE"
sha256sum "$ACCOUNTING_FIXTURE" > "$artifact_dir/native-fixture.sha256"
timeout --kill-after=15 1200 npm test 2>&1 | tee "$artifact_dir/browser-harness.log"
