#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE="${PROFILE:-native}"
ITERS="${1:-100000}"
RUNS="${RUNS:-15}"
WARMUP_RUNS="${WARMUP_RUNS:-3}"
BOOTSTRAP_SAMPLES="${BOOTSTRAP_SAMPLES:-20000}"
PIN_CPU="${PIN_CPU:-0}"
REPORT_FILE="${REPORT_FILE:-/tmp/baby-mlkem-goal-native-speed.txt}"
EXPECTED_SUITES="kyber_upstream_avx2,kyber_upstream_avx2_fair,mlkem_native,"
EXPECTED_SUITES+="pqclean_avx2,liboqs,boringssl,libcrux_rust,"
EXPECTED_SUITES+="libjade_kyber768_avx2,botan_mlkem,openssl_mlkem"

if [ "$PROFILE" != "native" ]; then
  echo "unsupported goal speed profile: $PROFILE (only native is implemented)" >&2
  exit 2
fi
if ! [[ "$ITERS" =~ ^[0-9]+$ ]] || [ "$ITERS" -le 0 ]; then
  echo "invalid iteration count: $ITERS" >&2
  exit 2
fi
if ! [[ "$RUNS" =~ ^[0-9]+$ ]] || [ "$RUNS" -lt 15 ]; then
  echo "RUNS must be an integer >= 15" >&2
  exit 2
fi
if ! [[ "$WARMUP_RUNS" =~ ^[0-9]+$ ]] || [ "$WARMUP_RUNS" -lt 3 ]; then
  echo "WARMUP_RUNS must be an integer >= 3" >&2
  exit 2
fi
if ! [[ "$BOOTSTRAP_SAMPLES" =~ ^[0-9]+$ ]] ||
    [ "$BOOTSTRAP_SAMPLES" -lt 20000 ]; then
  echo "BOOTSTRAP_SAMPLES must be an integer >= 20000" >&2
  exit 2
fi

if [ -n "${C_COMPILER:-}" ]; then
  C_COMPILER="$C_COMPILER"
elif command -v clang >/dev/null 2>&1; then
  C_COMPILER=clang
else
  C_COMPILER=gcc
fi
if ! command -v "$C_COMPILER" >/dev/null 2>&1; then
  echo "compiler not found: $C_COMPILER" >&2
  exit 2
fi
for required_command in git rg sha256sum lscpu; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    echo "required command not found: $required_command" >&2
    exit 2
  fi
done
if [ ! -d "$(dirname "$REPORT_FILE")" ]; then
  echo "report directory does not exist: $(dirname "$REPORT_FILE")" >&2
  exit 2
fi
if [ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=normal)" ]; then
  echo "goal verification requires a clean committed worktree" >&2
  exit 2
fi

BUILD_TAG="$(printf '%s' "$C_COMPILER" | tr '/ ' '__')"
KYBER_DIR="${KYBER_DIR:-/tmp/kyber}"
PQCLEAN_DIR="${PQCLEAN_DIR:-/tmp/PQClean}"
MLKEM_NATIVE_DIR="${MLKEM_NATIVE_DIR:-$ROOT_DIR/../mlkem-native}"
LIBOQS_DIR="${LIBOQS_DIR:-/tmp/liboqs}"
BORINGSSL_DIR="${BORINGSSL_DIR:-/tmp/boringssl}"
LIBCRUX_BENCH_DIR="${LIBCRUX_BENCH_DIR:-/tmp/libcrux-mlkem-bench}"
LIBCRUX_CRATE_VERSION="${LIBCRUX_CRATE_VERSION:-0.0.8}"
DEFAULT_LIBJADE_DIST_URL="https://github.com/formosa-crypto/libjade/releases/"
DEFAULT_LIBJADE_DIST_URL+="download/release/2023.05-2/libjade-dist-src-amd64.tar.gz"
LIBJADE_DIST_URL="${LIBJADE_DIST_URL:-$DEFAULT_LIBJADE_DIST_URL}"
LIBJADE_DIST_ROOT="${LIBJADE_DIST_ROOT:-/tmp/libjade-dist-src-amd64}"
DEFAULT_LIBJADE_KEM_DIR="$LIBJADE_DIST_ROOT/libjade/crypto_kem/"
DEFAULT_LIBJADE_KEM_DIR+="kyber_kyber768_avx2"
LIBJADE_KEM_DIR="${LIBJADE_KEM_DIR:-$DEFAULT_LIBJADE_KEM_DIR}"
BOTAN_DIR="${BOTAN_DIR:-/tmp/botan-mlkem}"
OPENSSL_DIR="${OPENSSL_DIR:-/tmp/openssl-mlkem-$BUILD_TAG}"

work_dir="$(mktemp -d /tmp/baby-mlkem-goal-speed.XXXXXX)"
raw_report="$work_dir/raw-report.txt"
stderr_report="$work_dir/stderr.txt"
revision_report="$work_dir/revisions.txt"
trap 'rm -rf "$work_dir"' EXIT

set +e
WARMUP_RUNS="$WARMUP_RUNS" \
STATS_MODE=median \
TRIM_COUNT=1 \
BOOTSTRAP_SAMPLES="$BOOTSTRAP_SAMPLES" \
BENCH_SUITES="$EXPECTED_SUITES" \
LOCAL_BENCH_REUSE=1 \
LOCAL_ROUNDTRIP_METRIC=mlkem_roundtrip_core_ns_per_op \
PIN_CPU="$PIN_CPU" \
C_COMPILER="$C_COMPILER" \
UPDATE_REPOS=1 \
ALLOW_CACHED_COMPARATOR=0 \
KYBER_DIR="$KYBER_DIR" \
PQCLEAN_DIR="$PQCLEAN_DIR" \
MLKEM_NATIVE_DIR="$MLKEM_NATIVE_DIR" \
LIBOQS_DIR="$LIBOQS_DIR" \
BORINGSSL_DIR="$BORINGSSL_DIR" \
LIBCRUX_BENCH_DIR="$LIBCRUX_BENCH_DIR" \
LIBCRUX_CRATE_VERSION="$LIBCRUX_CRATE_VERSION" \
LIBJADE_DIST_URL="$LIBJADE_DIST_URL" \
LIBJADE_DIST_ROOT="$LIBJADE_DIST_ROOT" \
LIBJADE_KEM_DIR="$LIBJADE_KEM_DIR" \
BOTAN_DIR="$BOTAN_DIR" \
OPENSSL_DIR="$OPENSSL_DIR" \
"$ROOT_DIR/scripts/bench_compare_all_stats.sh" "$ITERS" "$RUNS" \
  > "$raw_report" 2> "$stderr_report"
bench_status=$?
set -e

if [ "$bench_status" -ne 0 ]; then
  cat "$stderr_report" >&2
  echo "external benchmark suite failed with status $bench_status" >&2
  exit "$bench_status"
fi
update_failure_pattern="warning: failed to update|warning: fallback clone failed|"
update_failure_pattern+="warning: cargo update failed|UPDATE_REPOS=1 was set but|"
update_failure_pattern+="using fallback fresh clone"
if rg -n "$update_failure_pattern" "$stderr_report"; then
  cat "$stderr_report" >&2
  echo "comparator update was not fail-closed" >&2
  exit 2
fi

record_git_revision() {
  local name="$1"
  local directory="$2"
  if ! git -C "$directory" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "missing git checkout for $name: $directory" >&2
    return 1
  fi
  if ! git -C "$directory" diff --quiet ||
      ! git -C "$directory" diff --cached --quiet; then
    echo "comparator checkout has tracked changes: $name ($directory)" >&2
    return 1
  fi
  printf "comparator_%s_commit=%s\n" \
    "$name" "$(git -C "$directory" rev-parse HEAD)" >> "$revision_report"
  printf "comparator_%s_remote=%s\n" \
    "$name" "$(git -C "$directory" remote get-url origin)" >> "$revision_report"
}

: > "$revision_report"
record_git_revision kyber "$KYBER_DIR"
record_git_revision pqclean "$PQCLEAN_DIR"
record_git_revision mlkem_native "$MLKEM_NATIVE_DIR"
record_git_revision liboqs "$LIBOQS_DIR"
record_git_revision boringssl "$BORINGSSL_DIR"
record_git_revision botan "$BOTAN_DIR"
record_git_revision openssl "$OPENSSL_DIR"
if [ ! -f "$LIBCRUX_BENCH_DIR/Cargo.lock" ]; then
  echo "missing libcrux Cargo.lock: $LIBCRUX_BENCH_DIR/Cargo.lock" >&2
  exit 2
fi
if [ ! -f "$LIBJADE_KEM_DIR/kyber_kyber768_avx2.s" ]; then
  echo "missing libjade assembly: $LIBJADE_KEM_DIR" >&2
  exit 2
fi
printf "comparator_libcrux_crate_version=%s\n" "$LIBCRUX_CRATE_VERSION" \
  >> "$revision_report"
printf "comparator_libcrux_lock_sha256=%s\n" \
  "$(sha256sum "$LIBCRUX_BENCH_DIR/Cargo.lock" | awk '{print $1}')" \
  >> "$revision_report"
printf "comparator_libjade_url=%s\n" "$LIBJADE_DIST_URL" >> "$revision_report"
printf "comparator_libjade_asm_sha256=%s\n" \
  "$(sha256sum "$LIBJADE_KEM_DIR/kyber_kyber768_avx2.s" | awk '{print $1}')" \
  >> "$revision_report"

host_cpu="$(lscpu | awk -F: '/Model name/ && !seen {
  gsub(/^[[:space:]]+/, "", $2)
  print $2
  seen = 1
}')"
compiler_version="$("$C_COMPILER" --version | sed -n '1p')"

{
  printf "goal_profile=%s\n" "$PROFILE"
  printf "goal_report_utc=%s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf "baby_mlkem_commit=%s\n" "$(git -C "$ROOT_DIR" rev-parse HEAD)"
  printf "host_kernel=%s\n" "$(uname -sr)"
  printf "host_cpu=%s\n" "$host_cpu"
  printf "compiler_version=%s\n" "$compiler_version"
  cat "$revision_report"
  cat "$raw_report"
} > "$REPORT_FILE"
cp "$stderr_report" "${REPORT_FILE}.stderr"

cat "$REPORT_FILE"
"$ROOT_DIR/scripts/verify_goal_speed_report.py" "$REPORT_FILE" \
  --expected-suites "$EXPECTED_SUITES" \
  --expected-profile "$PROFILE" \
  --min-runs 15 \
  --min-warmups 3 \
  --min-bootstrap-samples 20000 \
  --min-aggregate-speedup 1.05 \
  --min-operation-speedup 1.0 \
  --require-updated-repos
printf "goal_speed_report=%s\n" "$REPORT_FILE"
printf "goal_speed_stderr=%s\n" "${REPORT_FILE}.stderr"
