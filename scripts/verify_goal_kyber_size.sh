#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/goal_speed_profile.sh"
PROFILE="${PROFILE:-native}"
C_COMPILER="${C_COMPILER:-clang}"
KYBER_DIR="${KYBER_DIR:-/tmp/kyber}"
REPORT_FILE="${REPORT_FILE:-/tmp/baby-mlkem-goal-${PROFILE}-kyber-size.txt}"
STACK_RUNS="${STACK_RUNS:-8}"
STACK_USABLE_BYTES="${STACK_USABLE_BYTES:-1048576}"
SIZE_ENFORCE="${SIZE_ENFORCE:-1}"
UPDATE_REPOS="${UPDATE_REPOS:-1}"
REQUIRE_CLEAN_WORKTREE="${REQUIRE_CLEAN_WORKTREE:-1}"

case "$PROFILE" in
  native|avx2) ;;
  *)
    echo "unsupported goal size profile: $PROFILE (expected native|avx2)" >&2
    exit 2
    ;;
esac
for name in SIZE_ENFORCE UPDATE_REPOS REQUIRE_CLEAN_WORKTREE; do
  value="${!name}"
  if [ "$value" != "0" ] && [ "$value" != "1" ]; then
    echo "$name must be 0 or 1" >&2
    exit 2
  fi
done
if ! [[ "$STACK_RUNS" =~ ^[0-9]+$ ]] || [ "$STACK_RUNS" -lt 8 ]; then
  echo "STACK_RUNS must be an integer >= 8" >&2
  exit 2
fi
if ! [[ "$STACK_USABLE_BYTES" =~ ^[0-9]+$ ]] ||
    [ "$STACK_USABLE_BYTES" -lt 65536 ]; then
  echo "STACK_USABLE_BYTES must be an integer >= 65536" >&2
  exit 2
fi
for command in "$C_COMPILER" git make rg nm objdump sha256sum awk lscpu; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command not found: $command" >&2
    exit 2
  fi
done
if [ ! -d "$(dirname "$REPORT_FILE")" ]; then
  echo "report directory does not exist: $(dirname "$REPORT_FILE")" >&2
  exit 2
fi
if [ "$REQUIRE_CLEAN_WORKTREE" = "1" ] &&
    [ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=normal)" ]; then
  echo "goal size verification requires a clean committed worktree" >&2
  exit 2
fi
if ! git -C "$KYBER_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "missing Kyber git checkout: $KYBER_DIR" >&2
  exit 2
fi
if [ -n "$(git -C "$KYBER_DIR" status --porcelain --untracked-files=normal)" ]; then
  echo "Kyber checkout must be clean: $KYBER_DIR" >&2
  exit 2
fi

if [ "$UPDATE_REPOS" = "1" ]; then
  git -C "$KYBER_DIR" pull --ff-only
  comparator_update=pass
else
  comparator_update=skipped
fi

goal_speed_configure_profile "$PROFILE" "$C_COMPILER"
stack_cflags="$OPT_CFLAGS $ARCH_CFLAGS $EXTRA_CFLAGS -std=c99"
work_dir="$(mktemp -d /tmp/baby-mlkem-goal-size.XXXXXX)"
local_artifact="$work_dir/baby_mlkem768_product.o"
kyber_artifact="$work_dir/kyber_mlkem768_product.o"
local_stack_report="$work_dir/local-stack.txt"
kyber_stack_report="$work_dir/kyber-stack.txt"
local_footprint="$work_dir/local-footprint.txt"
kyber_footprint="$work_dir/kyber-footprint.txt"
kyber_build_report="$work_dir/kyber-build.txt"
raw_report="$work_dir/report.txt"
cleanup() {
  make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT

if command -v flock >/dev/null 2>&1; then
  exec 9>"$ROOT_DIR/.bench-compare.lock"
  if ! flock -n 9; then
    echo "waiting_for_bench_lock=$ROOT_DIR/.bench-compare.lock" >&2
    flock 9
  fi
fi

make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null
make -C "$ROOT_DIR" product test-product CC="$C_COMPILER" >/dev/null
cp "$ROOT_DIR/baby_mlkem768_product.o" "$local_artifact"

local_api_count="$(nm -g --defined-only "$local_artifact" |
  awk '$3 ~ /^baby_mlkem768_/ { count++ } END { print count + 0 }')"
if [ "$local_api_count" -ne 3 ]; then
  echo "local product must export exactly three baby_mlkem768 APIs" >&2
  exit 2
fi
cache_pattern='mlkem_internal_caches_enabled|kpke_public_cache_(ek|valid|generation)'
cache_pattern+='|kpke_secret_cache_(dk|valid)|mlkem_ek_hash_cache'
cache_pattern+='|mlkem_cache_generation_counter'
if nm "$local_artifact" | rg -n "$cache_pattern"; then
  echo "local product retained persistent cache metadata" >&2
  exit 2
fi
if [ "$PROFILE" = "avx2" ]; then
  if objdump -d "$local_artifact" | rg -n '%zmm|%k[0-7]' ||
      nm "$local_artifact" | rg -n 'avx512'; then
    echo "local AVX2-only product retained AVX512 code" >&2
    exit 2
  fi
  local_avx512_audit=pass
else
  local_avx512_audit=not-applicable
fi

STACK_RUNS="$STACK_RUNS" STACK_USABLE_BYTES="$STACK_USABLE_BYTES" \
C_COMPILER="$C_COMPILER" STACK_CFLAGS="$stack_cflags" \
  "$ROOT_DIR/scripts/measure_stack_highwater.sh" \
  "$local_artifact" local > "$local_stack_report"
local_max_stack="$(sed -n 's/^max_stack_bytes=//p' "$local_stack_report")"
MAX_STACK_BYTES="$local_max_stack" \
  "$ROOT_DIR/scripts/measure_product_size.sh" \
  "$local_artifact" > "$local_footprint"

PROFILE="$PROFILE" OUTPUT="$kyber_artifact" KYBER_DIR="$KYBER_DIR" \
C_COMPILER="$C_COMPILER" UPSTREAM_CFLAGS="$UPSTREAM_CFLAGS" \
ALLOW_CACHED_COMPARATOR=0 \
  "$ROOT_DIR/scripts/build_goal_kyber_product.sh" > "$kyber_build_report"
STACK_RUNS="$STACK_RUNS" STACK_USABLE_BYTES="$STACK_USABLE_BYTES" \
C_COMPILER="$C_COMPILER" STACK_CFLAGS="$stack_cflags" \
  "$ROOT_DIR/scripts/measure_stack_highwater.sh" \
  "$kyber_artifact" goal > "$kyber_stack_report"
kyber_max_stack="$(sed -n 's/^max_stack_bytes=//p' "$kyber_stack_report")"
REQUIRED_SYMBOLS='goal_mlkem768_keypair_derand goal_mlkem768_encaps_derand goal_mlkem768_decaps' \
MAX_STACK_BYTES="$kyber_max_stack" \
  "$ROOT_DIR/scripts/measure_elf_footprint.sh" \
  "$kyber_artifact" > "$kyber_footprint"

local_primary="$(sed -n 's/^primary_bytes=//p' "$local_footprint")"
kyber_primary="$(sed -n 's/^primary_bytes=//p' "$kyber_footprint")"
local_writable="$(sed -n 's/^writable_bytes=//p' "$local_footprint")"
kyber_writable="$(sed -n 's/^writable_bytes=//p' "$kyber_footprint")"
if [ -z "$local_primary" ] || [ -z "$kyber_primary" ] ||
    [ -z "$local_max_stack" ] || [ -z "$kyber_max_stack" ]; then
  echo "failed to parse size or stack measurements" >&2
  exit 2
fi
primary_delta=$((local_primary - kyber_primary))
stack_delta=$((local_max_stack - kyber_max_stack))
primary_ratio="$(awk -v local="$local_primary" -v other="$kyber_primary" \
  'BEGIN { printf "%.6f", local / other }')"
stack_ratio="$(awk -v local="$local_max_stack" -v other="$kyber_max_stack" \
  'BEGIN { printf "%.6f", local / other }')"
if [ "$local_primary" -le "$kyber_primary" ]; then
  size_gate=PASS
else
  size_gate=FAIL
fi

host_cpu="$(lscpu | awk -F: '/Model name/ && !seen {
  gsub(/^[[:space:]]+/, "", $2)
  print $2
  seen = 1
}')"
{
  printf "goal_size_scope=kyber-only\n"
  printf "goal_completion_qualifying=no\n"
  printf "goal_profile=%s\n" "$PROFILE"
  printf "goal_report_utc=%s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf "baby_mlkem_commit=%s\n" "$(git -C "$ROOT_DIR" rev-parse HEAD)"
  printf "baby_mlkem_remote=%s\n" "$(git -C "$ROOT_DIR" remote get-url origin)"
  printf "kyber_commit=%s\n" "$(git -C "$KYBER_DIR" rev-parse HEAD)"
  printf "kyber_remote=%s\n" "$(git -C "$KYBER_DIR" remote get-url origin)"
  printf "comparator_update=%s\n" "$comparator_update"
  printf "host_kernel=%s\n" "$(uname -sr)"
  printf "host_cpu=%s\n" "$host_cpu"
  printf "compiler=%s\n" "$C_COMPILER"
  printf "compiler_version=%s\n" "$("$C_COMPILER" --version | sed -n '1p')"
  printf "local_opt_cflags=%s\n" "$OPT_CFLAGS"
  printf "local_extra_cflags=%s\n" "$EXTRA_CFLAGS"
  printf "local_arch_cflags=%s\n" "$ARCH_CFLAGS"
  printf "kyber_cflags=%s\n" "$UPSTREAM_CFLAGS"
  printf "stack_runs=%s\n" "$STACK_RUNS"
  printf "stack_usable_bytes=%s\n" "$STACK_USABLE_BYTES"
  printf "local_api_count=%s\n" "$local_api_count"
  printf "local_cache_audit=pass\n"
  printf "local_avx512_audit=%s\n" "$local_avx512_audit"
  sed 's/^/local_footprint_/' "$local_footprint"
  sed 's/^/local_stack_/' "$local_stack_report"
  sed 's/^/kyber_build_/' "$kyber_build_report"
  sed 's/^/kyber_footprint_/' "$kyber_footprint"
  sed 's/^/kyber_stack_/' "$kyber_stack_report"
  printf "local_primary_bytes=%s\n" "$local_primary"
  printf "kyber_primary_bytes=%s\n" "$kyber_primary"
  printf "local_writable_bytes=%s\n" "$local_writable"
  printf "kyber_writable_bytes=%s\n" "$kyber_writable"
  printf "local_max_stack_bytes=%s\n" "$local_max_stack"
  printf "kyber_max_stack_bytes=%s\n" "$kyber_max_stack"
  printf "local_over_kyber_primary_ratio=%s\n" "$primary_ratio"
  printf "local_minus_kyber_primary_bytes=%s\n" "$primary_delta"
  printf "local_over_kyber_stack_ratio=%s\n" "$stack_ratio"
  printf "local_minus_kyber_stack_bytes=%s\n" "$stack_delta"
  printf "kyber_size_gate=%s\n" "$size_gate"
} > "$raw_report"

cp "$raw_report" "$REPORT_FILE"
cat "$REPORT_FILE"
printf "goal_kyber_size_report=%s\n" "$REPORT_FILE"
if [ "$SIZE_ENFORCE" = "1" ] && [ "$size_gate" != "PASS" ]; then
  echo "Kyber size gate failed: local primary exceeds comparator" >&2
  exit 1
fi
