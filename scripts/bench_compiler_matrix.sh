#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ITERS="${1:-2000}"
RUNS="${2:-3}"
COMPILERS="${COMPILERS:-gcc clang}"
PIN_CPU="${PIN_CPU:-0}"
WARMUP_RUNS="${WARMUP_RUNS:-1}"
STATS_MODE="${STATS_MODE:-mean}"
TRIM_COUNT="${TRIM_COUNT:-1}"
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-ccmatrix.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

if ! [[ "$ITERS" =~ ^[0-9]+$ ]] || [ "$ITERS" -le 0 ]; then
  echo "invalid iteration count: $ITERS" >&2
  exit 1
fi
if ! [[ "$RUNS" =~ ^[0-9]+$ ]] || [ "$RUNS" -le 0 ]; then
  echo "invalid run count: $RUNS" >&2
  exit 1
fi

labels=(
  "kyber_upstream_avx2"
  "kyber_upstream_avx2_fair"
  "mlkem_native"
  "pqclean_avx2"
  "liboqs"
  "boringssl"
  "libcrux_rust"
  "libjade_kyber768_avx2"
  "botan_mlkem"
  "openssl_mlkem"
)

extract_speedup() {
  local file="$1"
  local label="$2"
  awk -v target="$label" '
    BEGIN { in_block = 0 }
    $0 == "[" target "]" { in_block = 1; next }
    /^\[/ && $0 != "[" target "]" { in_block = 0 }
    in_block && /^local_speedup_vs_competitor=/ {
      split($0, a, "=");
      print a[2];
      exit;
    }
  ' "$file"
}

extract_local_mean() {
  local file="$1"
  local label="$2"
  awk -v target="$label" '
    BEGIN { in_block = 0 }
    $0 == "[" target "]" { in_block = 1; next }
    /^\[/ && $0 != "[" target "]" { in_block = 0 }
    in_block && /^local_roundtrip_mean_ns=/ {
      split($0, a, "=");
      print a[2];
      exit;
    }
  ' "$file"
}

printf "iters=%s runs=%s warmup_runs=%s pin_cpu=%s\n" "$ITERS" "$RUNS" "$WARMUP_RUNS" "$PIN_CPU"
printf "stats_mode=%s trim_count=%s\n" "$STATS_MODE" "$TRIM_COUNT"
echo
printf "%-10s %-16s %-16s %-14s %-12s %-12s %-12s %-14s %-12s %-12s %-12s %-12s\n" \
  "compiler" "kyber_default" "kyber_fair" "local_mean_ns" "vs_native" "vs_pqclean" "vs_liboqs" "vs_boringssl" "vs_libcrux" "vs_libjade" "vs_botan" "vs_openssl"

for cc in $COMPILERS; do
  if ! command -v "$cc" >/dev/null 2>&1; then
    echo "skip compiler '$cc' (not found)" >&2
    continue
  fi

  out_file="$WORK_DIR/${cc}.txt"
  echo "running suite for compiler=$cc ..."
  PIN_CPU="$PIN_CPU" C_COMPILER="$cc" WARMUP_RUNS="$WARMUP_RUNS" \
    "$ROOT_DIR/scripts/bench_compare_all_stats.sh" "$ITERS" "$RUNS" > "$out_file"

  ky_def="$(extract_speedup "$out_file" "kyber_upstream_avx2")"
  ky_fair="$(extract_speedup "$out_file" "kyber_upstream_avx2_fair")"
  local_mean="$(extract_local_mean "$out_file" "kyber_upstream_avx2")"
  vs_native="$(extract_speedup "$out_file" "mlkem_native")"
  vs_pqclean="$(extract_speedup "$out_file" "pqclean_avx2")"
  vs_liboqs="$(extract_speedup "$out_file" "liboqs")"
  vs_boringssl="$(extract_speedup "$out_file" "boringssl")"
  vs_libcrux="$(extract_speedup "$out_file" "libcrux_rust")"
  vs_libjade="$(extract_speedup "$out_file" "libjade_kyber768_avx2")"
  vs_botan="$(extract_speedup "$out_file" "botan_mlkem")"
  vs_openssl="$(extract_speedup "$out_file" "openssl_mlkem")"

  printf "%-10s %-16s %-16s %-14s %-12s %-12s %-12s %-14s %-12s %-12s %-12s %-12s\n" \
    "$cc" "${ky_def:-n/a}" "${ky_fair:-n/a}" "${local_mean:-n/a}" \
    "${vs_native:-n/a}" "${vs_pqclean:-n/a}" "${vs_liboqs:-n/a}" "${vs_boringssl:-n/a}" "${vs_libcrux:-n/a}" "${vs_libjade:-n/a}" "${vs_botan:-n/a}" "${vs_openssl:-n/a}"
done
