#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ITERS="${1:-2000}"
RUNS="${2:-3}"
PIN_CPU="${PIN_CPU:-0}"
WARMUP_RUNS="${WARMUP_RUNS:-1}"
SLEEP_BETWEEN_RUNS="${SLEEP_BETWEEN_RUNS:-0}"
SLEEP_BETWEEN_COMBOS="${SLEEP_BETWEEN_COMBOS:-0}"
if [ -n "${C_COMPILER:-}" ]; then
  C_COMPILER="$C_COMPILER"
elif command -v clang >/dev/null 2>&1; then
  C_COMPILER="clang"
else
  C_COMPILER="gcc"
fi
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-tune.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

if ! [[ "$ITERS" =~ ^[0-9]+$ ]] || [ "$ITERS" -le 0 ]; then
  echo "invalid iteration count: $ITERS" >&2
  exit 1
fi
if ! [[ "$RUNS" =~ ^[0-9]+$ ]] || [ "$RUNS" -le 0 ]; then
  echo "invalid run count: $RUNS" >&2
  exit 1
fi
if ! [[ "$WARMUP_RUNS" =~ ^[0-9]+$ ]] || [ "$WARMUP_RUNS" -lt 0 ]; then
  echo "invalid warmup run count: $WARMUP_RUNS" >&2
  exit 1
fi
if ! [[ "$SLEEP_BETWEEN_RUNS" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "invalid sleep between runs: $SLEEP_BETWEEN_RUNS" >&2
  exit 1
fi
if ! [[ "$SLEEP_BETWEEN_COMBOS" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "invalid sleep between combos: $SLEEP_BETWEEN_COMBOS" >&2
  exit 1
fi

ARCH_FLAGS="-march=native -mavx2 -mbmi2 -mpopcnt -std=c99"

declare -a OPT_SET
declare -a EXTRA_SET

if [[ "$C_COMPILER" == *clang* ]]; then
  OPT_SET=(
    "-O3 -fno-semantic-interposition"
    "-O3 -fno-semantic-interposition -fvisibility=hidden"
    "-O3 -flto -fno-semantic-interposition"
    "-O2 -flto -fno-semantic-interposition"
    "-Ofast -flto -fno-semantic-interposition"
    "-O3 -fno-semantic-interposition -fno-plt"
    "-O3 -fno-semantic-interposition -fno-slp-vectorize"
    "-O3 -fno-semantic-interposition -fno-vectorize"
    "-O3 -fno-semantic-interposition -fno-strict-aliasing"
  )
  EXTRA_SET=(
    "-fomit-frame-pointer -fno-stack-protector -falign-loops=64 -fno-unwind-tables -fno-asynchronous-unwind-tables"
    "-fomit-frame-pointer -fno-stack-protector -falign-loops=64 -fno-unwind-tables -fno-asynchronous-unwind-tables -falign-functions=32"
    "-fomit-frame-pointer -fno-stack-protector -falign-loops=64 -fno-unwind-tables -fno-asynchronous-unwind-tables -falign-functions=64"
  )
else
  OPT_SET=(
    "-O2 -flto -fno-semantic-interposition"
    "-O3 -flto -fno-semantic-interposition"
    "-Ofast -flto -fno-semantic-interposition"
  )
  EXTRA_SET=(
    "-funroll-loops -fomit-frame-pointer -fno-stack-protector -falign-loops=32"
    "-funroll-loops -fomit-frame-pointer -fno-stack-protector -falign-loops=32 -finline-functions"
    "-funroll-loops -fomit-frame-pointer -fno-stack-protector -falign-loops=32 -falign-functions=32"
    "-funroll-loops -fomit-frame-pointer -fno-stack-protector -falign-loops=32 -falign-functions=64"
    "-funroll-loops -fomit-frame-pointer -fno-stack-protector -falign-loops=32 -frename-registers"
  )
fi

RESULTS="$WORK_DIR/results.tsv"
: > "$RESULTS"

run_combo() {
  local opt="$1"
  local extra="$2"
  local vals="$3"
  local upstream_flags="$opt $ARCH_FLAGS $extra"

  echo "building local bench: CC='$C_COMPILER' OPT_CFLAGS='$opt' EXTRA_CFLAGS='$extra'"
  make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null
  make -C "$ROOT_DIR" bench CC="$C_COMPILER" OPT_CFLAGS="$opt" EXTRA_CFLAGS="$extra" >/dev/null

  : > "$vals"
  for i in $(seq 1 "$WARMUP_RUNS"); do
    PIN_CPU="$PIN_CPU" \
    C_COMPILER="$C_COMPILER" \
    SKIP_LOCAL_BUILD=1 \
    LOCAL_BENCH_BIN="$ROOT_DIR/benchc" \
    UPSTREAM_CFLAGS="$upstream_flags" \
    "$ROOT_DIR/scripts/bench_compare_kyber_upstream.sh" "$ITERS" >/dev/null
  done

  for i in $(seq 1 "$RUNS"); do
    local out
    out="$(
      PIN_CPU="$PIN_CPU" \
      C_COMPILER="$C_COMPILER" \
      SKIP_LOCAL_BUILD=1 \
      LOCAL_BENCH_BIN="$ROOT_DIR/benchc" \
      UPSTREAM_CFLAGS="$upstream_flags" \
      "$ROOT_DIR/scripts/bench_compare_kyber_upstream.sh" "$ITERS"
    )"

    local l k
    l="$(echo "$out" | awk -F= '$1 == "mlkem_roundtrip_ns_per_op" {print $2; exit}')"
    k="$(echo "$out" | awk -F= '$1 == "kyber_avx2_roundtrip_ns_per_op" {print $2; exit}')"
    if [ -z "$l" ] || [ -z "$k" ]; then
      echo "failed to parse comparison output for combo" >&2
      exit 1
    fi
    printf "%s %s\n" "$l" "$k" >> "$vals"
    printf "  run=%d local=%s kyber=%s\n" "$i" "$l" "$k"
    if [ "$SLEEP_BETWEEN_RUNS" != "0" ]; then
      sleep "$SLEEP_BETWEEN_RUNS"
    fi
  done
}

combo_id=0
for opt in "${OPT_SET[@]}"; do
  for extra in "${EXTRA_SET[@]}"; do
    combo_id=$((combo_id + 1))
    vals="$WORK_DIR/combo_${combo_id}.txt"
    echo "=== combo=$combo_id ==="
    run_combo "$opt" "$extra" "$vals"

    awk -v id="$combo_id" -v opt="$opt" -v extra="$extra" '
BEGIN { n=0; sl=0; sk=0; s2l=0; s2k=0 }
{
  l = $1 + 0;
  k = $2 + 0;
  n++;
  sl += l; sk += k;
  s2l += l*l; s2k += k*k;
}
END {
  ml = sl / n;
  mk = sk / n;
  sdl = (n > 1) ? sqrt((s2l - n*ml*ml) / (n - 1)) : 0;
  sdk = (n > 1) ? sqrt((s2k - n*mk*mk) / (n - 1)) : 0;
  spd = (ml > 0) ? mk / ml : 0;
  printf("%d\t%.2f\t%.2f\t%.2f\t%.2f\t%.3f\t%s\t%s\n",
         id, ml, sdl, mk, sdk, spd, opt, extra);
}' "$vals" >> "$RESULTS"

    echo
    if [ "$SLEEP_BETWEEN_COMBOS" != "0" ]; then
      sleep "$SLEEP_BETWEEN_COMBOS"
    fi
  done
done

echo "=== ranked by local mean ns/op (lower is better) ==="
sort -t $'\t' -k2,2n "$RESULTS" | awk -F '\t' '
BEGIN {
  printf("%-6s %-12s %-12s %-12s %-12s %-10s %s\n",
         "id", "local_mean", "local_sd", "kyber_mean", "kyber_sd", "speedup", "flags");
}
{
  printf("%-6s %-12s %-12s %-12s %-12s %-10s OPT=%s | EXTRA=%s\n",
         $1, $2, $3, $4, $5, $6, $7, $8);
}'
