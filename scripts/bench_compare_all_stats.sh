#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ITERS="${1:-2000}"
RUNS="${2:-5}"
WARMUP_RUNS="${WARMUP_RUNS:-1}"
STATS_MODE="${STATS_MODE:-mean}"
TRIM_COUNT="${TRIM_COUNT:-1}"
LOCAL_BENCH_REUSE="${LOCAL_BENCH_REUSE:-1}"
GLOBAL_SKIP_LOCAL_BUILD="${SKIP_LOCAL_BUILD:-0}"
GLOBAL_LOCAL_BENCH_BIN="${LOCAL_BENCH_BIN:-$ROOT_DIR/bench_productc}"
LOCAL_ROUNDTRIP_METRIC="${LOCAL_ROUNDTRIP_METRIC:-mlkem_roundtrip_core_ns_per_op}"
if [ -n "${C_COMPILER:-}" ]; then
  C_COMPILER="$C_COMPILER"
elif command -v clang >/dev/null 2>&1; then
  C_COMPILER="clang"
else
  C_COMPILER="gcc"
fi
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-allstats.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

if ! [[ "$ITERS" =~ ^[0-9]+$ ]] || [ "$ITERS" -le 0 ]; then
  echo "invalid iteration count: $ITERS" >&2
  exit 1
fi
if ! [[ "$RUNS" =~ ^[0-9]+$ ]] || [ "$RUNS" -le 0 ]; then
  echo "invalid run count: $RUNS" >&2
  exit 1
fi
if ! [[ "$WARMUP_RUNS" =~ ^[0-9]+$ ]]; then
  echo "invalid warmup run count: $WARMUP_RUNS" >&2
  exit 1
fi
if ! [[ "$TRIM_COUNT" =~ ^[0-9]+$ ]]; then
  echo "invalid trim count: $TRIM_COUNT" >&2
  exit 1
fi
if ! [[ "$LOCAL_BENCH_REUSE" =~ ^(0|1)$ ]]; then
  echo "invalid LOCAL_BENCH_REUSE: $LOCAL_BENCH_REUSE (expected 0|1)" >&2
  exit 1
fi
if ! [[ "$GLOBAL_SKIP_LOCAL_BUILD" =~ ^(0|1)$ ]]; then
  echo "invalid SKIP_LOCAL_BUILD: $GLOBAL_SKIP_LOCAL_BUILD (expected 0|1)" >&2
  exit 1
fi
case "$STATS_MODE" in
  mean|median|trimmed)
    ;;
  *)
    echo "invalid stats mode: $STATS_MODE (expected mean|median|trimmed)" >&2
    exit 1
    ;;
esac

calc_stats() {
  local label="$1"
  local local_vals="$2"
  local comp_vals="$3"
  local paired="$WORK_DIR/${label}_paired.txt"

  local n_local n_comp
  n_local="$(wc -l < "$local_vals" | tr -d ' ')"
  n_comp="$(wc -l < "$comp_vals" | tr -d ' ')"

  if [ "$n_local" -ne "$RUNS" ] || [ "$n_comp" -ne "$RUNS" ]; then
    echo "[$label] parse error: expected $RUNS values, got local=$n_local competitor=$n_comp" >&2
    return 1
  fi

  paste -d' ' "$local_vals" "$comp_vals" > "$paired"

  awk -v name="$label" -v mode="$STATS_MODE" -v trim="$TRIM_COUNT" '
function copy_and_sort(src, n, dst,   i, j, key) {
  for (i = 1; i <= n; i++) {
    dst[i] = src[i];
  }
  for (i = 2; i <= n; i++) {
    key = dst[i];
    j = i - 1;
    while (j >= 1 && dst[j] > key) {
      dst[j + 1] = dst[j];
      j--;
    }
    dst[j + 1] = key;
  }
}
function median(sorted, n,   m) {
  if (n % 2 == 1) {
    return sorted[(n + 1) / 2];
  }
  m = n / 2;
  return (sorted[m] + sorted[m + 1]) / 2.0;
}
function mean_range(sorted, lo, hi,   i, s, c) {
  s = 0;
  c = 0;
  for (i = lo; i <= hi; i++) {
    s += sorted[i];
    c++;
  }
  return (c > 0) ? (s / c) : 0;
}
BEGIN { n=0; sum_l=0; sum_c=0; sumsq_l=0; sumsq_c=0 }
{
  l[n + 1]=$1+0;
  c[n + 1]=$2+0;
  ll=l[n + 1];
  cc=c[n + 1];
  n++;
  sum_l += ll;
  sum_c += cc;
  sumsq_l += ll*ll;
  sumsq_c += cc*cc;
}
END {
  if (n == 0) {
    printf("[%s] no data\n", name);
    exit 1;
  }
  mean_l = sum_l / n;
  mean_c = sum_c / n;
  sd_l = (n > 1) ? sqrt((sumsq_l - n*mean_l*mean_l) / (n - 1)) : 0;
  sd_c = (n > 1) ? sqrt((sumsq_c - n*mean_c*mean_c) / (n - 1)) : 0;
  copy_and_sort(l, n, ls);
  copy_and_sort(c, n, cs);
  med_l = median(ls, n);
  med_c = median(cs, n);

  trim_eff = trim + 0;
  if (trim_eff < 0) {
    trim_eff = 0;
  }
  if (2 * trim_eff >= n) {
    trim_eff = 0;
  }
  lo = 1 + trim_eff;
  hi = n - trim_eff;
  trim_l = mean_range(ls, lo, hi);
  trim_c = mean_range(cs, lo, hi);

  mode_eff = mode;
  if (mode_eff != "mean" && mode_eff != "median" && mode_eff != "trimmed") {
    mode_eff = "mean";
  }
  sel_l = mean_l;
  sel_c = mean_c;
  if (mode_eff == "median") {
    sel_l = med_l;
    sel_c = med_c;
  } else if (mode_eff == "trimmed") {
    sel_l = trim_l;
    sel_c = trim_c;
  }

  printf("[%s]\n", name);
  printf("runs=%d\n", n);
  printf("stats_mode_requested=%s\n", mode);
  printf("stats_mode_effective=%s\n", mode_eff);
  printf("trim_count_requested=%d\n", trim + 0);
  printf("trim_count_effective=%d\n", trim_eff);
  printf("local_roundtrip_mean_ns=%.2f\n", mean_l);
  printf("local_roundtrip_sd_ns=%.2f\n", sd_l);
  printf("local_roundtrip_median_ns=%.2f\n", med_l);
  printf("local_roundtrip_trimmed_ns=%.2f\n", trim_l);
  printf("competitor_roundtrip_mean_ns=%.2f\n", mean_c);
  printf("competitor_roundtrip_sd_ns=%.2f\n", sd_c);
  printf("competitor_roundtrip_median_ns=%.2f\n", med_c);
  printf("competitor_roundtrip_trimmed_ns=%.2f\n", trim_c);
  printf("selected_local_roundtrip_ns=%.2f\n", sel_l);
  printf("selected_competitor_roundtrip_ns=%.2f\n", sel_c);
  printf("local_ns_div_competitor_ns=%.3fx\n", (sel_c > 0) ? sel_l / sel_c : 0);
  printf("local_speedup_vs_competitor=%.3fx\n", (sel_l > 0) ? sel_c / sel_l : 0);
}' "$paired"
}

extract_local_roundtrip() {
  local file="$1"
  awk -F= -v metric="$LOCAL_ROUNDTRIP_METRIC" '$1 == metric {print $2; exit}' "$file"
}

extract_comp_roundtrip() {
  local label="$1"
  local file="$2"

  case "$label" in
    pqclean_avx2)
      awk -F= '
        /^--- pqclean avx2 ---$/ { in_avx2 = 1; next }
        in_avx2 && $1 == "roundtrip_ns_per_op" { print $2; exit }
      ' "$file"
      ;;
    liboqs)
      awk -F= '$1 == "liboqs_mlkem768_roundtrip_ns_per_op" {print $2; exit}' "$file"
      ;;
    kyber_upstream_avx2)
      awk -F= '$1 == "kyber_avx2_roundtrip_ns_per_op" {print $2; exit}' "$file"
      ;;
    kyber_upstream_avx2_fair)
      awk -F= '$1 == "kyber_avx2_roundtrip_ns_per_op" {print $2; exit}' "$file"
      ;;
    mlkem_native)
      awk -F= '$1 == "mlkem_native_roundtrip_ns_per_op" {print $2; exit}' "$file"
      ;;
    boringssl)
      awk -F= '$1 == "boringssl_mlkem768_roundtrip_ns_per_op" {print $2; exit}' "$file"
      ;;
    libcrux_rust)
      awk -F= '$1 == "libcrux_mlkem768_roundtrip_ns_per_op" {print $2; exit}' "$file"
      ;;
    libjade_kyber768_avx2)
      awk -F= '$1 == "libjade_kyber768_avx2_roundtrip_ns_per_op" {print $2; exit}' "$file"
      ;;
    botan_mlkem)
      awk -F= '$1 == "botan_mlkem768_roundtrip_ns_per_op" {print $2; exit}' "$file"
      ;;
    openssl_mlkem)
      awk -F= '$1 == "openssl_mlkem768_roundtrip_ns_per_op" {print $2; exit}' "$file"
      ;;
    *)
      return 1
      ;;
  esac
}

run_suite() {
  local label="$1"
  local script="$2"
  local upstream_flags="${3:-}"
  local update_repos_once="${UPDATE_REPOS:-0}"
  local raw_dir="$WORK_DIR/${label}_raw"
  local local_vals="$WORK_DIR/${label}_local.txt"
  local comp_vals="$WORK_DIR/${label}_comp.txt"

  mkdir -p "$raw_dir"
  : > "$local_vals"
  : > "$comp_vals"

  for i in $(seq 1 "$WARMUP_RUNS"); do
    local warmup_file="$raw_dir/warmup_${i}.txt"
    echo "[$label] warmup=$i/$WARMUP_RUNS"
    if [ -n "$upstream_flags" ]; then
      UPDATE_REPOS="$update_repos_once" \
      C_COMPILER="$C_COMPILER" \
      SKIP_LOCAL_BUILD="$GLOBAL_SKIP_LOCAL_BUILD" \
      LOCAL_BENCH_BIN="$GLOBAL_LOCAL_BENCH_BIN" \
      LOCAL_ROUNDTRIP_METRIC="$LOCAL_ROUNDTRIP_METRIC" \
      UPSTREAM_CFLAGS="$upstream_flags" \
      "$ROOT_DIR/$script" "$ITERS" > "$warmup_file"
    else
      UPDATE_REPOS="$update_repos_once" \
      C_COMPILER="$C_COMPILER" \
      SKIP_LOCAL_BUILD="$GLOBAL_SKIP_LOCAL_BUILD" \
      LOCAL_BENCH_BIN="$GLOBAL_LOCAL_BENCH_BIN" \
      LOCAL_ROUNDTRIP_METRIC="$LOCAL_ROUNDTRIP_METRIC" \
      "$ROOT_DIR/$script" "$ITERS" > "$warmup_file"
    fi
    update_repos_once=0
  done

  for i in $(seq 1 "$RUNS"); do
    local out_file="$raw_dir/run_${i}.txt"
    echo "[$label] run=$i/$RUNS"
    if [ -n "$upstream_flags" ]; then
      UPDATE_REPOS="$update_repos_once" \
      C_COMPILER="$C_COMPILER" \
      SKIP_LOCAL_BUILD="$GLOBAL_SKIP_LOCAL_BUILD" \
      LOCAL_BENCH_BIN="$GLOBAL_LOCAL_BENCH_BIN" \
      LOCAL_ROUNDTRIP_METRIC="$LOCAL_ROUNDTRIP_METRIC" \
      UPSTREAM_CFLAGS="$upstream_flags" \
      "$ROOT_DIR/$script" "$ITERS" > "$out_file"
    else
      UPDATE_REPOS="$update_repos_once" \
      C_COMPILER="$C_COMPILER" \
      SKIP_LOCAL_BUILD="$GLOBAL_SKIP_LOCAL_BUILD" \
      LOCAL_BENCH_BIN="$GLOBAL_LOCAL_BENCH_BIN" \
      LOCAL_ROUNDTRIP_METRIC="$LOCAL_ROUNDTRIP_METRIC" \
      "$ROOT_DIR/$script" "$ITERS" > "$out_file"
    fi
    update_repos_once=0

    local local_rt
    local comp_rt
    local_rt="$(extract_local_roundtrip "$out_file")"
    comp_rt="$(extract_comp_roundtrip "$label" "$out_file")"

    if [ -z "$local_rt" ] || [ -z "$comp_rt" ]; then
      echo "[$label] failed to parse run $i output" >&2
      echo "--- begin output ---" >&2
      cat "$out_file" >&2
      echo "--- end output ---" >&2
      return 1
    fi

    echo "$local_rt" >> "$local_vals"
    echo "$comp_rt" >> "$comp_vals"

    printf "[%s] run=%d local=%s competitor=%s\n" "$label" "$i" "$local_rt" "$comp_rt"
  done

  calc_stats "$label" "$local_vals" "$comp_vals"
  echo
}

if [ "$GLOBAL_SKIP_LOCAL_BUILD" = "1" ]; then
  if [ ! -x "$GLOBAL_LOCAL_BENCH_BIN" ]; then
    echo "LOCAL_BENCH_BIN is not executable: $GLOBAL_LOCAL_BENCH_BIN" >&2
    exit 1
  fi
elif [ "$LOCAL_BENCH_REUSE" = "1" ]; then
  echo "[all-stats] building local benchmark once for reuse"
  make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null
  make -C "$ROOT_DIR" bench-product CC="$C_COMPILER" >/dev/null
  GLOBAL_SKIP_LOCAL_BUILD=1
  GLOBAL_LOCAL_BENCH_BIN="$ROOT_DIR/bench_productc"
fi

printf "iters=%s runs=%s\n" "$ITERS" "$RUNS"
printf "warmup_runs=%s\n" "$WARMUP_RUNS"
printf "local_AVX2_BACKEND=%s\n" "${AVX2_BACKEND:-core (Makefile default)}"
printf "PIN_CPU=%s\n" "${PIN_CPU:-<unset>}"
printf "C_COMPILER=%s\n" "$C_COMPILER"
printf "UPDATE_REPOS=%s\n" "${UPDATE_REPOS:-0}"
printf "stats_mode=%s\n" "$STATS_MODE"
printf "trim_count=%s\n" "$TRIM_COUNT"
printf "local_bench_reuse=%s\n" "$LOCAL_BENCH_REUSE"
printf "skip_local_build=%s\n" "$GLOBAL_SKIP_LOCAL_BUILD"
printf "local_bench_bin=%s\n" "$GLOBAL_LOCAL_BENCH_BIN"
printf "local_roundtrip_metric=%s\n" "$LOCAL_ROUNDTRIP_METRIC"
printf "local_OPT_CFLAGS=%s\n" "${OPT_CFLAGS:-<Makefile default>}"
printf "local_EXTRA_CFLAGS=%s\n" "${EXTRA_CFLAGS:-<Makefile default>}"
printf "local_ASFLAGS=%s\n" "${ASFLAGS:-<Makefile default>}"
printf "mlkem_native_auto=%s\n" "${MLKEM_NATIVE_AUTO:-1}"
printf "upstream_cflags=%s\n" "${UPSTREAM_CFLAGS:--O3 -march=native -mavx2 -mbmi2 -mpopcnt -fomit-frame-pointer -std=c99}"

if [ -n "${OPT_CFLAGS+x}" ]; then
  EFFECTIVE_LOCAL_OPT_CFLAGS="$OPT_CFLAGS"
else
  if [[ "$C_COMPILER" == *clang* ]]; then
    EFFECTIVE_LOCAL_OPT_CFLAGS="-O3 -fno-semantic-interposition -fvisibility=hidden"
  else
    EFFECTIVE_LOCAL_OPT_CFLAGS="-O2 -flto -fno-semantic-interposition"
  fi
fi

if [ -n "${EXTRA_CFLAGS+x}" ]; then
  EFFECTIVE_LOCAL_EXTRA_CFLAGS="$EXTRA_CFLAGS"
else
  if [[ "$C_COMPILER" == *clang* ]]; then
    EFFECTIVE_LOCAL_EXTRA_CFLAGS="-fomit-frame-pointer -fno-stack-protector -falign-loops=64 -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-strict-aliasing"
  else
    EFFECTIVE_LOCAL_EXTRA_CFLAGS="-funroll-loops -fomit-frame-pointer -fno-stack-protector -falign-loops=32 -finline-functions"
  fi
fi

printf "effective_local_OPT_CFLAGS=%s\n" "$EFFECTIVE_LOCAL_OPT_CFLAGS"
printf "effective_local_EXTRA_CFLAGS=%s\n" "$EFFECTIVE_LOCAL_EXTRA_CFLAGS"
FAIR_UPSTREAM_CFLAGS="${FAIR_UPSTREAM_CFLAGS:-$EFFECTIVE_LOCAL_OPT_CFLAGS -march=native -mavx2 -mbmi2 -mpopcnt $EFFECTIVE_LOCAL_EXTRA_CFLAGS -std=c99}"
printf "fair_upstream_cflags=%s\n" "$FAIR_UPSTREAM_CFLAGS"
echo

run_suite "kyber_upstream_avx2" "scripts/bench_compare_kyber_upstream.sh"
run_suite "kyber_upstream_avx2_fair" "scripts/bench_compare_kyber_upstream.sh" "$FAIR_UPSTREAM_CFLAGS"
run_suite "mlkem_native" "scripts/bench_compare_mlkem_native.sh"
run_suite "pqclean_avx2" "scripts/bench_compare_pqclean.sh"
run_suite "liboqs" "scripts/bench_compare_liboqs.sh"
run_suite "boringssl" "scripts/bench_compare_boringssl.sh"
run_suite "libcrux_rust" "scripts/bench_compare_libcrux.sh"
run_suite "libjade_kyber768_avx2" "scripts/bench_compare_libjade.sh"
run_suite "botan_mlkem" "scripts/bench_compare_botan_mlkem.sh"
run_suite "openssl_mlkem" "scripts/bench_compare_openssl_mlkem.sh"
