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
BOOTSTRAP_SAMPLES="${BOOTSTRAP_SAMPLES:-20000}"
OPERATIONS=(keygen encaps decaps roundtrip)
DEFAULT_BENCH_SUITES="kyber_upstream_avx2,kyber_upstream_avx2_fair,"
DEFAULT_BENCH_SUITES+="mlkem_native,pqclean_avx2,liboqs,boringssl,"
DEFAULT_BENCH_SUITES+="libcrux_rust,libjade_kyber768_avx2,botan_mlkem,openssl_mlkem"
BENCH_SUITES="${BENCH_SUITES:-$DEFAULT_BENCH_SUITES}"
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
if ! [[ "$BOOTSTRAP_SAMPLES" =~ ^[0-9]+$ ]] || [ "$BOOTSTRAP_SAMPLES" -le 0 ]; then
  echo "invalid bootstrap sample count: $BOOTSTRAP_SAMPLES" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for paired statistics" >&2
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

extract_local_operation() {
  local operation="$1"
  local file="$2"
  local metric

  if [ "$operation" = "roundtrip" ]; then
    metric="$LOCAL_ROUNDTRIP_METRIC"
  else
    metric="mlkem_${operation}_core_ns_per_op"
  fi
  awk -F= -v target="$metric" '$1 == target { print $2; exit }' "$file"
}

competitor_metric_prefix() {
  case "$1" in
    kyber_upstream_avx2|kyber_upstream_avx2_fair)
      printf "kyber_avx2_\n"
      ;;
    mlkem_native)
      printf "mlkem_native_\n"
      ;;
    liboqs)
      printf "liboqs_mlkem768_\n"
      ;;
    boringssl)
      printf "boringssl_mlkem768_\n"
      ;;
    libcrux_rust)
      printf "libcrux_mlkem768_\n"
      ;;
    libjade_kyber768_avx2)
      printf "libjade_kyber768_avx2_\n"
      ;;
    botan_mlkem)
      printf "botan_mlkem768_\n"
      ;;
    openssl_mlkem)
      printf "openssl_mlkem768_\n"
      ;;
    *)
      return 1
      ;;
  esac
}

extract_comp_operation() {
  local label="$1"
  local operation="$2"
  local file="$3"
  local metric

  if [ "$label" = "pqclean_avx2" ]; then
    metric="${operation}_ns_per_op"
    awk -F= -v target="$metric" '
      /^--- pqclean avx2 ---$/ { in_avx2 = 1; next }
      in_avx2 && /^--- / { in_avx2 = 0 }
      in_avx2 && $1 == target { print $2; exit }
    ' "$file"
    return
  fi

  metric="$(competitor_metric_prefix "$label")${operation}_ns_per_op"
  awk -F= -v target="$metric" '$1 == target { print $2; exit }' "$file"
}

pair_order_for_run() {
  if (( $1 % 2 == 1 )); then
    printf "local-first\n"
  else
    printf "competitor-first\n"
  fi
}

run_suite() {
  local label="$1"
  local script="$2"
  local upstream_flags="${3:-}"
  local update_repos_once="${UPDATE_REPOS:-0}"
  local raw_dir="$WORK_DIR/${label}_raw"
  local local_vals="$raw_dir/roundtrip_local.txt"
  local comp_vals="$raw_dir/roundtrip_competitor.txt"
  local operation

  mkdir -p "$raw_dir"
  for operation in "${OPERATIONS[@]}"; do
    : > "$raw_dir/${operation}_local.txt"
    : > "$raw_dir/${operation}_competitor.txt"
  done

  for i in $(seq 1 "$WARMUP_RUNS"); do
    local pair_order
    pair_order="$(pair_order_for_run "$i")"
    local warmup_file="$raw_dir/warmup_${i}.txt"
    echo "[$label] warmup=$i/$WARMUP_RUNS order=$pair_order"
    if [ -n "$upstream_flags" ]; then
      UPDATE_REPOS="$update_repos_once" \
      C_COMPILER="$C_COMPILER" \
      BENCH_PAIR_ORDER="$pair_order" \
      SKIP_LOCAL_BUILD="$GLOBAL_SKIP_LOCAL_BUILD" \
      LOCAL_BENCH_BIN="$GLOBAL_LOCAL_BENCH_BIN" \
      LOCAL_ROUNDTRIP_METRIC="$LOCAL_ROUNDTRIP_METRIC" \
      UPSTREAM_CFLAGS="$upstream_flags" \
      "$ROOT_DIR/$script" "$ITERS" > "$warmup_file"
    else
      UPDATE_REPOS="$update_repos_once" \
      C_COMPILER="$C_COMPILER" \
      BENCH_PAIR_ORDER="$pair_order" \
      SKIP_LOCAL_BUILD="$GLOBAL_SKIP_LOCAL_BUILD" \
      LOCAL_BENCH_BIN="$GLOBAL_LOCAL_BENCH_BIN" \
      LOCAL_ROUNDTRIP_METRIC="$LOCAL_ROUNDTRIP_METRIC" \
      "$ROOT_DIR/$script" "$ITERS" > "$warmup_file"
    fi
    update_repos_once=0
  done

  for i in $(seq 1 "$RUNS"); do
    local pair_order
    pair_order="$(pair_order_for_run "$i")"
    local out_file="$raw_dir/run_${i}.txt"
    echo "[$label] run=$i/$RUNS order=$pair_order"
    if [ -n "$upstream_flags" ]; then
      UPDATE_REPOS="$update_repos_once" \
      C_COMPILER="$C_COMPILER" \
      BENCH_PAIR_ORDER="$pair_order" \
      SKIP_LOCAL_BUILD="$GLOBAL_SKIP_LOCAL_BUILD" \
      LOCAL_BENCH_BIN="$GLOBAL_LOCAL_BENCH_BIN" \
      LOCAL_ROUNDTRIP_METRIC="$LOCAL_ROUNDTRIP_METRIC" \
      UPSTREAM_CFLAGS="$upstream_flags" \
      "$ROOT_DIR/$script" "$ITERS" > "$out_file"
    else
      UPDATE_REPOS="$update_repos_once" \
      C_COMPILER="$C_COMPILER" \
      BENCH_PAIR_ORDER="$pair_order" \
      SKIP_LOCAL_BUILD="$GLOBAL_SKIP_LOCAL_BUILD" \
      LOCAL_BENCH_BIN="$GLOBAL_LOCAL_BENCH_BIN" \
      LOCAL_ROUNDTRIP_METRIC="$LOCAL_ROUNDTRIP_METRIC" \
      "$ROOT_DIR/$script" "$ITERS" > "$out_file"
    fi
    update_repos_once=0

    local -a operation_summary=()
    for operation in "${OPERATIONS[@]}"; do
      local local_value
      local competitor_value
      local_value="$(extract_local_operation "$operation" "$out_file")"
      competitor_value="$(extract_comp_operation "$label" "$operation" "$out_file")"

      if [ -z "$local_value" ] || [ -z "$competitor_value" ]; then
        echo "[$label] failed to parse $operation for run $i" >&2
        echo "--- begin output ---" >&2
        cat "$out_file" >&2
        echo "--- end output ---" >&2
        return 1
      fi

      echo "$local_value" >> "$raw_dir/${operation}_local.txt"
      echo "$competitor_value" >> "$raw_dir/${operation}_competitor.txt"
      operation_summary+=("${operation}=${local_value}/${competitor_value}")
    done

    printf "[%s] run=%d %s\n" "$label" "$i" "${operation_summary[*]}"
  done

  calc_stats "$label" "$local_vals" "$comp_vals"
  printf "paired_bootstrap_samples=%s\n" "$BOOTSTRAP_SAMPLES"
  for operation in "${OPERATIONS[@]}"; do
    "$ROOT_DIR/scripts/paired_benchmark_stats.py" \
      --metric "$operation" \
      --local "$raw_dir/${operation}_local.txt" \
      --competitor "$raw_dir/${operation}_competitor.txt" \
      --expected-runs "$RUNS" \
      --bootstrap-samples "$BOOTSTRAP_SAMPLES"
  done
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
printf "bootstrap_samples=%s\n" "$BOOTSTRAP_SAMPLES"
printf "bench_suites=%s\n" "$BENCH_SUITES"
printf "local_AVX2_BACKEND=%s\n" "${AVX2_BACKEND:-core (Makefile default)}"
printf "PIN_CPU=%s\n" "${PIN_CPU:-<unset>}"
printf "C_COMPILER=%s\n" "$C_COMPILER"
printf "CXX_COMPILER=%s\n" "${CXX_COMPILER:-<auto>}"
printf "gcc_install_dir=%s\n" "${GCC_INSTALL_DIR:-<auto>}"
printf "UPDATE_REPOS=%s\n" "${UPDATE_REPOS:-0}"
printf "allow_cached_comparator=%s\n" "${ALLOW_CACHED_COMPARATOR:-0}"
printf "stats_mode=%s\n" "$STATS_MODE"
printf "trim_count=%s\n" "$TRIM_COUNT"
printf "local_bench_reuse=%s\n" "$LOCAL_BENCH_REUSE"
printf "skip_local_build=%s\n" "$GLOBAL_SKIP_LOCAL_BUILD"
printf "local_bench_bin=%s\n" "$GLOBAL_LOCAL_BENCH_BIN"
printf "local_roundtrip_metric=%s\n" "$LOCAL_ROUNDTRIP_METRIC"
printf "bench_isa_profile=%s\n" "${BENCH_ISA_PROFILE:-native}"
printf "bench_profile_tag=%s\n" "${BENCH_PROFILE_TAG:-native}"
printf "local_OPT_CFLAGS=%s\n" "${OPT_CFLAGS:-<Makefile default>}"
printf "local_EXTRA_CFLAGS=%s\n" "${EXTRA_CFLAGS:-<Makefile default>}"
printf "local_ARCH_CFLAGS=%s\n" "${ARCH_CFLAGS:--march=native}"
printf "local_ASFLAGS=%s\n" "${ASFLAGS:-<Makefile default>}"
printf "mlkem_native_auto=%s\n" "${MLKEM_NATIVE_AUTO:-1}"
printf "mlkem_native_harness_cflags=%s\n" "${MLKEM_NATIVE_HARNESS_CFLAGS:--O3 -march=native -mavx2 -mbmi2 -mpopcnt -maes -fomit-frame-pointer -std=c99}"
printf "upstream_cflags=%s\n" "${UPSTREAM_CFLAGS:--O3 -march=native -mavx2 -mbmi2 -mpopcnt -fomit-frame-pointer -std=c99}"
printf "pqclean_clean_cflags=%s\n" "${PQCLEAN_CLEAN_CFLAGS:--O3 -march=native -std=c99}"
printf "pqclean_avx2_cflags=%s\n" "${PQCLEAN_AVX2_CFLAGS:--mavx2 -mbmi2 -mpopcnt -O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -Wpointer-arith -Wshadow -std=c99 -I../../../common}"
printf "pqclean_harness_cflags=%s\n" "${PQCLEAN_HARNESS_CFLAGS:--O3 -march=native -mavx2 -mbmi2 -mpopcnt -std=c99}"
printf "liboqs_dist_build=%s\n" "${LIBOQS_DIST_BUILD:-OFF}"
printf "liboqs_opt_target=%s\n" "${LIBOQS_OPT_TARGET:-native}"
printf "liboqs_cflags=%s\n" "${LIBOQS_CFLAGS:--O3 -march=native}"
printf "liboqs_harness_cflags=%s\n" "${LIBOQS_HARNESS_CFLAGS:--O3 -march=native}"
printf "boringssl_c_flags=%s\n" "${BORINGSSL_C_FLAGS:-<none>}"
printf "boringssl_cxx_flags=%s\n" "${BORINGSSL_CXX_FLAGS:-<none>}"
printf "boringssl_harness_flags=%s\n" "${BORINGSSL_HARNESS_FLAGS:--O3 -march=native}"
printf "libcrux_rustflags=%s\n" "${RUSTFLAGS_BENCH:--C target-cpu=native -C codegen-units=1}"
printf "libjade_harness_cflags=%s\n" "${LIBJADE_HARNESS_CFLAGS:--D_GNU_SOURCE -O3 -march=native -mavx2 -mbmi2 -mpopcnt -fomit-frame-pointer -std=c99}"
printf "botan_cxx=%s\n" "${BOTAN_CXX:-<auto>}"
printf "botan_cc_family=%s\n" "${BOTAN_CC_FAMILY:-<auto>}"
printf "botan_allow_compiler_fallback=%s\n" "${BOTAN_ALLOW_COMPILER_FALLBACK:-1}"
printf "botan_cxxflags=%s\n" "${BOTAN_CXXFLAGS:--O3 -march=native -mavx2 -mbmi2 -mpopcnt -fomit-frame-pointer -fno-semantic-interposition}"
printf "botan_disabled_modules=%s\n" "${BOTAN_DISABLED_MODULES:-<none>}"
printf "botan_harness_cxxflags=%s\n" "${BOTAN_HARNESS_CXXFLAGS:--O3}"
printf "openssl_cflags=%s\n" "${OPENSSL_CFLAGS:--O3 -fno-semantic-interposition -march=native -mavx2 -mbmi2 -mpopcnt}"
printf "openssl_harness_cflags=%s\n" "${OPENSSL_HARNESS_CFLAGS:--O3 -march=native}"
printf "openssl_ia32cap=%s\n" "${OPENSSL_IA32CAP:-<unset>}"

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

IFS="," read -r -a selected_suites <<< "$BENCH_SUITES"
if [ "${#selected_suites[@]}" -eq 0 ]; then
  echo "BENCH_SUITES must select at least one comparator" >&2
  exit 1
fi

for suite in "${selected_suites[@]}"; do
  case "$suite" in
    kyber_upstream_avx2)
      run_suite "$suite" "scripts/bench_compare_kyber_upstream.sh"
      ;;
    kyber_upstream_avx2_fair)
      run_suite "$suite" "scripts/bench_compare_kyber_upstream.sh" \
        "$FAIR_UPSTREAM_CFLAGS"
      ;;
    mlkem_native)
      run_suite "$suite" "scripts/bench_compare_mlkem_native.sh"
      ;;
    pqclean_avx2)
      run_suite "$suite" "scripts/bench_compare_pqclean.sh"
      ;;
    liboqs)
      run_suite "$suite" "scripts/bench_compare_liboqs.sh"
      ;;
    boringssl)
      run_suite "$suite" "scripts/bench_compare_boringssl.sh"
      ;;
    libcrux_rust)
      run_suite "$suite" "scripts/bench_compare_libcrux.sh"
      ;;
    libjade_kyber768_avx2)
      run_suite "$suite" "scripts/bench_compare_libjade.sh"
      ;;
    botan_mlkem)
      run_suite "$suite" "scripts/bench_compare_botan_mlkem.sh"
      ;;
    openssl_mlkem)
      run_suite "$suite" "scripts/bench_compare_openssl_mlkem.sh"
      ;;
    *)
      echo "unknown BENCH_SUITES entry: $suite" >&2
      exit 1
      ;;
  esac
done
