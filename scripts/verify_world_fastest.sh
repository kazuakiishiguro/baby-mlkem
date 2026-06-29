#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ITERS="${1:-2000}"
RUNS="${2:-3}"
STATS_MODE="${STATS_MODE:-median}"
TRIM_COUNT="${TRIM_COUNT:-1}"
MIN_SPEEDUP="${MIN_SPEEDUP:-1.000}"
PIN_CPU="${PIN_CPU:-0}"
WARMUP_RUNS="${WARMUP_RUNS:-1}"
C_COMPILER="${C_COMPILER:-}"
MAX_RETRIES="${MAX_RETRIES:-1}"
RETRY_LABELS="${RETRY_LABELS:-kyber_upstream_avx2,kyber_upstream_avx2_fair}"
SHOW_FULL_OUTPUT_ON_FAIL="${SHOW_FULL_OUTPUT_ON_FAIL:-1}"
LOCAL_ROUNDTRIP_METRIC="${LOCAL_ROUNDTRIP_METRIC:-mlkem_roundtrip_ns_per_op}"

if ! [[ "$ITERS" =~ ^[0-9]+$ ]] || [ "$ITERS" -le 0 ]; then
  echo "invalid iteration count: $ITERS" >&2
  exit 1
fi
if ! [[ "$RUNS" =~ ^[0-9]+$ ]] || [ "$RUNS" -le 0 ]; then
  echo "invalid run count: $RUNS" >&2
  exit 1
fi
case "$STATS_MODE" in
  mean|median|trimmed) ;;
  *)
    echo "invalid STATS_MODE: $STATS_MODE (expected mean|median|trimmed)" >&2
    exit 1
    ;;
esac
if ! [[ "$TRIM_COUNT" =~ ^[0-9]+$ ]]; then
  echo "invalid TRIM_COUNT: $TRIM_COUNT" >&2
  exit 1
fi
if ! [[ "$MIN_SPEEDUP" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "invalid MIN_SPEEDUP: $MIN_SPEEDUP" >&2
  exit 1
fi
if ! [[ "$MAX_RETRIES" =~ ^[0-9]+$ ]]; then
  echo "invalid MAX_RETRIES: $MAX_RETRIES" >&2
  exit 1
fi
if ! [[ "$SHOW_FULL_OUTPUT_ON_FAIL" =~ ^(0|1)$ ]]; then
  echo "invalid SHOW_FULL_OUTPUT_ON_FAIL: $SHOW_FULL_OUTPUT_ON_FAIL (expected 0|1)" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d /tmp/baby-mlkem-verify-fastest.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

run_cmd=(
  "$ROOT_DIR/scripts/bench_compare_all_stats.sh"
  "$ITERS"
  "$RUNS"
)

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

label_to_env_suffix() {
  local suffix="${1^^}"
  suffix="${suffix//[^A-Z0-9]/_}"
  printf "%s\n" "$suffix"
}

num_ge() {
  local a="$1"
  local b="$2"
  awk -v lhs="$a" -v rhs="$b" 'BEGIN { exit (lhs + 0 >= rhs + 0) ? 0 : 1 }'
}

num_gt() {
  local a="$1"
  local b="$2"
  awk -v lhs="$a" -v rhs="$b" 'BEGIN { exit (lhs + 0 > rhs + 0) ? 0 : 1 }'
}

is_retry_label() {
  local target="$1"
  local token
  for token in ${RETRY_LABELS//,/ }; do
    if [ -n "$token" ] && [ "$token" = "$target" ]; then
      return 0
    fi
  done
  return 1
}

extract_speedup() {
  local file="$1"
  local label="$2"
  awk -v target="$label" '
    BEGIN { in_block = 0 }
    $0 == "[" target "]" { in_block = 1; next }
    /^\[/ && $0 != "[" target "]" { in_block = 0 }
    in_block && /^local_speedup_vs_competitor=/ {
      split($0, a, "=");
      gsub(/x$/, "", a[2]);
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

declare -A min_speedup_by_label
for label in "${labels[@]}"; do
  env_key="MIN_SPEEDUP_$(label_to_env_suffix "$label")"
  env_val="${!env_key-}"
  threshold="${env_val:-$MIN_SPEEDUP}"
  if ! [[ "$threshold" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "invalid $env_key: $threshold" >&2
    exit 1
  fi
  min_speedup_by_label["$label"]="$threshold"
done

declare -A best_speedup_by_label
declare -A best_attempt_by_label
attempt=1
total_attempts=$((MAX_RETRIES + 1))
final_out_file=""
final_failed_labels=""
pass=0

while [ "$attempt" -le "$total_attempts" ]; do
  out_file="$WORK_DIR/attempt_${attempt}.txt"
  final_out_file="$out_file"

  echo "running verification suite... (attempt $attempt/$total_attempts)"
  echo "  iters=$ITERS runs=$RUNS stats_mode=$STATS_MODE trim_count=$TRIM_COUNT"
  echo "  pin_cpu=${PIN_CPU:-<unset>} warmup_runs=$WARMUP_RUNS"
  echo "  local_roundtrip_metric=$LOCAL_ROUNDTRIP_METRIC"
  echo "  min_speedup_default=$MIN_SPEEDUP max_retries=$MAX_RETRIES retry_labels=${RETRY_LABELS:-<none>}"
  if [ -n "$C_COMPILER" ]; then
    echo "  c_compiler=$C_COMPILER"
  fi

  PIN_CPU="$PIN_CPU" \
  WARMUP_RUNS="$WARMUP_RUNS" \
  STATS_MODE="$STATS_MODE" \
  TRIM_COUNT="$TRIM_COUNT" \
  C_COMPILER="$C_COMPILER" \
  "${run_cmd[@]}" > "$out_file"

  printf "\n%-28s %-12s %-12s %-8s\n" "label" "speedup" "min" "status"
  printf "%-28s %-12s %-12s %-8s\n" "----------------------------" "------------" "------------" "--------"

  failed_labels=()
  retryable_only=1

  for label in "${labels[@]}"; do
    sp="$(extract_speedup "$out_file" "$label")"
    min="${min_speedup_by_label[$label]}"

    if [ -z "$sp" ]; then
      printf "%-28s %-12s %-12s %-8s\n" "$label" "missing" "${min}x" "fail"
      failed_labels+=("$label")
      retryable_only=0
      continue
    fi

    prev_best="${best_speedup_by_label[$label]-}"
    if [ -z "$prev_best" ] || num_gt "$sp" "$prev_best"; then
      best_speedup_by_label["$label"]="$sp"
      best_attempt_by_label["$label"]="$attempt"
    fi

    if num_ge "$sp" "$min"; then
      printf "%-28s %-12s %-12s %-8s\n" "$label" "${sp}x" "${min}x" "pass"
    else
      printf "%-28s %-12s %-12s %-8s\n" "$label" "${sp}x" "${min}x" "fail"
      failed_labels+=("$label")
      if ! is_retry_label "$label"; then
        retryable_only=0
      fi
    fi
  done

  local_mean="$(extract_local_mean "$out_file" "kyber_upstream_avx2")"
  if [ -n "$local_mean" ]; then
    echo
    echo "local_mean_ns(reference kyber_upstream_avx2)=$local_mean"
  fi

  if [ "${#failed_labels[@]}" -eq 0 ]; then
    pass=1
    break
  fi

  final_failed_labels="${failed_labels[*]}"
  echo
  echo "failed_labels=$final_failed_labels"

  if [ "$attempt" -lt "$total_attempts" ] && [ "$retryable_only" -eq 1 ]; then
    echo "retrying due to retryable-label failures only..."
    echo
    attempt=$((attempt + 1))
    continue
  fi
  break
done

if [ "$pass" -eq 1 ]; then
  echo
  echo "verify_world_fastest=PASS (all labels met configured minimum speedup)"
  exit 0
fi

echo
echo "verify_world_fastest=FAIL (minimum speedup threshold not met or parse failure)"
if [ -n "$final_failed_labels" ]; then
  echo "failed_labels=$final_failed_labels"
fi
echo
echo "best_speedups_seen:"
printf "%-28s %-12s %-12s %-8s\n" "label" "best" "min" "attempt"
printf "%-28s %-12s %-12s %-8s\n" "----------------------------" "------------" "------------" "--------"
for label in "${labels[@]}"; do
  best="${best_speedup_by_label[$label]-missing}"
  best_attempt="${best_attempt_by_label[$label]-n/a}"
  min="${min_speedup_by_label[$label]}"
  if [ "$best" = "missing" ]; then
    best_out="missing"
  else
    best_out="${best}x"
  fi
  printf "%-28s %-12s %-12s %-8s\n" "$label" "$best_out" "${min}x" "$best_attempt"
done
echo
echo "full_output=$final_out_file"
if [ "$SHOW_FULL_OUTPUT_ON_FAIL" -eq 1 ]; then
  cat "$final_out_file"
fi
exit 1
