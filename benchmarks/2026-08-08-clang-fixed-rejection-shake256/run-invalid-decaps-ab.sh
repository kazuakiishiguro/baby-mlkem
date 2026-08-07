#!/usr/bin/env bash
set -euo pipefail

base_bin="$1"
cand_bin="$2"
profile="$3"
runs="${RUNS:-16}"
warmups="${WARMUP_RUNS:-4}"
iters="${ITERS:-100000}"
cpu="${PIN_CPU:-0}"
work_dir="$(mktemp -d /tmp/invalid-decaps-ab.XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT

measure() {
  taskset -c "$cpu" "$1" "$iters" |
    sed -n 's/^mlkem_decaps_invalid_ns_per_op=//p'
}

for run in $(seq 1 "$warmups"); do
  if ((run % 2 == 1)); then
    measure "$base_bin" >/dev/null
    measure "$cand_bin" >/dev/null
  else
    measure "$cand_bin" >/dev/null
    measure "$base_bin" >/dev/null
  fi
done

: >"$work_dir/base"
: >"$work_dir/cand"
: >"$work_dir/ratios"
: >"$work_dir/base-first"
: >"$work_dir/cand-first"

printf 'profile=%s runs=%s warmup_runs=%s iterations=%s pin_cpu=%s run_order=alternating\n' \
  "$profile" "$runs" "$warmups" "$iters" "$cpu"
printf 'run order base_ns cand_ns speedup\n'
for run in $(seq 1 "$runs"); do
  if ((run % 2 == 1)); then
    order=base-first
    base_ns="$(measure "$base_bin")"
    cand_ns="$(measure "$cand_bin")"
  else
    order=candidate-first
    cand_ns="$(measure "$cand_bin")"
    base_ns="$(measure "$base_bin")"
  fi
  ratio="$(awk -v b="$base_ns" -v c="$cand_ns" 'BEGIN {printf "%.8f", b/c}')"
  printf '%s %s %s %s %.6fx\n' "$run" "$order" "$base_ns" "$cand_ns" "$ratio"
  printf '%s\n' "$base_ns" >>"$work_dir/base"
  printf '%s\n' "$cand_ns" >>"$work_dir/cand"
  printf '%s\n' "$ratio" >>"$work_dir/ratios"
  if ((run % 2 == 1)); then
    printf '%s\n' "$ratio" >>"$work_dir/base-first"
  else
    printf '%s\n' "$ratio" >>"$work_dir/cand-first"
  fi
done

mean() {
  awk '{sum += $1} END {printf "%.2f", sum/NR}' "$1"
}
gmean() {
  awk '{sum += log($1)} END {printf "%.6f", exp(sum/NR)}' "$1"
}
median() {
  sort -n "$1" | awk '{a[NR]=$1} END {if (NR%2) printf "%.6f", a[(NR+1)/2]; else printf "%.6f", (a[NR/2]+a[NR/2+1])/2}'
}

base_avg="$(mean "$work_dir/base")"
cand_avg="$(mean "$work_dir/cand")"
avg_speedup="$(awk -v b="$base_avg" -v c="$cand_avg" 'BEGIN {printf "%.6f", b/c}')"
wins="$(awk '$1 > 1 {n++} END {print n+0}' "$work_dir/ratios")"
printf 'base_avg_ns=%s\n' "$base_avg"
printf 'candidate_avg_ns=%s\n' "$cand_avg"
printf 'average_speedup=%sx\n' "$avg_speedup"
printf 'paired_gmean=%sx\n' "$(gmean "$work_dir/ratios")"
printf 'paired_median=%sx\n' "$(median "$work_dir/ratios")"
printf 'wins=%s/%s\n' "$wins" "$runs"
printf 'base_first_median=%sx\n' "$(median "$work_dir/base-first")"
printf 'candidate_first_median=%sx\n' "$(median "$work_dir/cand-first")"
