#!/usr/bin/env bash

BENCH_PAIR_ORDER="${BENCH_PAIR_ORDER:-local-first}"
case "$BENCH_PAIR_ORDER" in
  local-first|competitor-first) ;;
  *)
    echo "invalid BENCH_PAIR_ORDER: $BENCH_PAIR_ORDER (expected local-first|competitor-first)" >&2
    return 1
    ;;
esac

bench_pair_run() {
  if [ "$#" -ne 5 ]; then
    echo "bench_pair_run expects: local-bin competitor-bin iters local-out competitor-out" >&2
    return 1
  fi

  local local_bin="$1"
  local competitor_bin="$2"
  local iters="$3"
  local local_out="$4"
  local competitor_out="$5"

  if [ "$BENCH_PAIR_ORDER" = "local-first" ]; then
    "${RUNNER[@]}" "$local_bin" "$iters" > "$local_out"
    "${RUNNER[@]}" "$competitor_bin" "$iters" > "$competitor_out"
  else
    "${RUNNER[@]}" "$competitor_bin" "$iters" > "$competitor_out"
    "${RUNNER[@]}" "$local_bin" "$iters" > "$local_out"
  fi
}

bench_pair_capture() {
  if [ "$#" -ne 4 ]; then
    echo "bench_pair_capture expects: local-bin competitor-bin iters work-dir" >&2
    return 1
  fi

  local local_out="$4/local-benchmark.out"
  local competitor_out="$4/competitor-benchmark.out"
  printf "bench_pair_order=%s\n" "$BENCH_PAIR_ORDER"
  bench_pair_run "$1" "$2" "$3" "$local_out" "$competitor_out"
  BENCH_LOCAL_OUT="$(cat "$local_out")"
  BENCH_COMPETITOR_OUT="$(cat "$competitor_out")"
}
