#!/usr/bin/env bash

BENCH_PAIR_ORDER="${BENCH_PAIR_ORDER:-local-first}"
BENCH_LOCAL_ENV="${BENCH_LOCAL_ENV:-}"
BENCH_COMPETITOR_ENV="${BENCH_COMPETITOR_ENV:-}"
case "$BENCH_PAIR_ORDER" in
  local-first|competitor-first) ;;
  *)
    echo "invalid BENCH_PAIR_ORDER: $BENCH_PAIR_ORDER (expected local-first|competitor-first)" >&2
    return 1
    ;;
esac

bench_pair_run_one() {
  if [ "$#" -ne 4 ]; then
    echo "bench_pair_run_one expects: env-spec bin iters output" >&2
    return 1
  fi

  local env_spec="$1"
  local bin="$2"
  local iters="$3"
  local output="$4"
  local -a env_args=()

  if [ -n "$env_spec" ]; then
    read -r -a env_args <<< "$env_spec"
    env "${env_args[@]}" "${RUNNER[@]}" "$bin" "$iters" > "$output"
  else
    "${RUNNER[@]}" "$bin" "$iters" > "$output"
  fi
}

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
    bench_pair_run_one "$BENCH_LOCAL_ENV" "$local_bin" "$iters" "$local_out"
    bench_pair_run_one "$BENCH_COMPETITOR_ENV" "$competitor_bin" "$iters" "$competitor_out"
  else
    bench_pair_run_one "$BENCH_COMPETITOR_ENV" "$competitor_bin" "$iters" "$competitor_out"
    bench_pair_run_one "$BENCH_LOCAL_ENV" "$local_bin" "$iters" "$local_out"
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
