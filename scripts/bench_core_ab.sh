#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BASE_REF="${1:-${BASE_REF:-HEAD}}"
RUNS="${RUNS:-5}"
PIN_CPU="${PIN_CPU:-0}"
SUITES="${SUITES:-kem,stage}"
KEM_ITERS="${KEM_ITERS:-3000}"
STAGE_ITERS="${STAGE_ITERS:-10000}"
NTT_ITERS="${NTT_ITERS:-200000}"
KECCAK_ITERS="${KECCAK_ITERS:-200000}"
WARMUP_RUNS="${WARMUP_RUNS:-1}"
RUN_ORDER="${RUN_ORDER:-grouped}"

if [ -n "${C_COMPILER:-}" ]; then
  C_COMPILER="$C_COMPILER"
elif [ -n "${CC:-}" ]; then
  C_COMPILER="$CC"
elif command -v clang >/dev/null 2>&1; then
  C_COMPILER="clang"
else
  C_COMPILER="gcc"
fi

WORK_DIR="$(mktemp -d /tmp/baby-mlkem-core-ab.XXXXXX)"
BASE_DIR="$WORK_DIR/base"
trap 'git -C "$ROOT_DIR" worktree remove --force "$BASE_DIR" >/dev/null 2>&1 || true; rm -rf "$WORK_DIR"' EXIT

check_positive_int() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -le 0 ]; then
    echo "invalid $name: $value" >&2
    exit 1
  fi
}

check_nonnegative_int() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "invalid $name: $value" >&2
    exit 1
  fi
}

check_positive_int RUNS "$RUNS"
check_positive_int KEM_ITERS "$KEM_ITERS"
check_positive_int STAGE_ITERS "$STAGE_ITERS"
check_positive_int NTT_ITERS "$NTT_ITERS"
check_positive_int KECCAK_ITERS "$KECCAK_ITERS"
check_nonnegative_int WARMUP_RUNS "$WARMUP_RUNS"

case "$RUN_ORDER" in
  grouped|alternating)
    ;;
  *)
    echo "invalid RUN_ORDER: $RUN_ORDER (expected grouped or alternating)" >&2
    exit 1
    ;;
esac

IFS=',' read -r -a SUITE_LIST <<< "$SUITES"

suite_target() {
  case "$1" in
    kem) echo "bench" ;;
    product) echo "bench-product" ;;
    stage) echo "bench-stages" ;;
    ntt) echo "bench-ntt" ;;
    keccak) echo "bench-keccak" ;;
    *) echo "unknown suite: $1" >&2; exit 1 ;;
  esac
}

suite_bin() {
  case "$1" in
    kem) echo "./benchc" ;;
    product) echo "./bench_productc" ;;
    stage) echo "./bench_core_stagesc" ;;
    ntt) echo "./bench_nttc" ;;
    keccak) echo "./bench_keccakc" ;;
    *) echo "unknown suite: $1" >&2; exit 1 ;;
  esac
}

suite_iters() {
  case "$1" in
    kem) echo "$KEM_ITERS" ;;
    product) echo "$KEM_ITERS" ;;
    stage) echo "$STAGE_ITERS" ;;
    ntt) echo "$NTT_ITERS" ;;
    keccak) echo "$KECCAK_ITERS" ;;
    *) echo "unknown suite: $1" >&2; exit 1 ;;
  esac
}

run_cmd() {
  if [ -n "$PIN_CPU" ]; then
    if ! command -v taskset >/dev/null 2>&1; then
      echo "taskset not found but PIN_CPU was set" >&2
      exit 1
    fi
    taskset -c "$PIN_CPU" "$@"
  else
    "$@"
  fi
}

build_targets=()
for suite in "${SUITE_LIST[@]}"; do
  suite="${suite//[[:space:]]/}"
  [ -n "$suite" ] || continue
  build_targets+=("$(suite_target "$suite")")
done
if [ "${#build_targets[@]}" -eq 0 ]; then
  echo "no suites selected" >&2
  exit 1
fi

printf "base_ref=%s\n" "$BASE_REF"
printf "candidate_root=%s\n" "$ROOT_DIR"
make_args=(CC="$C_COMPILER" AVX2_BACKEND=core)
if [ "${ARCH_CFLAGS+x}" ]; then
  make_args+=(ARCH_CFLAGS="$ARCH_CFLAGS")
fi

printf "compiler=%s avx2_backend=core suites=%s runs=%s warmup_runs=%s pin_cpu=%s run_order=%s\n" \
  "$C_COMPILER" "$SUITES" "$RUNS" "$WARMUP_RUNS" "${PIN_CPU:-<unset>}" "$RUN_ORDER"
printf "arch_cflags=%s\n" "${ARCH_CFLAGS:-<make default>}"
printf "iters: kem=%s stage=%s ntt=%s keccak=%s\n" \
  "$KEM_ITERS" "$STAGE_ITERS" "$NTT_ITERS" "$KECCAK_ITERS"

git -C "$ROOT_DIR" worktree add --detach "$BASE_DIR" "$BASE_REF" >/dev/null

make -C "$BASE_DIR" clean "${make_args[@]}" >/dev/null
make -C "$ROOT_DIR" clean "${make_args[@]}" >/dev/null
make -C "$BASE_DIR" "${build_targets[@]}" "${make_args[@]}" >/dev/null
make -C "$ROOT_DIR" "${build_targets[@]}" "${make_args[@]}" >/dev/null

run_suite_once() {
  local label="$1"
  local bin="$2"
  local iters="$3"
  local output="${4:-}"
  local root
  if [ "$label" = base ]; then
    root="$BASE_DIR"
  else
    root="$ROOT_DIR"
  fi
  if [ -n "$output" ]; then
    (cd "$root" && run_cmd "$bin" "$iters") > "$output"
  else
    (cd "$root" && run_cmd "$bin" "$iters") >/dev/null
  fi
}

for suite in "${SUITE_LIST[@]}"; do
  suite="${suite//[[:space:]]/}"
  [ -n "$suite" ] || continue
  bin="$(suite_bin "$suite")"
  iters="$(suite_iters "$suite")"
  if [ "$RUN_ORDER" = grouped ]; then
    for label in base cand; do
      for run in $(seq 1 "$WARMUP_RUNS"); do
        run_suite_once "$label" "$bin" "$iters"
      done
      for run in $(seq 1 "$RUNS"); do
        run_suite_once "$label" "$bin" "$iters" \
          "$WORK_DIR/${suite}_${label}_${run}.txt"
      done
    done
  else
    for run in $(seq 1 "$WARMUP_RUNS"); do
      if (( run % 2 == 1 )); then
        labels=(base cand)
      else
        labels=(cand base)
      fi
      for label in "${labels[@]}"; do
        run_suite_once "$label" "$bin" "$iters"
      done
    done
    for run in $(seq 1 "$RUNS"); do
      if (( run % 2 == 1 )); then
        labels=(base cand)
      else
        labels=(cand base)
      fi
      for label in "${labels[@]}"; do
        run_suite_once "$label" "$bin" "$iters" \
          "$WORK_DIR/${suite}_${label}_${run}.txt"
      done
    done
  fi
done

AB_WORK_DIR="$WORK_DIR" AB_SUITES="$SUITES" AB_RUN_ORDER="$RUN_ORDER" python3 - <<'PY'
import glob
import math
import os
import re
import statistics

work_dir = os.environ["AB_WORK_DIR"]
suites = [s.strip() for s in os.environ["AB_SUITES"].split(",") if s.strip()]
run_order = os.environ["AB_RUN_ORDER"]
pattern = re.compile(r"^(.+)_ns_per_op=([0-9.]+)$")
run_pattern = re.compile(r"_(\d+)\.txt$")


def run_number(path):
    match = run_pattern.search(path)
    if not match:
        raise ValueError(f"missing run number in {path}")
    return int(match.group(1))


def format_median(values):
    if not values:
        return "n/a"
    return f"{statistics.median(values):.4f}x"


for suite in suites:
    values = {"base": {}, "cand": {}}
    for label in ("base", "cand"):
        paths = glob.glob(os.path.join(work_dir, f"{suite}_{label}_*.txt"))
        for path in sorted(paths, key=run_number):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    m = pattern.match(line.strip())
                    if not m:
                        continue
                    values[label].setdefault(m.group(1), []).append(float(m.group(2)))

    metrics = sorted(set(values["base"]) & set(values["cand"]))
    print(f"\n[{suite}]")
    print("metric base_avg cand_avg avg_speedup base_median cand_median median_speedup")
    for metric in metrics:
        base = values["base"][metric]
        cand = values["cand"][metric]
        if not base or not cand:
            continue
        base_avg = statistics.mean(base)
        cand_avg = statistics.mean(cand)
        base_med = statistics.median(base)
        cand_med = statistics.median(cand)
        print(
            f"{metric} {base_avg:.2f} {cand_avg:.2f} {base_avg / cand_avg:.4f}x "
            f"{base_med:.2f} {cand_med:.2f} {base_med / cand_med:.4f}x"
        )

    if run_order == "alternating":
        print()
        print("paired_metric gmean median wins base_first_median cand_first_median")
        for metric in metrics:
            base = values["base"][metric]
            cand = values["cand"][metric]
            if not base or len(base) != len(cand):
                continue
            ratios = [b / c for b, c in zip(base, cand)]
            base_first = ratios[0::2]
            cand_first = ratios[1::2]
            gmean = math.exp(statistics.mean(math.log(r) for r in ratios))
            print(
                f"{metric} {gmean:.4f}x {statistics.median(ratios):.4f}x "
                f"{sum(r > 1.0 for r in ratios)}/{len(ratios)} "
                f"{format_median(base_first)} "
                f"{format_median(cand_first)}"
            )
PY
