#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RUNS="${RUNS:-15}"
WARMUP_RUNS="${WARMUP_RUNS:-3}"
KEM_ITERS="${KEM_ITERS:-100000}"
PIN_CPU="${PIN_CPU:-0}"
BOOTSTRAP_SAMPLES="${BOOTSTRAP_SAMPLES:-20000}"

if [ -n "${C_COMPILER:-}" ]; then
  C_COMPILER="$C_COMPILER"
elif [ -n "${CC:-}" ]; then
  C_COMPILER="$CC"
elif command -v clang >/dev/null 2>&1; then
  C_COMPILER="clang"
else
  C_COMPILER="gcc"
fi

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
check_positive_int BOOTSTRAP_SAMPLES "$BOOTSTRAP_SAMPLES"
check_nonnegative_int WARMUP_RUNS "$WARMUP_RUNS"

if [ -n "$PIN_CPU" ] && ! command -v taskset >/dev/null 2>&1; then
  echo "taskset not found but PIN_CPU was set" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for paired statistics" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d /tmp/baby-mlkem-product-ab.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

if command -v flock >/dev/null 2>&1; then
  exec 9>"$ROOT_DIR/.bench-compare.lock"
  if ! flock -n 9; then
    echo "waiting_for_bench_lock=$ROOT_DIR/.bench-compare.lock" >&2
    flock 9
  fi
fi

make_args=(CC="$C_COMPILER" AVX2_BACKEND=core)
if [ "${ARCH_CFLAGS+x}" ]; then
  make_args+=(ARCH_CFLAGS="$ARCH_CFLAGS")
fi

printf "compiler=%s runs=%s warmup_runs=%s kem_iters=%s pin_cpu=%s\n" \
  "$C_COMPILER" "$RUNS" "$WARMUP_RUNS" "$KEM_ITERS" "${PIN_CPU:-<unset>}"
printf "arch_cflags=%s\n" "${ARCH_CFLAGS:-<make default>}"
printf "speedup_direction=inline_time/product_time\n"

make -C "$ROOT_DIR" clean "${make_args[@]}" >/dev/null
make -C "$ROOT_DIR" bench bench-product "${make_args[@]}" >/dev/null

run_one() {
  local label="$1"
  local output="${2:-}"
  local bin
  if [ "$label" = inline ]; then
    bin="$ROOT_DIR/benchc"
  else
    bin="$ROOT_DIR/bench_productc"
  fi

  local runner=()
  if [ -n "$PIN_CPU" ]; then
    runner=(taskset -c "$PIN_CPU")
  fi
  if [ -n "$output" ]; then
    "${runner[@]}" "$bin" "$KEM_ITERS" > "$output"
  else
    "${runner[@]}" "$bin" "$KEM_ITERS" >/dev/null
  fi
}

for run in $(seq 1 "$WARMUP_RUNS"); do
  if (( run % 2 == 1 )); then
    labels=(inline product)
  else
    labels=(product inline)
  fi
  for label in "${labels[@]}"; do
    run_one "$label"
  done
done

for run in $(seq 1 "$RUNS"); do
  if (( run % 2 == 1 )); then
    labels=(inline product)
  else
    labels=(product inline)
  fi
  for label in "${labels[@]}"; do
    run_one "$label" "$WORK_DIR/${label}_${run}.txt"
  done
done

PRODUCT_AB_WORK_DIR="$WORK_DIR" \
PRODUCT_AB_RUNS="$RUNS" \
PRODUCT_AB_BOOTSTRAP_SAMPLES="$BOOTSTRAP_SAMPLES" \
python3 - <<'PY'
import glob
import math
import os
import random
import re
import statistics

work_dir = os.environ["PRODUCT_AB_WORK_DIR"]
expected_runs = int(os.environ["PRODUCT_AB_RUNS"])
bootstrap_samples = int(os.environ["PRODUCT_AB_BOOTSTRAP_SAMPLES"])
metric_pattern = re.compile(r"^(.+)_ns_per_op=([0-9.]+)$")
run_pattern = re.compile(r"_(\d+)\.txt$")


def run_number(path):
    match = run_pattern.search(path)
    if not match:
        raise ValueError(f"missing run number in {path}")
    return int(match.group(1))


def geometric_mean(values):
    return math.exp(statistics.mean(math.log(value) for value in values))


def bootstrap_gmean_interval(values):
    rng = random.Random(0x4D4C4B454D)
    samples = []
    for _ in range(bootstrap_samples):
        resample = [values[rng.randrange(len(values))] for _ in values]
        samples.append(geometric_mean(resample))
    samples.sort()
    low_index = int(0.025 * (len(samples) - 1))
    high_index = int(0.975 * (len(samples) - 1))
    return samples[low_index], samples[high_index]


def order_median(values):
    if not values:
        return "n/a"
    return f"{statistics.median(values):.4f}x"


values = {"inline": {}, "product": {}}
for label in values:
    paths = glob.glob(os.path.join(work_dir, f"{label}_*.txt"))
    for path in sorted(paths, key=run_number):
        with open(path, "r", encoding="utf-8") as source:
            for line in source:
                match = metric_pattern.match(line.strip())
                if match:
                    values[label].setdefault(match.group(1), []).append(
                        float(match.group(2))
                    )

metrics = sorted(set(values["inline"]) & set(values["product"]))
if not metrics:
    raise SystemExit("no common benchmark metrics found")

print()
print(
    "metric inline_avg product_avg product_speedup "
    "inline_median product_median median_speedup"
)
for metric in metrics:
    inline = values["inline"][metric]
    product = values["product"][metric]
    if len(inline) != expected_runs or len(product) != expected_runs:
        raise SystemExit(
            f"{metric}: expected {expected_runs} runs, "
            f"got inline={len(inline)} product={len(product)}"
        )
    inline_avg = statistics.mean(inline)
    product_avg = statistics.mean(product)
    inline_median = statistics.median(inline)
    product_median = statistics.median(product)
    print(
        f"{metric} {inline_avg:.2f} {product_avg:.2f} "
        f"{inline_avg / product_avg:.4f}x "
        f"{inline_median:.2f} {product_median:.2f} "
        f"{inline_median / product_median:.4f}x"
    )

print()
print(
    "paired_metric gmean ci95_low ci95_high median wins "
    "inline_first_median product_first_median"
)
for metric in metrics:
    inline = values["inline"][metric]
    product = values["product"][metric]
    ratios = [inline_time / product_time
              for inline_time, product_time in zip(inline, product)]
    low, high = bootstrap_gmean_interval(ratios)
    print(
        f"{metric} {geometric_mean(ratios):.4f}x "
        f"{low:.4f}x {high:.4f}x "
        f"{statistics.median(ratios):.4f}x "
        f"{sum(ratio > 1.0 for ratio in ratios)}/{len(ratios)} "
        f"{order_median(ratios[0::2])} "
        f"{order_median(ratios[1::2])}"
    )
PY
