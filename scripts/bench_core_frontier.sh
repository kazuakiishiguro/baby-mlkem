#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RUNS="${RUNS:-7}"
STAGE_ITERS="${STAGE_ITERS:-30000}"
PIN_CPU="${PIN_CPU:-0}"

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

check_positive_int RUNS "$RUNS"
check_positive_int STAGE_ITERS "$STAGE_ITERS"

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

ARCH_CFLAGS="${ARCH_CFLAGS:--mavx2 -mbmi2 -mpopcnt}"
make_args=(CC="$C_COMPILER" AVX2_BACKEND=core ARCH_CFLAGS="$ARCH_CFLAGS")

printf "compiler=%s avx2_backend=core runs=%s stage_iters=%s pin_cpu=%s\n" \
  "$C_COMPILER" "$RUNS" "$STAGE_ITERS" "${PIN_CPU:-<unset>}"
printf "arch_cflags=%s\n" "$ARCH_CFLAGS"

make -C "$ROOT_DIR" clean "${make_args[@]}" >/dev/null
make -C "$ROOT_DIR" bench-stages "${make_args[@]}" >/dev/null

WORK_DIR="$(mktemp -d /tmp/baby-mlkem-core-frontier.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

for run in $(seq 1 "$RUNS"); do
  printf "run=%s/%s\n" "$run" "$RUNS" >&2
  (cd "$ROOT_DIR" && run_cmd ./bench_core_stagesc "$STAGE_ITERS") \
    > "$WORK_DIR/run_$run.txt"
done

FRONTIER_WORK_DIR="$WORK_DIR" python3 - <<'PY2'
import glob
import os
import re
import statistics
import sys

targets = [
    ("mlkem_core_stage_kpke_encrypt_uncached",
     "largest integrated cache-miss encryption row"),
    ("mlkem_core_stage_kpke_keygen_full",
     "keygen still dominated by matrix sampling plus six NTTs"),
    ("mlkem_core_stage_kpke_prepare_public_no_cache",
     "public-key d12 decode + matrix sampling + H(pk)"),
    ("mlkem_core_stage_sample_matrix",
     "largest standalone public-work target"),
    ("mlkem_core_stage_kpke_encrypt_cached",
     "cached encapsulation arithmetic/noise target"),
    ("mlkem_core_stage_keygen_noise_ntt",
     "keygen PRF/CBD plus six forward NTTs"),
    ("mlkem_core_stage_keygen_noise_ntt_encode",
     "six forward NTTs plus secret d12 encode"),
    ("mlkem_core_stage_encrypt_accum_inv",
     "K=3 accumulation plus production 16-bit inverse-add"),
    ("mlkem_core_stage_encrypt_inv_add_u_raw",
     "production 16-bit inverse-add across the three u rows"),
    ("mlkem_core_stage_encrypt_inv_add_u_tail_final_raw",
     "legacy 32-bit tail/final diagnostic; no longer a production target"),
    ("mlkem_core_stage_sample_ntt4_lane0_carry_keccak_store3",
     "production x4 sampler Keccak/state/store cost"),
    ("mlkem_core_stage_sample_ntt4_init_only",
     "x4 sampler initialization is too small to be the next target"),
    ("mlkem_core_stage_sample_ntt4_lane0_carry_keccak3_only",
     "production x4 sampler Keccak permutations dominate stream setup"),
    ("mlkem_core_stage_sample_ntt4_parse_504",
     "parser bookkeeping is not the main sampler cost"),
    ("mlkem_core_stage_sample_ntt4_full_raw",
     "complete production x4 sampler including rejection parsing"),
    ("mlkem_core_stage_keygen_accum_only",
     "A^T*s scalar accumulation is still meaningful but local rewrites failed"),
    ("mlkem_core_stage_keygen_add_only",
     "vector add is smaller than accumulation and NTT work"),
    ("mlkem_core_stage_ciphertext_compress_encode",
     "d10/d4 packing is too small for the next target"),
]

work_dir = os.environ["FRONTIER_WORK_DIR"]
pattern = re.compile(r"^(.+)_ns_per_op=([0-9.]+)$")
values = {}

for path in sorted(glob.glob(os.path.join(work_dir, "run_*.txt"))):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            match = pattern.match(line.strip())
            if match:
                values.setdefault(match.group(1), []).append(float(match.group(2)))

missing = [metric for metric, _ in targets if metric not in values]
if missing:
    for metric in missing:
        print(f"missing metric: {metric}", file=sys.stderr)
    sys.exit(1)

print()
print("| Metric | Avg ns/op | Median ns/op | Readout |")
print("|---|---:|---:|---|")
for metric, readout in targets:
    series = values[metric]
    avg = statistics.mean(series)
    median = statistics.median(series)
    print(f"| `{metric}` | {avg:.2f} | {median:.2f} | {readout} |")
PY2
