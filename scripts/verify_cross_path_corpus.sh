#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MAKE_BIN="${MAKE:-make}"
JOBS="${JOBS:-$(nproc)}"
KEEP_DIR="${CROSS_PATH_KEEP_DIR:-0}"
EXPECTED_BYTES=381228
AVX2_FLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"
SCALAR_FLAGS="-mno-avx -mno-avx2 -mno-avx512f -mno-avx512bw -mno-bmi2"
work_dir=""
reference=""
verified=0

[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || {
  echo "JOBS must be a positive integer" >&2
  exit 2
}
[[ "$KEEP_DIR" = 0 || "$KEEP_DIR" = 1 ]] || {
  echo "CROSS_PATH_KEEP_DIR must be 0 or 1" >&2
  exit 2
}
for tool in "$MAKE_BIN" clang gcc cmp nproc sha256sum wc; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "required tool not found: $tool" >&2
    exit 2
  }
done

cd "$ROOT_DIR"
work_dir="$(mktemp -d /tmp/baby-mlkem-cross-path.XXXXXX)"

clean_all() {
  "$MAKE_BIN" -s AVX2_BACKEND=core clean >/dev/null 2>&1 || true
  "$MAKE_BIN" -s AVX2_BACKEND=upstream clean >/dev/null 2>&1 || true
  "$MAKE_BIN" -s AVX2_BACKEND=pqclean clean >/dev/null 2>&1 || true
}

cleanup() {
  local status=$?
  set +e
  clean_all
  if [[ "$KEEP_DIR" = 1 || $status -ne 0 ]]; then
    echo "cross-path corpus directory: $work_dir" >&2
  else
    rm -rf "$work_dir"
  fi
}
trap cleanup EXIT

emit_and_compare() {
  local label="$1"
  local binary="$2"
  local output="$work_dir/$label.bin"
  local bytes digest

  "$binary" --emit-corpus >"$output"
  bytes="$(wc -c <"$output")"
  if [[ "$bytes" -ne "$EXPECTED_BYTES" ]]; then
    echo "$label emitted $bytes bytes, expected $EXPECTED_BYTES" >&2
    return 1
  fi

  if [[ -z "$reference" ]]; then
    reference="$output"
  elif ! cmp -s "$reference" "$output"; then
    echo "$label differs from $(basename "$reference" .bin)" >&2
    return 1
  fi

  digest="$(sha256sum "$output")"
  digest="${digest%% *}"
  printf 'cross_path_corpus=%s bytes=%s sha256=%s\n' \
    "$label" "$bytes" "$digest"
  verified=$((verified + 1))
}

build_core_profile() {
  local compiler="$1"
  local profile="$2"
  local flags="$3"

  clean_all
  "$MAKE_BIN" -s -j"$JOBS" CC="$compiler" AVX2_BACKEND=core \
    ARCH_CFLAGS="$flags" bench bench-product
  emit_and_compare "core-$compiler-$profile" ./benchc
  emit_and_compare "product-$compiler-$profile" ./bench_productc
}

build_vendor_backend() {
  local compiler="$1"
  local backend="$2"

  clean_all
  "$MAKE_BIN" -s -j"$JOBS" CC="$compiler" AVX2_BACKEND="$backend" \
    ARCH_CFLAGS="$AVX2_FLAGS" bench
  emit_and_compare "$backend-$compiler-avx2" ./benchc
}

for compiler in clang gcc; do
  build_core_profile "$compiler" native "-march=native"
  build_core_profile "$compiler" avx2 "$AVX2_FLAGS"
  build_core_profile "$compiler" scalar "$SCALAR_FLAGS"
done

for compiler in clang gcc; do
  build_vendor_backend "$compiler" upstream
  build_vendor_backend "$compiler" pqclean
done

[[ "$verified" -eq 16 ]] || {
  echo "verified $verified corpus files, expected 16" >&2
  exit 1
}

reference_hash="$(sha256sum "$reference")"
reference_hash="${reference_hash%% *}"
printf 'cross_path_corpus_verified=%s\n' "$verified"
printf 'cross_path_corpus_sha256=%s\n' "$reference_hash"
