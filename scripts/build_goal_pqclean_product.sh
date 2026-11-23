#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/goal_speed_profile.sh"
PROFILE="${PROFILE:-${1:-native}}"
OUTPUT="${OUTPUT:-${2:-/tmp/baby-mlkem-pqclean-${PROFILE}-product.o}}"
PQCLEAN_DIR="${PQCLEAN_DIR:-/tmp/PQClean}"
C_COMPILER="${C_COMPILER:-clang}"
REQUIRED_SYMBOLS="goal_mlkem768_keypair_derand goal_mlkem768_encaps_derand goal_mlkem768_decaps"

case "$PROFILE" in
  native|avx2) ;;
  *)
    echo "unsupported goal size profile: $PROFILE (expected native|avx2)" >&2
    exit 2
    ;;
esac
if [[ "$OUTPUT" != /* ]]; then
  OUTPUT="$ROOT_DIR/$OUTPUT"
fi
if ! command -v "$C_COMPILER" >/dev/null 2>&1; then
  echo "compiler not found: $C_COMPILER" >&2
  exit 2
fi
for tool in git rg readelf objdump nm; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool" >&2
    exit 2
  fi
done
src="$PQCLEAN_DIR/crypto_kem/ml-kem-768/avx2"
common="$PQCLEAN_DIR/common"
if [ ! -d "$src" ] || [ ! -f "$common/fips202.c" ] ||
    [ ! -f "$common/keccak4x/KeccakP-1600-times4-SIMD256.c" ]; then
  echo "PQClean checkout is incomplete: $PQCLEAN_DIR" >&2
  exit 2
fi
if ! git -C "$PQCLEAN_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "PQClean directory is not a git checkout: $PQCLEAN_DIR" >&2
  exit 2
fi
if ! git -C "$PQCLEAN_DIR" diff --quiet ||
    ! git -C "$PQCLEAN_DIR" diff --cached --quiet; then
  echo "PQClean checkout has tracked changes: $PQCLEAN_DIR" >&2
  exit 2
fi

if [ -z "${PQCLEAN_AVX2_CFLAGS:-}" ]; then
  goal_speed_configure_profile "$PROFILE" "$C_COMPILER"
fi
read -r -a pqclean_cflags_arr <<< "$PQCLEAN_AVX2_CFLAGS"
if [[ " $PQCLEAN_AVX2_CFLAGS " != *" -mavx2 "* ]]; then
  echo "PQClean AVX2 flags are missing -mavx2" >&2
  exit 2
fi
if [ "$PROFILE" = "avx2" ]; then
  for token in -march=x86-64-v3 -mno-avx512f; do
    if [[ " $PQCLEAN_AVX2_CFLAGS " != *" $token "* ]]; then
      echo "AVX2-only PQClean flags are missing $token" >&2
      exit 2
    fi
  done
  if [[ " $PQCLEAN_AVX2_CFLAGS " == *" -march=native "* ]]; then
    echo "AVX2-only PQClean flags enable the native target" >&2
    exit 2
  fi
fi
for token in "${pqclean_cflags_arr[@]}"; do
  if [[ "$token" == -mavx512* ]]; then
    echo "PQClean AVX2 flags explicitly enable AVX512: $token" >&2
    exit 2
  fi
done
section_flags=(
  -ffunction-sections
  -fdata-sections
  -fno-unwind-tables
  -fno-asynchronous-unwind-tables
)

cache_pattern='(pk|public_key|matrix|at|hash)[[:alnum:]_]*cache|indcpa_enc_precomp'
cache_report="$(mktemp /tmp/baby-mlkem-pqclean-cache.XXXXXX)"
work_dir="$(mktemp -d /tmp/baby-mlkem-pqclean-product.XXXXXX)"
cleanup() {
  rm -f "$cache_report"
  rm -rf "$work_dir"
}
trap cleanup EXIT

cache_scan_status=0
rg -n --glob '*.[ch]' "$cache_pattern" "$src" "$common" > "$cache_report" ||
  cache_scan_status=$?
if [ "$cache_scan_status" -gt 1 ]; then
  echo "failed to audit PQClean comparator sources" >&2
  exit 2
fi
if [ -s "$cache_report" ]; then
  cat "$cache_report" >&2
  echo "persistent comparator cache detected; product build refused" >&2
  exit 2
fi

compile_c() {
  local input="$1"
  local output="$2"
  (
    cd "$src"
    "$C_COMPILER" "${pqclean_cflags_arr[@]}" "${section_flags[@]}" \
      -I"$ROOT_DIR/scripts" -I"$src" -I"$common" -I"$common/keccak4x" \
      -c "$input" -o "$output"
  )
}
compile_asm() {
  local input="$1"
  local output="$2"
  (
    cd "$src"
    "$C_COMPILER" "${pqclean_cflags_arr[@]}" "${section_flags[@]}" \
      -I"$src" -I"$common" -Wa,--noexecstack -c "$input" -o "$output"
  )
}

compile_c "$ROOT_DIR/scripts/goal_size_pqclean_adapter.c" "$work_dir/adapter.o"
for name in cbd consts fips202x4 indcpa kem poly polyvec rejsample \
    symmetric-shake verify; do
  compile_c "$src/$name.c" "$work_dir/$name.o"
done
compile_c "$common/fips202.c" "$work_dir/fips202.o"
compile_c "$common/keccak4x/KeccakP-1600-times4-SIMD256.c" \
  "$work_dir/keccak4x.o"
for name in basemul fq invntt ntt shuffle; do
  compile_asm "$src/$name.S" "$work_dir/$name.o"
done

mkdir -p "$(dirname "$OUTPUT")"
"$C_COMPILER" -r -nostdlib "$work_dir"/*.o -o "$work_dir/product.o" \
  -Wl,--gc-sections \
  -Wl,--undefined=goal_mlkem768_keypair_derand \
  -Wl,--undefined=goal_mlkem768_encaps_derand \
  -Wl,--undefined=goal_mlkem768_decaps
if readelf -Wr "$work_dir/product.o" | rg -n '\b(PQCLEAN_)?randombytes\b'; then
  echo "reachable PQClean product code depends on randombytes" >&2
  exit 2
fi
if objdump -d "$work_dir/product.o" | rg -n '%zmm|%k[0-7]' ||
    nm "$work_dir/product.o" | rg -n 'avx512'; then
  echo "AVX512 code detected in PQClean AVX2 product" >&2
  exit 2
fi

"$C_COMPILER" -O2 -I"$ROOT_DIR/scripts" \
  "$ROOT_DIR/scripts/goal_size_adapter_test.c" "$work_dir/product.o" \
  -Wl,-z,noexecstack -o "$work_dir/product_test"
"$work_dir/product_test"
cp "$work_dir/product.o" "$OUTPUT"

printf "profile=%s\n" "$PROFILE"
printf "compiler=%s\n" "$C_COMPILER"
printf "compiler_version=%s\n" "$("$C_COMPILER" --version | sed -n '1p')"
printf "pqclean_commit=%s\n" "$(git -C "$PQCLEAN_DIR" rev-parse HEAD)"
printf "pqclean_remote=%s\n" "$(git -C "$PQCLEAN_DIR" remote get-url origin)"
printf "pqclean_cflags=%s\n" "$PQCLEAN_AVX2_CFLAGS"
printf "normalization_cflags=%s\n" "${section_flags[*]}"
printf "cache_audit=pass\n"
printf "reachable_randombytes_audit=pass\n"
printf "avx512_audit=pass\n"
printf "correctness_smoke=pass\n"
REQUIRED_SYMBOLS="$REQUIRED_SYMBOLS" \
  "$ROOT_DIR/scripts/measure_elf_footprint.sh" "$OUTPUT"
