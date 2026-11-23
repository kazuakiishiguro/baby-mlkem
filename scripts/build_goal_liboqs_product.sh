#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/goal_speed_profile.sh"
PROFILE="${PROFILE:-${1:-native}}"
OUTPUT="${OUTPUT:-${2:-/tmp/baby-mlkem-liboqs-${PROFILE}-product.o}}"
LIBOQS_DIR="${LIBOQS_DIR:-/tmp/liboqs}"
C_COMPILER="${C_COMPILER:-clang}"
BUILD_JOBS="${BUILD_JOBS:-$(nproc)}"
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
if ! [[ "$BUILD_JOBS" =~ ^[1-9][0-9]*$ ]]; then
  echo "BUILD_JOBS must be a positive integer" >&2
  exit 2
fi
if ! command -v "$C_COMPILER" >/dev/null 2>&1; then
  echo "compiler not found: $C_COMPILER" >&2
  exit 2
fi
for tool in cmake git rg readelf objdump nm; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool" >&2
    exit 2
  fi
done
if [ ! -f "$LIBOQS_DIR/CMakeLists.txt" ] ||
    [ ! -f "$LIBOQS_DIR/src/kem/ml_kem/kem_ml_kem_768.c" ]; then
  echo "liboqs checkout is incomplete: $LIBOQS_DIR" >&2
  exit 2
fi
if ! git -C "$LIBOQS_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "liboqs directory is not a git checkout: $LIBOQS_DIR" >&2
  exit 2
fi
if ! git -C "$LIBOQS_DIR" diff --quiet ||
    ! git -C "$LIBOQS_DIR" diff --cached --quiet; then
  echo "liboqs checkout has tracked changes: $LIBOQS_DIR" >&2
  exit 2
fi

liboqs_cflags_override="${LIBOQS_CFLAGS:-}"
liboqs_opt_target_override="${LIBOQS_OPT_TARGET:-}"
liboqs_dist_build_override="${LIBOQS_DIST_BUILD:-}"
goal_speed_configure_profile "$PROFILE" "$C_COMPILER"
if [ -n "$liboqs_cflags_override" ]; then
  LIBOQS_CFLAGS="$liboqs_cflags_override"
fi
if [ -n "$liboqs_opt_target_override" ]; then
  LIBOQS_OPT_TARGET="$liboqs_opt_target_override"
fi
if [ -n "$liboqs_dist_build_override" ]; then
  LIBOQS_DIST_BUILD="$liboqs_dist_build_override"
fi
if [ "$LIBOQS_DIST_BUILD" != "OFF" ]; then
  echo "normalized liboqs product requires LIBOQS_DIST_BUILD=OFF" >&2
  exit 2
fi
read -r -a liboqs_cflags_arr <<< "$LIBOQS_CFLAGS"
case "$PROFILE" in
  native)
    if [ "$LIBOQS_OPT_TARGET" != "native" ]; then
      echo "native liboqs product requires LIBOQS_OPT_TARGET=native" >&2
      exit 2
    fi
    if [[ " $LIBOQS_CFLAGS " != *" -march=native "* ]]; then
      echo "native liboqs flags are missing -march=native" >&2
      exit 2
    fi
    ;;
  avx2)
    if [ "$LIBOQS_OPT_TARGET" != "x86-64-v3" ]; then
      echo "AVX2-only liboqs product requires LIBOQS_OPT_TARGET=x86-64-v3" >&2
      exit 2
    fi
    for token in -march=x86-64-v3 -mavx2 -mno-avx512f; do
      if [[ " $LIBOQS_CFLAGS " != *" $token "* ]]; then
        echo "AVX2-only liboqs flags are missing $token" >&2
        exit 2
      fi
    done
    if [[ " $LIBOQS_CFLAGS " == *" -march=native "* ]]; then
      echo "AVX2-only liboqs flags enable the native target" >&2
      exit 2
    fi
    ;;
esac
for token in "${liboqs_cflags_arr[@]}"; do
  if [[ "$token" == -mavx512* ]]; then
    echo "liboqs flags explicitly enable AVX512: $token" >&2
    exit 2
  fi
done

section_flags=(
  -ffunction-sections
  -fdata-sections
  -fno-unwind-tables
  -fno-asynchronous-unwind-tables
)
assembler_flags=(-Wa,--noexecstack)
normalization_cflags="${section_flags[*]} ${assembler_flags[*]}"
build_cflags="$LIBOQS_CFLAGS $normalization_cflags"
cache_pattern='(pk|public_key|matrix|hash)[[:alnum:]_]*cache|indcpa_enc_precomp'
cache_report="$(mktemp /tmp/baby-mlkem-liboqs-cache.XXXXXX)"
work_dir="$(mktemp -d /tmp/baby-mlkem-liboqs-product.XXXXXX)"
build_dir="$work_dir/build"
cleanup() {
  rm -f "$cache_report"
  rm -rf "$work_dir"
}
trap cleanup EXIT

cache_scan_status=0
rg -n -i --glob '*.[ch]' "$cache_pattern" \
  "$LIBOQS_DIR/src/kem/ml_kem" "$LIBOQS_DIR/src/common/sha3" \
  > "$cache_report" || cache_scan_status=$?
if [ "$cache_scan_status" -gt 1 ]; then
  echo "failed to audit liboqs comparator sources" >&2
  exit 2
fi
if [ -s "$cache_report" ]; then
  cat "$cache_report" >&2
  echo "persistent comparator cache detected; product build refused" >&2
  exit 2
fi

cmake -S "$LIBOQS_DIR" -B "$build_dir" \
  -DCMAKE_C_COMPILER="$C_COMPILER" \
  -DCMAKE_C_FLAGS="$build_cflags" \
  -DCMAKE_ASM_FLAGS="$LIBOQS_CFLAGS ${assembler_flags[*]}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_USE_OPENSSL=OFF \
  -DOQS_DIST_BUILD="$LIBOQS_DIST_BUILD" \
  -DOQS_OPT_TARGET="$LIBOQS_OPT_TARGET" \
  -DOQS_MINIMAL_BUILD=KEM_ml_kem_768 >/dev/null
cmake --build "$build_dir" --target oqs -j "$BUILD_JOBS" >/dev/null

archive="$build_dir/lib/liboqs.a"
config="$build_dir/include/oqs/oqsconfig.h"
cache="$build_dir/CMakeCache.txt"
if [ ! -f "$archive" ] || [ ! -f "$config" ]; then
  echo "liboqs static minimal build was not produced" >&2
  exit 2
fi
if ! rg -q '^#define OQS_ENABLE_KEM_ml_kem_768 1$' "$config" ||
    ! rg -q '^#define OQS_ENABLE_KEM_ml_kem_768_x86_64 1$' "$config"; then
  echo "liboqs minimal build did not enable the ML-KEM-768 x86_64 backend" >&2
  exit 2
fi
unexpected_algorithms="$(rg '^#define OQS_ENABLE_(KEM|SIG|SIG_STFL)_' "$config" |
  rg -v '^#define OQS_ENABLE_KEM_(ML_KEM|ml_kem_768|ml_kem_768_x86_64) 1$' || true)"
if [ -n "$unexpected_algorithms" ]; then
  printf '%s\n' "$unexpected_algorithms" >&2
  echo "liboqs minimal build enabled algorithms outside ML-KEM-768" >&2
  exit 2
fi
if ! rg -q '^OQS_MINIMAL_BUILD:STRING=KEM_ml_kem_768$' "$cache" ||
    ! rg -q '^OQS_DIST_BUILD:BOOL=OFF$' "$cache" ||
    ! rg -q "^OQS_OPT_TARGET:STRING=$LIBOQS_OPT_TARGET$" "$cache"; then
  echo "liboqs CMake cache does not match the normalized product profile" >&2
  exit 2
fi
if nm -g --defined-only "$archive" 2>/dev/null |
    rg -n 'OQS_KEM_ml_kem_(512|1024)'; then
  echo "liboqs minimal archive retained another ML-KEM parameter set" >&2
  exit 2
fi

"$C_COMPILER" "${liboqs_cflags_arr[@]}" "${section_flags[@]}" \
  "${assembler_flags[@]}" -I"$ROOT_DIR/scripts" -I"$build_dir/include" \
  -c "$ROOT_DIR/scripts/goal_size_liboqs_adapter.c" \
  -o "$work_dir/adapter.o"

"$C_COMPILER" -r -nostdlib "$work_dir/adapter.o" "$archive" \
  -o "$work_dir/product.o" -Wl,--gc-sections \
  -Wl,--undefined=goal_mlkem768_keypair_derand \
  -Wl,--undefined=goal_mlkem768_encaps_derand \
  -Wl,--undefined=goal_mlkem768_decaps

api_count="$(nm -g --defined-only "$work_dir/product.o" |
  awk '$3 ~ /^goal_mlkem768_/ { count++ } END { print count + 0 }')"
if [ "$api_count" -ne 3 ]; then
  echo "liboqs product must export exactly three goal APIs" >&2
  exit 2
fi
if readelf -Wr "$work_dir/product.o" |
    rg -n '\b(OQS_randombytes(_system)?|randombytes|getentropy|getrandom)\b'; then
  echo "reachable liboqs product code depends on an entropy source" >&2
  exit 2
fi
if readelf -SW "$work_dir/product.o" | rg -n '\.note\.GNU-stack.* X '; then
  echo "liboqs product requests an executable stack" >&2
  exit 2
fi
if [ "$PROFILE" = "avx2" ]; then
  if rg -q '^#define OQS_USE_AVX512_INSTRUCTIONS 1$' "$config" ||
      objdump -d "$work_dir/product.o" | rg -n '%zmm|%k[0-7]' ||
      nm "$work_dir/product.o" | rg -ni 'avx512'; then
    echo "AVX512 code detected in liboqs AVX2-only product" >&2
    exit 2
  fi
  avx512_audit=pass
else
  avx512_audit=not-applicable
fi

"$C_COMPILER" -O2 -I"$ROOT_DIR/scripts" \
  "$ROOT_DIR/scripts/goal_size_adapter_test.c" "$work_dir/product.o" \
  -pthread -Wl,-z,noexecstack -o "$work_dir/product_test"
"$work_dir/product_test"
mkdir -p "$(dirname "$OUTPUT")"
cp "$work_dir/product.o" "$OUTPUT"

printf "profile=%s\n" "$PROFILE"
printf "compiler=%s\n" "$C_COMPILER"
printf "compiler_version=%s\n" "$("$C_COMPILER" --version | sed -n '1p')"
printf "liboqs_commit=%s\n" "$(git -C "$LIBOQS_DIR" rev-parse HEAD)"
printf "liboqs_remote=%s\n" "$(git -C "$LIBOQS_DIR" remote get-url origin)"
printf "liboqs_minimal_build=KEM_ml_kem_768\n"
printf "liboqs_dist_build=%s\n" "$LIBOQS_DIST_BUILD"
printf "liboqs_opt_target=%s\n" "$LIBOQS_OPT_TARGET"
printf "liboqs_cflags=%s\n" "$LIBOQS_CFLAGS"
printf "normalization_cflags=%s\n" "$normalization_cflags"
printf "build_jobs=%s\n" "$BUILD_JOBS"
printf "api_count=%s\n" "$api_count"
printf "cache_audit=pass\n"
printf "minimal_algorithm_audit=pass\n"
printf "reachable_entropy_audit=pass\n"
printf "noexec_stack_audit=pass\n"
printf "avx512_audit=%s\n" "$avx512_audit"
printf "correctness_smoke=pass\n"
REQUIRED_SYMBOLS="$REQUIRED_SYMBOLS" \
  "$ROOT_DIR/scripts/measure_elf_footprint.sh" "$OUTPUT"
