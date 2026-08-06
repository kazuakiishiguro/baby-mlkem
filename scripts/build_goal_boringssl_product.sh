#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/goal_speed_profile.sh"
PROFILE="${PROFILE:-${1:-native}}"
OUTPUT="${OUTPUT:-${2:-/tmp/baby-mlkem-boringssl-${PROFILE}-product.o}}"
BORINGSSL_DIR="${BORINGSSL_DIR:-/tmp/boringssl}"
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
for tool in ar cmake git ninja nm objcopy objdump readelf rg; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool" >&2
    exit 2
  fi
done
if [ ! -f "$BORINGSSL_DIR/CMakeLists.txt" ] ||
    [ ! -f "$BORINGSSL_DIR/crypto/fipsmodule/bcm.cc" ] ||
    [ ! -f "$BORINGSSL_DIR/crypto/fipsmodule/mlkem/mlkem.cc.inc" ]; then
  echo "BoringSSL checkout is incomplete: $BORINGSSL_DIR" >&2
  exit 2
fi
if ! git -C "$BORINGSSL_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "BoringSSL directory is not a git checkout: $BORINGSSL_DIR" >&2
  exit 2
fi
if ! git -C "$BORINGSSL_DIR" diff --quiet ||
    ! git -C "$BORINGSSL_DIR" diff --cached --quiet; then
  echo "BoringSSL checkout has tracked changes: $BORINGSSL_DIR" >&2
  exit 2
fi

boringssl_cflags_override="${BORINGSSL_C_FLAGS:-}"
boringssl_cxxflags_override="${BORINGSSL_CXX_FLAGS:-}"
goal_speed_configure_profile "$PROFILE" "$C_COMPILER"
if [ -n "$boringssl_cflags_override" ]; then
  BORINGSSL_C_FLAGS="$boringssl_cflags_override"
fi
if [ -n "$boringssl_cxxflags_override" ]; then
  BORINGSSL_CXX_FLAGS="$boringssl_cxxflags_override"
fi
if ! command -v "$CXX_COMPILER" >/dev/null 2>&1; then
  echo "matching C++ compiler not found: $CXX_COMPILER" >&2
  exit 2
fi

validate_native_flags() {
  local label="$1"
  local flags="$2"
  local token
  local -a flag_array

  read -r -a flag_array <<< "$flags"
  if [[ " $flags " != *" -march=native "* ]]; then
    echo "$label is missing -march=native" >&2
    return 2
  fi
  for token in "${flag_array[@]}"; do
    if [[ "$token" == -march=* ]] && [ "$token" != "-march=native" ]; then
      echo "$label contains conflicting architecture flag: $token" >&2
      return 2
    fi
  done
}

validate_avx2_flags() {
  local label="$1"
  local flags="$2"
  local token
  local -a flag_array

  read -r -a flag_array <<< "$flags"
  for token in -march=x86-64-v3 -mavx2 -mno-avx512f; do
    if [[ " $flags " != *" $token "* ]]; then
      echo "$label is missing $token" >&2
      return 2
    fi
  done
  if [[ " $flags " == *" -march=native "* ]]; then
    echo "$label contains forbidden -march=native" >&2
    return 2
  fi
  for token in "${flag_array[@]}"; do
    if [[ "$token" == -mavx512* ]]; then
      echo "$label explicitly enables AVX512: $token" >&2
      return 2
    fi
  done
}

case "$PROFILE" in
  native)
    validate_native_flags BORINGSSL_C_FLAGS "$BORINGSSL_C_FLAGS"
    validate_native_flags BORINGSSL_CXX_FLAGS "$BORINGSSL_CXX_FLAGS"
    ;;
  avx2)
    validate_avx2_flags BORINGSSL_C_FLAGS "$BORINGSSL_C_FLAGS"
    validate_avx2_flags BORINGSSL_CXX_FLAGS "$BORINGSSL_CXX_FLAGS"
    ;;
esac

read -r -a boringssl_cflags_arr <<< "$BORINGSSL_C_FLAGS"
read -r -a boringssl_cxxflags_arr <<< "$BORINGSSL_CXX_FLAGS"
section_flags=(
  -ffunction-sections
  -fdata-sections
  -fno-unwind-tables
  -fno-asynchronous-unwind-tables
)
assembler_flags=(-Wa,--noexecstack)
normalization_cflags="${section_flags[*]} ${assembler_flags[*]}"
build_cflags="$BORINGSSL_C_FLAGS $normalization_cflags"
build_cxxflags="$BORINGSSL_CXX_FLAGS $normalization_cflags -fno-strict-aliasing"
cache_pattern='(pk|public_key|matrix|hash)[[:alnum:]_]*cache|indcpa_enc_precomp'
cache_report="$(mktemp /tmp/baby-mlkem-boringssl-cache.XXXXXX)"
work_dir="$(mktemp -d /tmp/baby-mlkem-boringssl-product.XXXXXX)"
build_dir="$work_dir/build"
cleanup() {
  rm -f "$cache_report"
  rm -rf "$work_dir"
}
trap cleanup EXIT

cache_scan_status=0
rg -n -i --glob '*.cc' --glob '*.inc' --glob '*.h' "$cache_pattern" \
  "$BORINGSSL_DIR/crypto/fipsmodule/mlkem" \
  "$BORINGSSL_DIR/crypto/fipsmodule/keccak" \
  > "$cache_report" || cache_scan_status=$?
if [ "$cache_scan_status" -gt 1 ]; then
  echo "failed to audit BoringSSL comparator sources" >&2
  exit 2
fi
if [ -s "$cache_report" ]; then
  cat "$cache_report" >&2
  echo "persistent comparator cache detected; product build refused" >&2
  exit 2
fi

cmake -S "$BORINGSSL_DIR" -B "$build_dir" -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="$C_COMPILER" \
  -DCMAKE_CXX_COMPILER="$CXX_COMPILER" \
  -DCMAKE_C_FLAGS="$build_cflags" \
  -DCMAKE_CXX_FLAGS="$build_cxxflags" \
  -DCMAKE_ASM_FLAGS="$BORINGSSL_C_FLAGS ${assembler_flags[*]}" \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF >/dev/null
cmake --build "$build_dir" --target crypto -j "$BUILD_JOBS" >/dev/null

archive="$build_dir/libcrypto.a"
if [ ! -f "$archive" ]; then
  echo "BoringSSL static crypto archive was not produced" >&2
  exit 2
fi
bcm_member_count="$(ar t "$archive" |
  awk '$0 == "bcm.cc.o" { count++ } END { print count + 0 }')"
if [ "$bcm_member_count" -ne 1 ]; then
  echo "expected exactly one bcm.cc.o archive member, found $bcm_member_count" >&2
  exit 2
fi
cp "$archive" "$work_dir/libcrypto-without-bcm.a"
ar d "$work_dir/libcrypto-without-bcm.a" bcm.cc.o
if ar t "$work_dir/libcrypto-without-bcm.a" | rg -n '^bcm\.cc\.o$'; then
  echo "failed to replace BoringSSL bcm.cc.o with the normalized unity object" >&2
  exit 2
fi

cat > "$work_dir/unity.cc" <<'UNITY_EOF'
#include "crypto/fipsmodule/bcm.cc"
#include "goal_size_boringssl_adapter.cc"
UNITY_EOF
"$CXX_COMPILER" "${boringssl_cxxflags_arr[@]}" \
  "${section_flags[@]}" "${assembler_flags[@]}" \
  -DBORINGSSL_IMPLEMENTATION \
  -I"$BORINGSSL_DIR/include" -I"$BORINGSSL_DIR" -I"$ROOT_DIR/scripts" \
  -fno-strict-aliasing -fno-common -fvisibility=hidden -DNDEBUG \
  -std=gnu++17 -fno-exceptions -fno-rtti \
  -c "$work_dir/unity.cc" -o "$work_dir/unity.o"

"$CXX_COMPILER" -r -nostdlib "$work_dir/unity.o" \
  "$work_dir/libcrypto-without-bcm.a" -o "$work_dir/product.o" \
  -Wl,--gc-sections \
  -Wl,--undefined=goal_mlkem768_keypair_derand \
  -Wl,--undefined=goal_mlkem768_encaps_derand \
  -Wl,--undefined=goal_mlkem768_decaps
objcopy --strip-debug --remove-section=.note.gnu.build-id \
  "$work_dir/product.o" "$work_dir/product-stripped.o"

api_count="$(nm -g --defined-only "$work_dir/product-stripped.o" |
  awk '$3 ~ /^goal_mlkem768_/ { count++ } END { print count + 0 }')"
if [ "$api_count" -ne 3 ]; then
  echo "BoringSSL product must export exactly three goal APIs" >&2
  exit 2
fi
if readelf -Wr "$work_dir/product-stripped.o" |
    rg -ni 'RAND_|BCM_rand|syscall|getentropy|getrandom|urandom'; then
  echo "reachable BoringSSL product code depends on an entropy source" >&2
  exit 2
fi
if readelf -SW "$work_dir/product-stripped.o" |
    rg -n '\.note\.GNU-stack.* X '; then
  echo "BoringSSL product requests an executable stack" >&2
  exit 2
fi
if [ "$PROFILE" = "avx2" ]; then
  if objdump -d "$work_dir/product-stripped.o" | rg -n '%zmm|%k[0-7]' ||
      nm "$work_dir/product-stripped.o" | rg -ni 'avx512'; then
    echo "AVX512 code detected in BoringSSL AVX2-only product" >&2
    exit 2
  fi
  avx512_audit=pass
else
  avx512_audit=not-applicable
fi

"$C_COMPILER" -O2 -I"$ROOT_DIR/scripts" \
  "$ROOT_DIR/scripts/goal_size_adapter_test.c" \
  "$work_dir/product-stripped.o" -pthread -ldl -Wl,-z,noexecstack \
  -o "$work_dir/product_test"
"$work_dir/product_test"
mkdir -p "$(dirname "$OUTPUT")"
cp "$work_dir/product-stripped.o" "$OUTPUT"

printf "profile=%s\n" "$PROFILE"
printf "compiler=%s\n" "$C_COMPILER"
printf "compiler_version=%s\n" "$("$C_COMPILER" --version | sed -n '1p')"
printf "cxx_compiler=%s\n" "$CXX_COMPILER"
printf "cxx_compiler_version=%s\n" "$("$CXX_COMPILER" --version | sed -n '1p')"
printf "boringssl_commit=%s\n" "$(git -C "$BORINGSSL_DIR" rev-parse HEAD)"
printf "boringssl_remote=%s\n" "$(git -C "$BORINGSSL_DIR" remote get-url origin)"
printf "boringssl_cflags=%s\n" "$BORINGSSL_C_FLAGS"
printf "boringssl_cxxflags=%s\n" "$BORINGSSL_CXX_FLAGS"
printf "normalization_cflags=%s\n" "$normalization_cflags"
printf "build_jobs=%s\n" "$BUILD_JOBS"
printf "original_bcm_member_count=%s\n" "$bcm_member_count"
printf "bcm_unity_replacement_audit=pass\n"
printf "build_id_removed=pass\n"
printf "api_count=%s\n" "$api_count"
printf "cache_audit=pass\n"
printf "reachable_entropy_audit=pass\n"
printf "noexec_stack_audit=pass\n"
printf "avx512_audit=%s\n" "$avx512_audit"
printf "correctness_smoke=pass\n"
REQUIRED_SYMBOLS="$REQUIRED_SYMBOLS" \
  "$ROOT_DIR/scripts/measure_elf_footprint.sh" "$OUTPUT"
