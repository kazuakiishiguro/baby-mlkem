#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/goal_speed_profile.sh"
PROFILE="${PROFILE:-${1:-native}}"
OUTPUT="${OUTPUT:-${2:-/tmp/baby-mlkem-mlkem-native-${PROFILE}-product.o}}"
MLKEM_NATIVE_DIR="${MLKEM_NATIVE_DIR:-$ROOT_DIR/../mlkem-native}"
MLKEM_NATIVE_AUTO="${MLKEM_NATIVE_AUTO:-1}"
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
if [ "$MLKEM_NATIVE_AUTO" != "0" ] && [ "$MLKEM_NATIVE_AUTO" != "1" ]; then
  echo "MLKEM_NATIVE_AUTO must be 0 or 1" >&2
  exit 2
fi
if ! command -v "$C_COMPILER" >/dev/null 2>&1; then
  echo "compiler not found: $C_COMPILER" >&2
  exit 2
fi
for tool in git make rg readelf objdump nm; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool" >&2
    exit 2
  fi
done
if [ ! -f "$MLKEM_NATIVE_DIR/Makefile" ]; then
  echo "mlkem-native checkout is incomplete: $MLKEM_NATIVE_DIR" >&2
  exit 2
fi
if ! git -C "$MLKEM_NATIVE_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "mlkem-native directory is not a git checkout: $MLKEM_NATIVE_DIR" >&2
  exit 2
fi
if ! git -C "$MLKEM_NATIVE_DIR" diff --quiet ||
    ! git -C "$MLKEM_NATIVE_DIR" diff --cached --quiet; then
  echo "mlkem-native checkout has tracked changes: $MLKEM_NATIVE_DIR" >&2
  exit 2
fi

if [ -f "$MLKEM_NATIVE_DIR/mlkem/mlkem_native.h" ]; then
  api_mode=modern
  adapter_defines=(
    -DGOAL_MLKEM_NATIVE_MODERN_API
    -DMLK_CONFIG_PARAMETER_SET=768
    -DMLK_CONFIG_NO_RANDOMIZED_API
  )
elif [ -f "$MLKEM_NATIVE_DIR/mlkem/kem.h" ]; then
  api_mode=legacy
  adapter_defines=(-DMLKEM_K=3 -DMLKEM_USE_NATIVE -DFORCE_X86_64)
else
  echo "unsupported mlkem-native API layout: $MLKEM_NATIVE_DIR" >&2
  exit 2
fi

if [ -z "${MLKEM_NATIVE_CFLAGS:-}" ]; then
  goal_speed_configure_profile "$PROFILE" "$C_COMPILER"
fi
read -r -a mlkem_cflags_arr <<< "$MLKEM_NATIVE_CFLAGS"
case "$PROFILE" in
  native)
    if [[ " $MLKEM_NATIVE_CFLAGS " != *" -march=native "* ]]; then
      echo "native mlkem-native flags are missing -march=native" >&2
      exit 2
    fi
    ;;
  avx2)
    for token in -march=x86-64-v3 -mavx2 -mno-avx512f; do
      if [[ " $MLKEM_NATIVE_CFLAGS " != *" $token "* ]]; then
        echo "AVX2-only mlkem-native flags are missing $token" >&2
        exit 2
      fi
    done
    if [[ " $MLKEM_NATIVE_CFLAGS " == *" -march=native "* ]]; then
      echo "AVX2-only mlkem-native flags enable the native target" >&2
      exit 2
    fi
    ;;
esac
for token in "${mlkem_cflags_arr[@]}"; do
  if [[ "$token" == -mavx512* ]]; then
    echo "mlkem-native flags explicitly enable AVX512: $token" >&2
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
config_flags=(-DMLK_CONFIG_NO_RANDOMIZED_API)
cache_pattern='(pk|public_key|matrix|at|hash)[[:alnum:]_]*cache|indcpa_enc_precomp'
cache_report="$(mktemp /tmp/baby-mlkem-native-cache.XXXXXX)"
work_dir="$(mktemp -d /tmp/baby-mlkem-native-product.XXXXXX)"
build_dir="$work_dir/build"
archive="$build_dir/libmlkem768.a"
cleanup() {
  rm -f "$cache_report"
  rm -rf "$work_dir"
}
trap cleanup EXIT

cache_scan_status=0
rg -n --glob '*.[ch]' "$cache_pattern" "$MLKEM_NATIVE_DIR/mlkem" \
  > "$cache_report" || cache_scan_status=$?
if [ "$cache_scan_status" -gt 1 ]; then
  echo "failed to audit mlkem-native comparator sources" >&2
  exit 2
fi
if [ -s "$cache_report" ]; then
  cat "$cache_report" >&2
  echo "persistent comparator cache detected; product build refused" >&2
  exit 2
fi

build_cflags="${MLKEM_NATIVE_CFLAGS} ${section_flags[*]} ${assembler_flags[*]} ${config_flags[*]}"
env CFLAGS="$build_cflags" \
  make -C "$MLKEM_NATIVE_DIR" BUILD_DIR="$build_dir" \
    CC="$C_COMPILER" OPT=1 AUTO="$MLKEM_NATIVE_AUTO" "$archive" >/dev/null
if [ ! -f "$archive" ]; then
  echo "mlkem-native archive was not produced: $archive" >&2
  exit 2
fi

"$C_COMPILER" -O3 "${mlkem_cflags_arr[@]}" "${section_flags[@]}" "${assembler_flags[@]}" \
  "${adapter_defines[@]}" -I"$ROOT_DIR/scripts" -I"$MLKEM_NATIVE_DIR/mlkem" \
  -c "$ROOT_DIR/scripts/goal_size_mlkem_native_adapter.c" \
  -o "$work_dir/adapter.o"

"$C_COMPILER" -r -nostdlib "$work_dir/adapter.o" "$archive" \
  -o "$work_dir/product.o" -Wl,--gc-sections \
  -Wl,--undefined=goal_mlkem768_keypair_derand \
  -Wl,--undefined=goal_mlkem768_encaps_derand \
  -Wl,--undefined=goal_mlkem768_decaps

api_count="$(nm -g --defined-only "$work_dir/product.o" |
  awk '$3 ~ /^goal_mlkem768_/ { count++ } END { print count + 0 }')"
if [ "$api_count" -ne 3 ]; then
  echo "mlkem-native product must export exactly three goal APIs" >&2
  exit 2
fi
if readelf -Wr "$work_dir/product.o" | rg -n '\brandombytes\b'; then
  echo "reachable mlkem-native product code depends on randombytes" >&2
  exit 2
fi
if [ "$PROFILE" = "avx2" ]; then
  if objdump -d "$work_dir/product.o" | rg -n '%zmm|%k[0-7]' ||
      nm "$work_dir/product.o" | rg -n 'avx512'; then
    echo "AVX512 code detected in mlkem-native AVX2-only product" >&2
    exit 2
  fi
  avx512_audit=pass
else
  avx512_audit=not-applicable
fi

"$C_COMPILER" -O2 -I"$ROOT_DIR/scripts" \
  "$ROOT_DIR/scripts/goal_size_adapter_test.c" "$work_dir/product.o" \
  -Wl,-z,noexecstack -o "$work_dir/product_test"
"$work_dir/product_test"
mkdir -p "$(dirname "$OUTPUT")"
cp "$work_dir/product.o" "$OUTPUT"

printf "profile=%s\n" "$PROFILE"
printf "compiler=%s\n" "$C_COMPILER"
printf "compiler_version=%s\n" "$("$C_COMPILER" --version | sed -n '1p')"
printf "mlkem_native_commit=%s\n" \
  "$(git -C "$MLKEM_NATIVE_DIR" rev-parse HEAD)"
printf "mlkem_native_remote=%s\n" \
  "$(git -C "$MLKEM_NATIVE_DIR" remote get-url origin)"
printf "mlkem_native_api_mode=%s\n" "$api_mode"
printf "mlkem_native_auto=%s\n" "$MLKEM_NATIVE_AUTO"
printf "mlkem_native_cflags=%s\n" "$MLKEM_NATIVE_CFLAGS"
printf "normalization_cflags=%s\n" "${section_flags[*]} ${assembler_flags[*]} ${config_flags[*]}"
printf "api_count=%s\n" "$api_count"
printf "cache_audit=pass\n"
printf "reachable_randombytes_audit=pass\n"
printf "avx512_audit=%s\n" "$avx512_audit"
printf "correctness_smoke=pass\n"
REQUIRED_SYMBOLS="$REQUIRED_SYMBOLS" \
  "$ROOT_DIR/scripts/measure_elf_footprint.sh" "$OUTPUT"
