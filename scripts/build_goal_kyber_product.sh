#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/goal_speed_profile.sh"
PROFILE="${PROFILE:-${1:-native}}"
OUTPUT="${OUTPUT:-${2:-/tmp/baby-mlkem-kyber-${PROFILE}-product.o}}"
KYBER_DIR="${KYBER_DIR:-/tmp/kyber}"
C_COMPILER="${C_COMPILER:-clang}"
ALLOW_CACHED_COMPARATOR="${ALLOW_CACHED_COMPARATOR:-0}"
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
if [ "$ALLOW_CACHED_COMPARATOR" != "0" ] &&
    [ "$ALLOW_CACHED_COMPARATOR" != "1" ]; then
  echo "ALLOW_CACHED_COMPARATOR must be 0 or 1" >&2
  exit 2
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
if [ ! -d "$KYBER_DIR/avx2" ] || [ ! -d "$KYBER_DIR/ref" ]; then
  echo "Kyber checkout is incomplete: $KYBER_DIR" >&2
  exit 2
fi
if ! git -C "$KYBER_DIR" diff --quiet ||
    ! git -C "$KYBER_DIR" diff --cached --quiet; then
  echo "Kyber checkout has tracked changes: $KYBER_DIR" >&2
  exit 2
fi

if [ -z "${UPSTREAM_CFLAGS:-}" ]; then
  goal_speed_configure_profile "$PROFILE" "$C_COMPILER"
fi
read -r -a upstream_cflags_arr <<< "$UPSTREAM_CFLAGS"
case "$PROFILE" in
  native)
    if [[ " $UPSTREAM_CFLAGS " != *" -march=native "* ]]; then
      echo "native upstream flags are missing -march=native" >&2
      exit 2
    fi
    ;;
  avx2)
    for token in -march=x86-64-v3 -mavx2 -mno-avx512f; do
      if [[ " $UPSTREAM_CFLAGS " != *" $token "* ]]; then
        echo "AVX2 upstream flags are missing $token" >&2
        exit 2
      fi
    done
    positive_avx512=0
    for token in "${upstream_cflags_arr[@]}"; do
      if [[ "$token" == -mavx512* ]]; then
        positive_avx512=1
      fi
    done
    if [[ " $UPSTREAM_CFLAGS " == *" -march=native "* ]] ||
        [ "$positive_avx512" = "1" ]; then
      echo "AVX2 upstream flags enable a forbidden native/AVX512 path" >&2
      exit 2
    fi
    ;;
esac
section_flags=(
  -ffunction-sections
  -fdata-sections
  -fno-unwind-tables
  -fno-asynchronous-unwind-tables
)

cache_pattern='(pk|public_key|matrix|at|hash)[[:alnum:]_]*cache|indcpa_enc_precomp'
cache_report="$(mktemp /tmp/baby-mlkem-kyber-cache.XXXXXX)"
work_dir="$(mktemp -d /tmp/baby-mlkem-kyber-product.XXXXXX)"
cleanup() {
  rm -f "$cache_report"
  rm -rf "$work_dir"
}
trap cleanup EXIT

cache_scan_status=0
rg -n --glob '*.[ch]' "$cache_pattern" \
  "$KYBER_DIR/avx2" "$KYBER_DIR/ref" > "$cache_report" ||
  cache_scan_status=$?
if [ "$cache_scan_status" -gt 1 ]; then
  echo "failed to audit Kyber comparator sources" >&2
  exit 2
fi
if [ -s "$cache_report" ]; then
  if [ "$ALLOW_CACHED_COMPARATOR" != "1" ]; then
    cat "$cache_report" >&2
    echo "persistent comparator cache detected; product build refused" >&2
    exit 2
  fi
  echo "warning: cached Kyber product explicitly allowed; artifact cannot qualify" >&2
  cache_audit=override
else
  cache_audit=pass
fi

src="$KYBER_DIR/avx2"
compile_c() {
  local input="$1"
  local output="$2"
  "$C_COMPILER" "${upstream_cflags_arr[@]}" "${section_flags[@]}" \
    -DKYBER_K=3 -I"$ROOT_DIR/scripts" -I"$src" -I"$src/keccak4x" \
    -c "$input" -o "$output"
}
compile_asm() {
  local input="$1"
  local output="$2"
  "$C_COMPILER" "${upstream_cflags_arr[@]}" "${section_flags[@]}" \
    -DKYBER_K=3 -I"$src" -I"$src/keccak4x" -Wa,--noexecstack \
    -c "$input" -o "$output"
}

compile_c "$ROOT_DIR/scripts/goal_size_kyber_adapter.c" "$work_dir/adapter.o"
for name in kem indcpa polyvec poly consts rejsample cbd verify fips202 \
    fips202x4 symmetric-shake; do
  compile_c "$src/$name.c" "$work_dir/$name.o"
done
compile_c "$src/keccak4x/KeccakP-1600-times4-SIMD256.c" \
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
if readelf -Wr "$work_dir/product.o" | rg -n '\brandombytes\b'; then
  echo "reachable Kyber product code depends on randombytes" >&2
  exit 2
fi
if [ "$PROFILE" = "avx2" ]; then
  if objdump -d "$work_dir/product.o" | rg -n '%zmm|%k[0-7]' ||
      nm "$work_dir/product.o" | rg -n 'avx512'; then
    echo "AVX512 code detected in Kyber AVX2-only product" >&2
    exit 2
  fi
fi

"$C_COMPILER" -O2 -I"$ROOT_DIR/scripts" \
  "$ROOT_DIR/scripts/goal_size_adapter_test.c" "$work_dir/product.o" \
  -Wl,-z,noexecstack -o "$work_dir/product_test"
"$work_dir/product_test"
cp "$work_dir/product.o" "$OUTPUT"

printf "profile=%s\n" "$PROFILE"
printf "compiler=%s\n" "$C_COMPILER"
printf "compiler_version=%s\n" "$("$C_COMPILER" --version | sed -n '1p')"
printf "kyber_commit=%s\n" "$(git -C "$KYBER_DIR" rev-parse HEAD)"
printf "kyber_remote=%s\n" "$(git -C "$KYBER_DIR" remote get-url origin)"
printf "upstream_cflags=%s\n" "$UPSTREAM_CFLAGS"
printf "normalization_cflags=%s\n" "${section_flags[*]}"
printf "cache_audit=%s\n" "$cache_audit"
printf "correctness_smoke=pass\n"
REQUIRED_SYMBOLS="$REQUIRED_SYMBOLS" \
  "$ROOT_DIR/scripts/measure_elf_footprint.sh" "$OUTPUT"
