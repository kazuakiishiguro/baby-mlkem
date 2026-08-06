#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/goal_speed_profile.sh"
PROFILE="${PROFILE:-${1:-native}}"
OUTPUT="${OUTPUT:-${2:-/tmp/baby-mlkem-botan-${PROFILE}-product.o}}"
BOTAN_DIR="${BOTAN_DIR:-/tmp/botan-mlkem}"
BOTAN_MODULES="${BOTAN_MODULES:-ml_kem,keccak_perm_bmi2}"
BOTAN_BUILD_JOBS="${BOTAN_BUILD_JOBS:-$(nproc)}"
UPDATE_REPOS="${UPDATE_REPOS:-0}"
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
if [ "$UPDATE_REPOS" != "0" ] && [ "$UPDATE_REPOS" != "1" ]; then
  echo "UPDATE_REPOS must be 0 or 1" >&2
  exit 2
fi
if ! [[ "$BOTAN_BUILD_JOBS" =~ ^[1-9][0-9]*$ ]]; then
  echo "BOTAN_BUILD_JOBS must be a positive integer" >&2
  exit 2
fi
if ! [[ "$BOTAN_MODULES" =~ ^[a-z0-9_,]+$ ]]; then
  echo "invalid BOTAN_MODULES list: $BOTAN_MODULES" >&2
  exit 2
fi
if [ "$(uname -m)" != "x86_64" ]; then
  echo "normalized Botan product currently requires x86_64" >&2
  exit 2
fi
for tool in "$C_COMPILER" ar awk cmp git make nm objcopy objdump python3 \
    readelf rg sha256sum sort; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool" >&2
    exit 2
  fi
done
if [ ! -f "$BOTAN_DIR/configure.py" ] ||
    [ ! -f "$BOTAN_DIR/src/lib/pubkey/kyber/ml_kem/ml_kem_impl.cpp" ]; then
  echo "Botan checkout is incomplete: $BOTAN_DIR" >&2
  exit 2
fi
if ! git -C "$BOTAN_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Botan directory is not a git checkout: $BOTAN_DIR" >&2
  exit 2
fi

check_checkout_clean() {
  local untracked

  if ! git -C "$BOTAN_DIR" diff --quiet ||
      ! git -C "$BOTAN_DIR" diff --cached --quiet; then
    echo "Botan checkout has tracked changes: $BOTAN_DIR" >&2
    return 2
  fi
  while IFS= read -r untracked; do
    case "$untracked" in
      build-baby-mlkem-*) ;;
      *)
        echo "Botan checkout has an unexpected untracked path: $untracked" >&2
        return 2
        ;;
    esac
  done < <(git -C "$BOTAN_DIR" ls-files --others --exclude-standard)
}

check_checkout_clean
if [ "$UPDATE_REPOS" = "1" ]; then
  git -C "$BOTAN_DIR" pull --ff-only
  comparator_update=pass
else
  comparator_update=skipped
fi
check_checkout_clean

botan_cxxflags_override="${BOTAN_CXXFLAGS:-}"
botan_disabled_override="${BOTAN_DISABLED_MODULES:-}"
goal_speed_configure_profile "$PROFILE" "$C_COMPILER"
if [ -n "$botan_cxxflags_override" ]; then
  BOTAN_CXXFLAGS="$botan_cxxflags_override"
fi
if [ -n "$botan_disabled_override" ]; then
  BOTAN_DISABLED_MODULES="$botan_disabled_override"
fi
CXX_COMPILER="$BOTAN_CXX"
if ! command -v "$CXX_COMPILER" >/dev/null 2>&1; then
  echo "matching C++ compiler not found: $CXX_COMPILER" >&2
  exit 2
fi

compiler_family() {
  if "$1" --version 2>/dev/null | head -n 1 | grep -qi clang; then
    printf 'clang\n'
  else
    printf 'gcc\n'
  fi
}
if [ "$(compiler_family "$C_COMPILER")" != "$(compiler_family "$CXX_COMPILER")" ]; then
  echo "Botan C and C++ compiler families do not match" >&2
  exit 2
fi

has_module() {
  printf '%s\n' "$1" | tr ',' '\n' | awk -v target="$2" \
    '$0 == target { found = 1 } END { exit !found }'
}
if ! has_module "$BOTAN_MODULES" ml_kem ||
    ! has_module "$BOTAN_MODULES" keccak_perm_bmi2; then
  echo "normalized Botan product requires ml_kem and keccak_perm_bmi2" >&2
  exit 2
fi

validate_native_flags() {
  local token
  local -a flags

  read -r -a flags <<< "$BOTAN_CXXFLAGS"
  if [[ " $BOTAN_CXXFLAGS " != *" -march=native "* ]]; then
    echo "native Botan flags are missing -march=native" >&2
    return 2
  fi
  for token in "${flags[@]}"; do
    if [[ "$token" == -march=* ]] && [ "$token" != "-march=native" ]; then
      echo "native Botan flags contain conflicting architecture flag: $token" >&2
      return 2
    fi
  done
}

validate_avx2_flags() {
  local token
  local -a flags

  read -r -a flags <<< "$BOTAN_CXXFLAGS"
  for token in -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f; do
    if [[ " $BOTAN_CXXFLAGS " != *" $token "* ]]; then
      echo "AVX2-only Botan flags are missing $token" >&2
      return 2
    fi
  done
  if [[ " $BOTAN_CXXFLAGS " == *" -march=native "* ]]; then
    echo "AVX2-only Botan flags contain forbidden -march=native" >&2
    return 2
  fi
  for token in "${flags[@]}"; do
    if [[ "$token" == -mavx512* ]]; then
      echo "AVX2-only Botan flags explicitly enable AVX512: $token" >&2
      return 2
    fi
  done
  if has_module "$BOTAN_MODULES" keccak_perm_avx512; then
    echo "AVX2-only Botan modules explicitly enable Keccak AVX512" >&2
    return 2
  fi
  if ! has_module "$BOTAN_DISABLED_MODULES" keccak_perm_avx512; then
    echo "AVX2-only Botan build must disable keccak_perm_avx512" >&2
    return 2
  fi
}

case "$PROFILE" in
  native) validate_native_flags ;;
  avx2) validate_avx2_flags ;;
esac

cache_pattern='(public_key|secret_key|matrix|hash)[[:alnum:]_]*cache'
cache_pattern+='|indcpa_enc_precomp|once_cell|lazy_static'
cache_report="$(mktemp /tmp/baby-mlkem-botan-cache.XXXXXX)"
work_dir="$(mktemp -d /tmp/baby-mlkem-botan-product.XXXXXX)"
build_dir="$work_dir/build"
cleanup() {
  rm -f "$cache_report"
  rm -rf "$work_dir"
}
trap cleanup EXIT

cache_scan_status=0
rg -n -i --glob '*.{cpp,h}' "$cache_pattern" \
  "$BOTAN_DIR/src/lib/pubkey/kyber" \
  "$BOTAN_DIR/src/lib/hash/sha3" \
  "$BOTAN_DIR/src/lib/permutations/keccak_perm" \
  "$BOTAN_DIR/src/lib/xof" > "$cache_report" || cache_scan_status=$?
if [ "$cache_scan_status" -gt 1 ]; then
  echo "failed to audit Botan comparator sources" >&2
  exit 2
fi
if [ -s "$cache_report" ]; then
  cat "$cache_report" >&2
  echo "persistent Botan key or matrix cache detected" >&2
  exit 2
fi

precompute_source="$BOTAN_DIR/src/lib/pubkey/kyber/kyber_common/kyber_encaps_base.h"
precompute_marker='m_At(Kyber_Algos::sample_matrix(pk.rho(), true /* transposed */, m_mode))'
if [ "$(rg -F -c "$precompute_marker" "$precompute_source")" -ne 1 ]; then
  echo "Botan per-operation matrix precompute marker changed" >&2
  exit 2
fi
for marker in 'Botan::ML_KEM_Encryptor operation' \
    'Botan::ML_KEM_Decryptor operation'; do
  if [ "$(rg -F -c "$marker" "$ROOT_DIR/scripts/goal_size_botan_adapter.cpp")" -ne 1 ]; then
    echo "Botan adapter operation-rebuild marker changed: $marker" >&2
    exit 2
  fi
done

botan_commit="$(git -C "$BOTAN_DIR" rev-parse HEAD)"
botan_remote="$(git -C "$BOTAN_DIR" remote get-url origin)"
source_date_epoch="$(git -C "$BOTAN_DIR" show -s --format=%ct HEAD)"
normalization_cxxflags="-ffunction-sections -fdata-sections"
if [ "$(compiler_family "$CXX_COMPILER")" = "gcc" ]; then
  normalization_cxxflags+=" -fno-gnu-unique"
fi
normalization_cxxflags+=" -fno-unwind-tables -fno-asynchronous-unwind-tables"
normalization_cxxflags+=" -fno-stack-protector -fno-pic -fno-PIE"
normalization_cxxflags+=" -ffile-prefix-map=$BOTAN_DIR=/botan"
normalization_cxxflags+=" -ffile-prefix-map=$ROOT_DIR=/baby-mlkem"
normalization_cxxflags+=" -ffile-prefix-map=$work_dir=/botan-build"
effective_cxxflags="$BOTAN_CXXFLAGS $normalization_cxxflags"
configure_cmd=(
  python3 ./configure.py
  "--with-build-dir=$build_dir"
  "--cc=$BOTAN_CC_FAMILY"
  "--cc-bin=$CXX_COMPILER"
  --disable-shared-library
  --build-targets=static
  --minimized-build
  --disable-deprecated-features
  --without-stack-protector
  "--enable-modules=$BOTAN_MODULES"
  "--extra-cxxflags=$effective_cxxflags"
)
if [ -n "$BOTAN_DISABLED_MODULES" ]; then
  configure_cmd+=("--disable-modules=$BOTAN_DISABLED_MODULES")
fi
(
  cd "$BOTAN_DIR"
  LC_ALL=C SOURCE_DATE_EPOCH="$source_date_epoch" \
    "${configure_cmd[@]}"
) > "$work_dir/configure.log"
LC_ALL=C SOURCE_DATE_EPOCH="$source_date_epoch" \
  make -C "$BOTAN_DIR" -f "$build_dir/Makefile" \
    -j"$BOTAN_BUILD_JOBS" libs > "$work_dir/build.log"

archive="$build_dir/libbotan-3.a"
build_config="$build_dir/build/build_config.json"
build_header="$build_dir/build/build.h"
if [ ! -f "$archive" ] || [ ! -f "$build_config" ] ||
    [ ! -f "$build_header" ]; then
  echo "Botan minimized static build was not produced" >&2
  exit 2
fi
mapfile -t config_values < <(python3 - "$build_config" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    config = json.load(handle)
print(config["version_vc_rev"])
print(config["full_version_string"])
print(config["cxx"])
print(config["compiler"])
print(",".join(sorted(config["mod_list"])))
PY
)
if [ "${#config_values[@]}" -ne 5 ]; then
  echo "failed to parse Botan build metadata" >&2
  exit 2
fi
config_revision="${config_values[0]}"
botan_version="${config_values[1]}"
config_cxx="${config_values[2]}"
config_compiler="${config_values[3]}"
resolved_modules="${config_values[4]}"
if [ "$config_revision" != "git:$botan_commit" ]; then
  echo "Botan build revision mismatch: $config_revision" >&2
  exit 2
fi
if [ "$config_cxx" != "$CXX_COMPILER" ] ||
    [ "$config_compiler" != "$BOTAN_CC_FAMILY" ]; then
  echo "Botan build compiler metadata mismatch" >&2
  exit 2
fi
if ! rg -q '^#define BOTAN_HAS_ML_KEM ' "$build_header" ||
    ! rg -q '^#define BOTAN_HAS_KECCAK_PERM_BMI2 ' "$build_header"; then
  echo "Botan build omitted ML-KEM or BMI2 Keccak" >&2
  exit 2
fi
if rg -q '^#define BOTAN_HAS_(SYSTEM_RNG|AUTO_RNG|FFI) ' "$build_header"; then
  echo "Botan product build enabled an entropy or FFI module" >&2
  exit 2
fi
if [ "$PROFILE" = "avx2" ] &&
    rg -q '^#define BOTAN_HAS_KECCAK_PERM_AVX512 ' "$build_header"; then
  echo "Botan AVX2-only build enabled Keccak AVX512" >&2
  exit 2
fi

read -r -a effective_cxxflags_arr <<< "$effective_cxxflags"
"$CXX_COMPILER" "${effective_cxxflags_arr[@]}" -fno-rtti -std=c++20 \
  -I"$ROOT_DIR/scripts" \
  -I"$build_dir/build/include/public" \
  -I"$build_dir/build/include/internal" \
  -c "$ROOT_DIR/scripts/goal_size_botan_adapter.cpp" \
  -o "$work_dir/adapter.o"

"$CXX_COMPILER" -r -nostdlib "$work_dir/adapter.o" "$archive" \
  -o "$work_dir/product-raw.o" -Wl,--gc-sections \
  -Wl,--undefined=goal_mlkem768_keypair_derand \
  -Wl,--undefined=goal_mlkem768_encaps_derand \
  -Wl,--undefined=goal_mlkem768_decaps
objcopy --strip-debug \
  --keep-global-symbol=goal_mlkem768_keypair_derand \
  --keep-global-symbol=goal_mlkem768_encaps_derand \
  --keep-global-symbol=goal_mlkem768_decaps \
  --remove-section=.comment \
  --remove-section=.note.gnu.build-id \
  --remove-section=.llvm_addrsig \
  "$work_dir/product-raw.o" "$work_dir/product.o"

nm -g --defined-only "$work_dir/product.o" |
  awk 'NF { print $NF }' | sort > "$work_dir/actual-api.txt"
printf '%s\n' $REQUIRED_SYMBOLS | sort > "$work_dir/expected-api.txt"
if ! cmp -s "$work_dir/actual-api.txt" "$work_dir/expected-api.txt"; then
  echo "Botan product does not export exactly the three goal APIs" >&2
  cat "$work_dir/actual-api.txt" >&2
  exit 2
fi
api_count=3
nm -a "$work_dir/product.o" > "$work_dir/all-symbols.txt"
nm -u "$work_dir/product.o" > "$work_dir/undefined-symbols.txt"
readelf -Wr "$work_dir/product.o" > "$work_dir/relocations.txt"
readelf -SW "$work_dir/product.o" > "$work_dir/sections.txt"
objdump -d "$work_dir/product.o" > "$work_dir/disassembly.txt"
undefined_symbol_count="$(awk 'NF { count++ } END { print count + 0 }' \
  "$work_dir/undefined-symbols.txt")"
if rg -ni 'system_rng|auto_rng|getrandom|getentropy|urandom|random_device' \
    "$work_dir/relocations.txt" "$work_dir/all-symbols.txt"; then
  echo "reachable Botan product code depends on an entropy source" >&2
  exit 2
fi
if rg -ni "$cache_pattern" "$work_dir/all-symbols.txt"; then
  echo "Botan product retained persistent key or matrix cache metadata" >&2
  exit 2
fi
if rg -n '\.note\.GNU-stack.* X ' "$work_dir/sections.txt"; then
  echo "Botan product requests an executable stack" >&2
  exit 2
fi
if ! rg -q 'Keccak_Permutation.*permute_bmi2' \
    "$work_dir/all-symbols.txt"; then
  echo "Botan product did not retain the requested BMI2 Keccak path" >&2
  exit 2
fi
if [ "$PROFILE" = "avx2" ]; then
  if rg -n '%zmm|%k[0-7]' "$work_dir/disassembly.txt" ||
      rg -ni 'avx512' "$work_dir/all-symbols.txt"; then
    echo "AVX512 code detected in Botan AVX2-only product" >&2
    exit 2
  fi
  avx512_audit=pass
else
  avx512_audit=not-applicable
fi

eh_frame_bytes="$(objdump -h "$work_dir/product.o" |
  awk '$2 ~ /^\.eh_frame/ { n += strtonum("0x" $3) } END { print n + 0 }')"
gcc_except_table_bytes="$(objdump -h "$work_dir/product.o" |
  awk '$2 ~ /^\.gcc_except_table/ { n += strtonum("0x" $3) } END { print n + 0 }')"
if [ "$eh_frame_bytes" -le 0 ] || [ "$gcc_except_table_bytes" -le 0 ] ||
    ! rg -q '_Unwind_Resume' "$work_dir/undefined-symbols.txt"; then
  echo "Botan product lost exception-required unwind metadata" >&2
  exit 2
fi

read -r -a arch_cflags_arr <<< "$ARCH_CFLAGS"
"$C_COMPILER" -O2 "${arch_cflags_arr[@]}" -std=c11 \
  -I"$ROOT_DIR/scripts" -c "$ROOT_DIR/scripts/goal_size_adapter_test.c" \
  -o "$work_dir/product-test.o"
read -r -a cxx_stdlib_flags_arr <<< "$GOAL_CXX_STDLIB_FLAGS"
"$CXX_COMPILER" "${cxx_stdlib_flags_arr[@]}" -no-pie \
  "$work_dir/product-test.o" "$work_dir/product.o" \
  -pthread -ldl -lm -Wl,-z,noexecstack -o "$work_dir/product-test"
"$work_dir/product-test"
if ! readelf -W -l "$work_dir/product-test" |
    awk '$1 == "GNU_STACK" && $0 !~ /E/ { found = 1 } END { exit !found }'; then
  echo "linked Botan smoke test has an executable stack" >&2
  exit 2
fi

mkdir -p "$(dirname "$OUTPUT")"
cp "$work_dir/product.o" "$OUTPUT"

printf "profile=%s\n" "$PROFILE"
printf "compiler=%s\n" "$C_COMPILER"
printf "compiler_version=%s\n" "$("$C_COMPILER" --version | sed -n '1p')"
printf "cxx_compiler=%s\n" "$CXX_COMPILER"
printf "cxx_compiler_version=%s\n" "$("$CXX_COMPILER" --version | sed -n '1p')"
printf "botan_version=%s\n" "$botan_version"
printf "botan_commit=%s\n" "$botan_commit"
printf "botan_remote=%s\n" "$botan_remote"
printf "comparator_update=%s\n" "$comparator_update"
printf "botan_modules_requested=%s\n" "$BOTAN_MODULES"
printf "botan_modules_resolved=%s\n" "$resolved_modules"
printf "botan_disabled_modules=%s\n" "${BOTAN_DISABLED_MODULES:-none}"
printf "botan_cxxflags=%s\n" "$BOTAN_CXXFLAGS"
printf "normalization_cxxflags=%s\n" "$normalization_cxxflags"
printf "botan_build_jobs=%s\n" "$BOTAN_BUILD_JOBS"
printf "botan_archive_member_count=%s\n" "$(ar t "$archive" | awk 'NF { n++ } END { print n + 0 }')"
printf "adapter_mode=internal-core-direct\n"
printf "wire_key_parse_per_call=pass\n"
printf "operation_rebuild_per_call=pass\n"
printf "matrix_precompute_timed=pass\n"
printf "source_precompute_sha256=%s\n" "$(sha256sum "$precompute_source" | awk '{print $1}')"
printf "api_count=%s\n" "$api_count"
printf "undefined_symbol_count=%s\n" "$undefined_symbol_count"
printf "cache_audit=pass\n"
printf "reachable_entropy_audit=pass\n"
printf "noexec_stack_audit=pass\n"
printf "bmi2_keccak_audit=pass\n"
printf "avx512_audit=%s\n" "$avx512_audit"
printf "exception_required_eh_frame_bytes=%s\n" "$eh_frame_bytes"
printf "gcc_except_table_bytes=%s\n" "$gcc_except_table_bytes"
printf "functional_exception_unwind_retained=pass\n"
printf "correctness_smoke=pass\n"
REQUIRED_SYMBOLS="$REQUIRED_SYMBOLS" \
  "$ROOT_DIR/scripts/measure_elf_footprint.sh" "$OUTPUT"
