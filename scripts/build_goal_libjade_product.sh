#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/goal_speed_profile.sh"
PROFILE="${PROFILE:-${1:-native}}"
OUTPUT="${OUTPUT:-${2:-/tmp/baby-mlkem-libjade-${PROFILE}-product.o}}"
LIBJADE_RELEASE_TAG="${LIBJADE_RELEASE_TAG:-release/2023.05-2}"
LIBJADE_DIST_URL="${LIBJADE_DIST_URL:-https://github.com/formosa-crypto/libjade/releases/download/release/2023.05-2/libjade-dist-src-amd64.tar.gz}"
LIBJADE_LATEST_API="${LIBJADE_LATEST_API:-https://api.github.com/repos/formosa-crypto/libjade/releases/latest}"
LIBJADE_DIST_ROOT="${LIBJADE_DIST_ROOT:-/tmp/libjade-dist-src-amd64}"
LIBJADE_KEM_DIR="${LIBJADE_KEM_DIR:-$LIBJADE_DIST_ROOT/libjade/crypto_kem/kyber_kyber768_avx2}"
LIBJADE_EXPECTED_ASSEMBLY_SHA256="${LIBJADE_EXPECTED_ASSEMBLY_SHA256:-358736656400f28f75db858c1be703a3140c8f6fac17b99279abc857112cf5d1}"
LIBJADE_EXPECTED_HEADER_SHA256="${LIBJADE_EXPECTED_HEADER_SHA256:-e4ee2af96ac4c4f3184764c4e8565eb52d58670d4b58ef98b9635415162f9ca7}"
LIBJADE_EXPECTED_JAZZ_SHA256="${LIBJADE_EXPECTED_JAZZ_SHA256:-ef7b8c32a0ef5d52150decbeea34161b986c3c580122c459c69fa28265a84f5f}"
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
if [ "$(uname -m)" != "x86_64" ]; then
  echo "normalized libjade AVX2 product currently requires x86_64" >&2
  exit 2
fi
for tool in "$C_COMPILER" awk cmp curl ld nm objcopy objdump readelf rg \
    sha256sum sort tar; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool" >&2
    exit 2
  fi
done

libjade_cflags_override="${LIBJADE_HARNESS_CFLAGS:-}"
goal_speed_configure_profile "$PROFILE" "$C_COMPILER"
if [ -n "$libjade_cflags_override" ]; then
  LIBJADE_HARNESS_CFLAGS="$libjade_cflags_override"
fi

validate_native_flags() {
  local flags="$1"
  local token
  local -a flag_array

  read -r -a flag_array <<< "$flags"
  if [[ " $flags " != *" -march=native "* ]]; then
    echo "native libjade flags are missing -march=native" >&2
    return 2
  fi
  for token in "${flag_array[@]}"; do
    if [[ "$token" == -march=* ]] && [ "$token" != "-march=native" ]; then
      echo "native libjade flags contain conflicting architecture flag: $token" >&2
      return 2
    fi
  done
}

validate_avx2_flags() {
  local flags="$1"
  local token
  local -a flag_array

  read -r -a flag_array <<< "$flags"
  for token in -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f; do
    if [[ " $flags " != *" $token "* ]]; then
      echo "AVX2-only libjade flags are missing $token" >&2
      return 2
    fi
  done
  if [[ " $flags " == *" -march=native "* ]]; then
    echo "AVX2-only libjade flags contain forbidden -march=native" >&2
    return 2
  fi
  for token in "${flag_array[@]}"; do
    if [[ "$token" == -mavx512* ]]; then
      echo "AVX2-only libjade flags explicitly enable AVX512: $token" >&2
      return 2
    fi
  done
}

case "$PROFILE" in
  native) validate_native_flags "$LIBJADE_HARNESS_CFLAGS" ;;
  avx2) validate_avx2_flags "$LIBJADE_HARNESS_CFLAGS" ;;
esac

work_dir="$(mktemp -d /tmp/baby-mlkem-libjade-product.XXXXXX)"
cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT

latest_release_tag=unchecked
latest_release_audit=skipped
archive_sha256=not-downloaded
source_origin=local-pinned-release
source_kem_dir="$LIBJADE_KEM_DIR"

download_release() {
  local archive="$work_dir/libjade-dist.tar.gz"
  local archive_list="$work_dir/archive-list.txt"
  local extract_dir="$work_dir/release"
  local archive_root

  curl -fsSL "$LIBJADE_DIST_URL" -o "$archive"
  archive_sha256="$(sha256sum "$archive" | awk '{print $1}')"
  tar -tzf "$archive" > "$archive_list"
  if ! awk -F/ '
    BEGIN { root = ""; files = 0 }
    /^\// { exit 1 }
    {
      for (i = 1; i <= NF; i++) if ($i == "..") exit 1
      if ($1 != "" && root == "") root = $1
      if ($1 != "" && $1 != root) exit 1
      files++
    }
    END { if (root == "" || files == 0) exit 1 }
  ' "$archive_list"; then
    echo "unsafe or malformed libjade release archive" >&2
    exit 2
  fi
  archive_root="$(awk -F/ '$1 != "" { print $1; exit }' "$archive_list")"
  mkdir -p "$extract_dir"
  tar -xzf "$archive" -C "$extract_dir"
  source_kem_dir="$extract_dir/$archive_root/libjade/crypto_kem/kyber_kyber768_avx2"
  source_origin=official-release-download
}

if [ "$UPDATE_REPOS" = "1" ]; then
  latest_json="$work_dir/latest-release.json"
  curl -fsSL "$LIBJADE_LATEST_API" -o "$latest_json"
  latest_release_tag="$(sed -n \
    's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
    "$latest_json")"
  if [ -z "$latest_release_tag" ] ||
      [ "$latest_release_tag" != "$LIBJADE_RELEASE_TAG" ]; then
    echo "configured libjade release is not GitHub Latest: configured=$LIBJADE_RELEASE_TAG latest=${latest_release_tag:-unknown}" >&2
    exit 2
  fi
  latest_release_audit=pass
  comparator_update=pass
  download_release
elif [ ! -f "$source_kem_dir/kyber_kyber768_avx2.s" ] ||
    [ ! -f "$source_kem_dir/kyber_kyber768_avx2.h" ] ||
    [ ! -f "$source_kem_dir/kyber_kyber768_avx2.jazz" ]; then
  comparator_update=downloaded-pinned
  download_release
else
  comparator_update=skipped
fi

assembly="$source_kem_dir/kyber_kyber768_avx2.s"
header="$source_kem_dir/kyber_kyber768_avx2.h"
jazz="$source_kem_dir/kyber_kyber768_avx2.jazz"
for source_file in "$assembly" "$header" "$jazz"; do
  if [ ! -f "$source_file" ]; then
    echo "libjade release source not found: $source_file" >&2
    exit 2
  fi
done

verify_sha256() {
  local file="$1"
  local expected="$2"
  local label="$3"
  local actual

  if ! [[ "$expected" =~ ^[0-9a-f]{64}$ ]]; then
    echo "invalid expected $label SHA-256: $expected" >&2
    exit 2
  fi
  actual="$(sha256sum "$file" | awk '{print $1}')"
  if [ "$actual" != "$expected" ]; then
    echo "$label SHA-256 mismatch: expected=$expected actual=$actual" >&2
    exit 2
  fi
}

verify_sha256 "$assembly" "$LIBJADE_EXPECTED_ASSEMBLY_SHA256" assembly
verify_sha256 "$header" "$LIBJADE_EXPECTED_HEADER_SHA256" header
verify_sha256 "$jazz" "$LIBJADE_EXPECTED_JAZZ_SHA256" jazz

expect_marker_once() {
  local marker="$1"
  local count

  count="$(awk -v target="$marker" '$0 == target { count++ } END { print count + 0 }' \
    "$assembly")"
  if [ "$count" -ne 1 ]; then
    echo "expected one libjade assembly marker, found $count: $marker" >&2
    exit 2
  fi
}

expect_marker_once $'\t.text'
expect_marker_once '_jade_kem_kyber_kyber768_amd64_avx2_enc:'
expect_marker_once '_jade_kem_kyber_kyber768_amd64_avx2_enc_derand:'
expect_marker_once '_jade_kem_kyber_kyber768_amd64_avx2_keypair:'
expect_marker_once '_jade_kem_kyber_kyber768_amd64_avx2_keypair_derand:'
expect_marker_once 'L__crypto_kem_enc_derand_jazz$1:'
random_call_count="$(awk '
  $1 == "call" && $2 == "__jasmin_syscall_randombytes__" { count++ }
  END { print count + 0 }
' "$assembly")"
if [ "$random_call_count" -ne 2 ]; then
  echo "expected exactly two libjade random-wrapper calls, found $random_call_count" >&2
  exit 2
fi

split_assembly="$work_dir/kyber_kyber768_avx2.split.s"
awk '
  /^[[:space:]]*\.text[[:space:]]*$/ {
    print "\t.section\t.text.libjade_dec,\"ax\",@progbits"
    next
  }
  $0 == "_jade_kem_kyber_kyber768_amd64_avx2_enc:" {
    print "\t.section\t.text.libjade_enc_random,\"ax\",@progbits"
  }
  $0 == "_jade_kem_kyber_kyber768_amd64_avx2_enc_derand:" {
    print "\t.section\t.text.libjade_enc_derand,\"ax\",@progbits"
  }
  $0 == "_jade_kem_kyber_kyber768_amd64_avx2_keypair:" {
    print "\t.section\t.text.libjade_keypair_random,\"ax\",@progbits"
  }
  $0 == "_jade_kem_kyber_kyber768_amd64_avx2_keypair_derand:" {
    print "\t.section\t.text.libjade_keypair_derand,\"ax\",@progbits"
  }
  $0 == "L__crypto_kem_enc_derand_jazz$1:" {
    print "\t.section\t.text.libjade_core,\"ax\",@progbits"
  }
  { print }
  END { print "\t.section\t.note.GNU-stack,\"\",@progbits" }
' "$assembly" > "$split_assembly"

awk '!/^[[:space:]]*\.text[[:space:]]*$/' "$assembly" \
  > "$work_dir/original-nonsection.txt"
awk '
  !/^[[:space:]]*\.section[[:space:]]+\.text\.libjade_/ &&
  !/^[[:space:]]*\.section[[:space:]]+\.note\.GNU-stack/
' "$split_assembly" > "$work_dir/split-nonsection.txt"
if ! cmp -s "$work_dir/original-nonsection.txt" \
    "$work_dir/split-nonsection.txt"; then
  echo "libjade section normalization changed non-section assembly lines" >&2
  exit 2
fi

read -r -a libjade_cflags_arr <<< "$LIBJADE_HARNESS_CFLAGS"
normalization_cflags="-ffunction-sections -fdata-sections -fno-stack-protector"
normalization_cflags+=" -fno-unwind-tables -fno-asynchronous-unwind-tables"
normalization_cflags+=" -Wa,--noexecstack"
read -r -a normalization_cflags_arr <<< "$normalization_cflags"

"$C_COMPILER" -c "$split_assembly" -o "$work_dir/libjade.o"
"$C_COMPILER" "${libjade_cflags_arr[@]}" \
  "${normalization_cflags_arr[@]}" -std=c11 \
  -I"$ROOT_DIR/scripts" -I"$source_kem_dir" \
  -c "$ROOT_DIR/scripts/goal_size_libjade_adapter.c" \
  -o "$work_dir/adapter.o"

"$C_COMPILER" -r -nostdlib "$work_dir/adapter.o" "$work_dir/libjade.o" \
  -o "$work_dir/product-raw.o" \
  -Wl,--gc-sections \
  -Wl,--undefined=goal_mlkem768_keypair_derand \
  -Wl,--undefined=goal_mlkem768_encaps_derand \
  -Wl,--undefined=goal_mlkem768_decaps

if readelf -SW "$work_dir/product-raw.o" |
    rg -n '\.text\.libjade_(enc|keypair)_random'; then
  echo "libjade product retained a randomized wrapper section" >&2
  exit 2
fi
if readelf -Wr "$work_dir/product-raw.o" |
    rg -ni '__jasmin_syscall_randombytes__|getrandom|getentropy|urandom'; then
  echo "reachable libjade product code depends on an entropy source" >&2
  exit 2
fi

objcopy --strip-debug \
  --strip-symbol=__jasmin_syscall_randombytes__ \
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
  echo "libjade product does not export exactly the three goal APIs" >&2
  cat "$work_dir/actual-api.txt" >&2
  exit 2
fi
api_count=3
undefined_symbol_count="$(nm -u "$work_dir/product.o" |
  awk 'NF { count++ } END { print count + 0 }')"
if [ "$undefined_symbol_count" -ne 0 ]; then
  nm -u "$work_dir/product.o" >&2
  echo "libjade product retained undefined symbols" >&2
  exit 2
fi
if nm -a "$work_dir/product.o" |
    rg -ni '__jasmin_syscall_randombytes__|jade_kem_kyber_kyber768_amd64_avx2_(enc|keypair)$'; then
  echo "libjade product retained a randomized API or entropy symbol" >&2
  exit 2
fi
if nm -a "$work_dir/product.o" |
    rg -ni '(public_key|matrix|hash|secret_key)[[:alnum:]_]*cache|once_cell|lazy_static'; then
  echo "libjade product retained persistent cache metadata" >&2
  exit 2
fi
if readelf -SW "$work_dir/product.o" |
    rg -n '\.note\.GNU-stack.* X '; then
  echo "libjade product requests an executable stack" >&2
  exit 2
fi

objdump -d "$work_dir/product.o" > "$work_dir/disassembly.txt"
if rg -n '%zmm|%k[0-7]' "$work_dir/disassembly.txt" >/dev/null; then
  echo "AVX512 code detected in fixed-AVX2 libjade product" >&2
  exit 2
fi
if ! rg -n '%ymm' "$work_dir/disassembly.txt" >/dev/null; then
  echo "AVX2 evidence missing from libjade AVX2 product" >&2
  exit 2
fi

"$C_COMPILER" -O2 -std=c11 -I"$ROOT_DIR/scripts" \
  "$ROOT_DIR/scripts/goal_size_adapter_test.c" "$work_dir/product.o" \
  -Wl,-z,noexecstack -o "$work_dir/product_test"
"$work_dir/product_test"
if ! readelf -W -l "$work_dir/product_test" |
    awk '$1 == "GNU_STACK" && $0 !~ /E/ { found = 1 } END { exit !found }'; then
  echo "linked libjade smoke test has an executable stack" >&2
  exit 2
fi

mkdir -p "$(dirname "$OUTPUT")"
cp "$work_dir/product.o" "$OUTPUT"

printf "profile=%s\n" "$PROFILE"
printf "compiler=%s\n" "$C_COMPILER"
printf "compiler_version=%s\n" "$("$C_COMPILER" --version | sed -n '1p')"
printf "libjade_semantics=Kyber768-pre-FIPS\n"
printf "libjade_fixed_isa=avx2-bmi2-popcnt\n"
printf "libjade_release_tag=%s\n" "$LIBJADE_RELEASE_TAG"
printf "libjade_dist_url=%s\n" "$LIBJADE_DIST_URL"
printf "libjade_source_origin=%s\n" "$source_origin"
printf "libjade_assembly_sha256=%s\n" "$LIBJADE_EXPECTED_ASSEMBLY_SHA256"
printf "libjade_header_sha256=%s\n" "$LIBJADE_EXPECTED_HEADER_SHA256"
printf "libjade_jazz_sha256=%s\n" "$LIBJADE_EXPECTED_JAZZ_SHA256"
printf "libjade_archive_sha256=%s\n" "$archive_sha256"
printf "comparator_update=%s\n" "$comparator_update"
printf "latest_release_tag=%s\n" "$latest_release_tag"
printf "latest_release_audit=%s\n" "$latest_release_audit"
printf "libjade_adapter_cflags=%s\n" "$LIBJADE_HARNESS_CFLAGS"
printf "normalization_cflags=%s\n" "$normalization_cflags"
printf "assembly_random_call_count=%s\n" "$random_call_count"
printf "assembly_nonsection_identity_audit=pass\n"
printf "random_wrapper_gc_audit=pass\n"
printf "api_count=%s\n" "$api_count"
printf "undefined_symbol_count=%s\n" "$undefined_symbol_count"
printf "cache_audit=pass\n"
printf "reachable_entropy_audit=pass\n"
printf "noexec_stack_audit=pass\n"
printf "avx2_evidence_audit=pass\n"
printf "avx512_audit=pass\n"
printf "correctness_smoke=pass\n"
REQUIRED_SYMBOLS="$REQUIRED_SYMBOLS" \
  "$ROOT_DIR/scripts/measure_elf_footprint.sh" "$OUTPUT"
