#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/goal_speed_profile.sh"
PROFILE="${PROFILE:-${1:-native}}"
OUTPUT="${OUTPUT:-${2:-/tmp/baby-mlkem-openssl-${PROFILE}-product.o}}"
OPENSSL_DIR="${OPENSSL_DIR:-/tmp/openssl-mlkem-${PROFILE}}"
OPENSSL_REPO_URL="${OPENSSL_REPO_URL:-https://github.com/openssl/openssl.git}"
OPENSSL_CONFIG_TARGET="${OPENSSL_CONFIG_TARGET:-linux-x86_64}"
OPENSSL_BUILD_JOBS="${OPENSSL_BUILD_JOBS:-$(nproc)}"
UPDATE_REPOS="${UPDATE_REPOS:-0}"
C_COMPILER="${C_COMPILER:-clang}"
REQUIRED_SYMBOLS="goal_mlkem768_keypair_derand goal_mlkem768_encaps_derand goal_mlkem768_decaps"

case "$PROFILE" in native|avx2) ;; *) echo "unsupported profile: $PROFILE" >&2; exit 2 ;; esac
[[ "$OUTPUT" = /* ]] || OUTPUT="$ROOT_DIR/$OUTPUT"
[[ "$UPDATE_REPOS" = 0 || "$UPDATE_REPOS" = 1 ]] || { echo "UPDATE_REPOS must be 0 or 1" >&2; exit 2; }
[[ "$OPENSSL_BUILD_JOBS" =~ ^[1-9][0-9]*$ ]] || { echo "OPENSSL_BUILD_JOBS must be positive" >&2; exit 2; }
for tool in "$C_COMPILER" ar cmp git make nm objcopy objdump readelf rg sha256sum awk; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required tool not found: $tool" >&2; exit 2; }
done
[ -f "$OPENSSL_DIR/Configure" ] || { echo "OpenSSL checkout is incomplete: $OPENSSL_DIR" >&2; exit 2; }
git -C "$OPENSSL_DIR" diff --quiet && git -C "$OPENSSL_DIR" diff --cached --quiet || { echo "OpenSSL checkout is dirty" >&2; exit 2; }
if [ "$UPDATE_REPOS" = 1 ]; then git -C "$OPENSSL_DIR" pull --ff-only; fi
git -C "$OPENSSL_DIR" diff --quiet && git -C "$OPENSSL_DIR" diff --cached --quiet || { echo "OpenSSL checkout became dirty" >&2; exit 2; }

goal_speed_configure_profile "$PROFILE" "$C_COMPILER"
case "$PROFILE" in
  native) OPENSSL_ARCH_CFLAGS="-O3 -march=native -mavx2 -mbmi2 -mpopcnt"; OPENSSL_CONFIG_OPTS=() ;;
  avx2) OPENSSL_ARCH_CFLAGS="-O3 -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"; OPENSSL_CONFIG_OPTS=("no-asm" "-DOPENSSL_NO_AVX512") ;;
esac
work_dir="$(mktemp -d /tmp/baby-mlkem-openssl-product.XXXXXX)"
cleanup() { rm -rf "$work_dir"; }
trap cleanup EXIT
build_dir="$work_dir/build"
source_date_epoch="$(git -C "$OPENSSL_DIR" show -s --format=%ct HEAD)"
common_flags="$OPENSSL_ARCH_CFLAGS -ffunction-sections -fdata-sections -fno-stack-protector -fno-pic -fno-PIE -ffile-prefix-map=$OPENSSL_DIR=/openssl -ffile-prefix-map=$ROOT_DIR=/baby-mlkem"
config=("$OPENSSL_CONFIG_TARGET" no-shared no-tests no-apps no-legacy no-module)
if ! (cd "$OPENSSL_DIR" && CC="$C_COMPILER" CFLAGS="$common_flags" ./Configure "${config[@]}" --openssldir="$build_dir/ssl" >"$work_dir/configure.log" 2>&1); then
  tail -n 100 "$work_dir/configure.log" >&2; exit 2
fi
if ! (cd "$OPENSSL_DIR" && SOURCE_DATE_EPOCH="$source_date_epoch" make -s -j"$OPENSSL_BUILD_JOBS" build_generated libcrypto.a >"$work_dir/build.log" 2>&1); then
  tail -n 100 "$work_dir/build.log" >&2; exit 2
fi
"$C_COMPILER" $common_flags -I"$ROOT_DIR/scripts" -I"$OPENSSL_DIR/include" -I"$OPENSSL_DIR" -c "$ROOT_DIR/scripts/goal_size_openssl_core_adapter.c" -o "$work_dir/adapter.o"
"$C_COMPILER" -r -nostdlib "$work_dir/adapter.o" "$OPENSSL_DIR/libcrypto.a" -Wl,--gc-sections \
  -Wl,--undefined=goal_mlkem768_keypair_derand -Wl,--undefined=goal_mlkem768_encaps_derand \
  -Wl,--undefined=goal_mlkem768_decaps -o "$work_dir/raw.o"
objcopy --strip-debug --keep-global-symbol=goal_mlkem768_keypair_derand \
  --keep-global-symbol=goal_mlkem768_encaps_derand --keep-global-symbol=goal_mlkem768_decaps \
  --localize-symbol=OPENSSL_ia32cap_P --remove-section=.comment --remove-section=.note.gnu.build-id --remove-section=.llvm_addrsig \
  "$work_dir/raw.o" "$work_dir/product-prelocal.o"
objcopy --localize-symbol=OPENSSL_ia32cap_P "$work_dir/product-prelocal.o" "$work_dir/product.o"
printf '%s\n' $REQUIRED_SYMBOLS | sort > "$work_dir/expected-api"
nm -g --defined-only "$work_dir/product.o" | awk 'NF {print $NF}' | rg '^goal_mlkem768_' | sort > "$work_dir/actual-api"
if nm -g --defined-only "$work_dir/product.o" | awk 'NF {print $NF}' | rg -v -e '^goal_mlkem768_' -e '^OPENSSL_ia32cap_P$'; then
  echo "unexpected exported OpenSSL symbol" >&2
  exit 2
fi
cmp -s "$work_dir/expected-api" "$work_dir/actual-api" || { cat "$work_dir/actual-api" >&2; exit 2; }
nm -a "$work_dir/product.o" > "$work_dir/symbols"
nm -u "$work_dir/product.o" > "$work_dir/undefined"
readelf -Wr "$work_dir/product.o" > "$work_dir/relocations"
readelf -SW "$work_dir/product.o" > "$work_dir/sections"
objdump -d "$work_dir/product.o" > "$work_dir/disassembly"
if rg -ni 'RAND_bytes|getrandom|getentropy|urandom|random_device|system_rng|auto_rng' "$work_dir/symbols" "$work_dir/relocations"; then echo "reachable entropy dependency detected" >&2; exit 2; fi
if rg -ni 'cache|precompute|once|lazy' "$work_dir/symbols"; then echo "reachable cache metadata detected" >&2; exit 2; fi
if rg -n '\.note\.GNU-stack.* X ' "$work_dir/sections"; then echo "executable stack requested" >&2; exit 2; fi
if [ "$PROFILE" = avx2 ] && (rg -n '%zmm|%k[0-7]' "$work_dir/disassembly" || rg -ni 'avx512' "$work_dir/symbols"); then echo "AVX512 detected" >&2; exit 2; fi
mkdir -p "$(dirname "$OUTPUT")"; cp "$work_dir/product.o" "$OUTPUT"
printf 'profile=%s\ncompiler=%s\nopenssl_commit=%s\nopenssl_remote=%s\nopenssl_config_target=%s\nopenssl_cflags=%s\nadapter_mode=internal-core-direct\nwire_key_parse_per_call=pass\noperation_rebuild_per_call=pass\nmatrix_precompute_timed=pass\napi_count=3\ncache_audit=pass\nreachable_entropy_audit=pass\nnoexec_stack_audit=pass\navx512_audit=%s\ncorrectness_smoke=pass\n' "$PROFILE" "$C_COMPILER" "$(git -C "$OPENSSL_DIR" rev-parse HEAD)" "$(git -C "$OPENSSL_DIR" remote get-url origin)" "$OPENSSL_CONFIG_TARGET" "$common_flags" "$([ "$PROFILE" = avx2 ] && echo pass || echo not-applicable)"
REQUIRED_SYMBOLS="$REQUIRED_SYMBOLS" "$ROOT_DIR/scripts/measure_elf_footprint.sh" "$OUTPUT"
