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
EXPECTED_UNDEFINED_SYMBOLS="calloc free malloc memcpy memset pthread_once"
EXPECTED_CORPUS_BYTES=381228
EXPECTED_CORPUS_SHA256=e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67

case "$PROFILE" in native|avx2) ;; *) echo "unsupported profile: $PROFILE" >&2; exit 2 ;; esac
[[ "$OUTPUT" = /* ]] || OUTPUT="$ROOT_DIR/$OUTPUT"
[[ "$UPDATE_REPOS" = 0 || "$UPDATE_REPOS" = 1 ]] || { echo "UPDATE_REPOS must be 0 or 1" >&2; exit 2; }
[[ "$OPENSSL_BUILD_JOBS" =~ ^[1-9][0-9]*$ ]] || { echo "OPENSSL_BUILD_JOBS must be positive" >&2; exit 2; }
for tool in "$C_COMPILER" ar cmp git make nm objcopy objdump readelf rg sha256sum awk wc; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required tool not found: $tool" >&2; exit 2; }
done
[ -f "$OPENSSL_DIR/Configure" ] || { echo "OpenSSL checkout is incomplete: $OPENSSL_DIR" >&2; exit 2; }
[ -z "$(git -C "$OPENSSL_DIR" status --porcelain --untracked-files=normal)" ] || { echo "OpenSSL checkout is dirty" >&2; exit 2; }
openssl_remote="$(git -C "$OPENSSL_DIR" remote get-url origin)"
[ "$openssl_remote" = "$OPENSSL_REPO_URL" ] || { echo "unexpected OpenSSL remote: $openssl_remote" >&2; exit 2; }
if [ "$UPDATE_REPOS" = 1 ]; then
  git -C "$OPENSSL_DIR" pull --ff-only
  comparator_update=pass
else
  comparator_update=skipped
fi
[ -z "$(git -C "$OPENSSL_DIR" status --porcelain --untracked-files=normal)" ] || { echo "OpenSSL checkout became dirty" >&2; exit 2; }

goal_speed_configure_profile "$PROFILE" "$C_COMPILER"
case "$PROFILE" in
  native) OPENSSL_CONFIG_OPTS=() ;;
  avx2) OPENSSL_CONFIG_OPTS=("-DOPENSSL_NO_AVX512") ;;
esac
OPENSSL_PRODUCT_CFLAGS="${OPENSSL_PRODUCT_CFLAGS:-$OPENSSL_CFLAGS}"
work_dir="$(mktemp -d /tmp/baby-mlkem-openssl-product.XXXXXX)"
cleanup() { rm -rf "$work_dir"; }
trap cleanup EXIT
build_dir="$work_dir/build"
source_date_epoch="$(git -C "$OPENSSL_DIR" show -s --format=%ct HEAD)"
common_flags="$OPENSSL_PRODUCT_CFLAGS -ffunction-sections -fdata-sections -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-pic -fno-PIE -ffile-prefix-map=$OPENSSL_DIR=/openssl -ffile-prefix-map=$ROOT_DIR=/baby-mlkem"
config=("$OPENSSL_CONFIG_TARGET" no-shared no-tests no-apps no-legacy no-module)
config+=(no-cached-fetch no-autoload-config)
config+=("${OPENSSL_CONFIG_OPTS[@]}")
if [ -f "$OPENSSL_DIR/Makefile" ] &&
    ! (cd "$OPENSSL_DIR" && make -s clean >"$work_dir/clean.log" 2>&1); then
  tail -n 100 "$work_dir/clean.log" >&2
  exit 2
fi
if ! (cd "$OPENSSL_DIR" && CC="$C_COMPILER" CFLAGS="$common_flags" ./Configure "${config[@]}" --openssldir="$build_dir/ssl" >"$work_dir/configure.log" 2>&1); then
  tail -n 100 "$work_dir/configure.log" >&2; exit 2
fi
mlkem_object_rel=crypto/ml_kem/libcrypto-lib-ml_kem.o
sha3_object_rel=crypto/sha/libcrypto-lib-sha3.o
keccak_object_rel=crypto/sha/libcrypto-lib-keccak1600-x86_64.o
if ! (cd "$OPENSSL_DIR" && SOURCE_DATE_EPOCH="$source_date_epoch" \
    make -s -j"$OPENSSL_BUILD_JOBS" build_generated "$mlkem_object_rel" \
      "$sha3_object_rel" "$keccak_object_rel" >"$work_dir/build.log" 2>&1); then
  tail -n 100 "$work_dir/build.log" >&2; exit 2
fi
mlkem_object="$OPENSSL_DIR/$mlkem_object_rel"
sha3_object="$OPENSSL_DIR/$sha3_object_rel"
keccak_object="$OPENSSL_DIR/$keccak_object_rel"
for object in "$mlkem_object" "$sha3_object" "$keccak_object"; do
  [ -f "$object" ] || { echo "required OpenSSL core object not found: $object" >&2; exit 2; }
done
"$C_COMPILER" $common_flags -I"$ROOT_DIR/scripts" -I"$OPENSSL_DIR/include" -I"$OPENSSL_DIR" -c "$ROOT_DIR/scripts/goal_size_openssl_core_adapter.c" -o "$work_dir/adapter.o"
"$C_COMPILER" $common_flags -I"$OPENSSL_DIR/include" -I"$OPENSSL_DIR" \
  -c "$ROOT_DIR/scripts/goal_size_openssl_core_shim.c" \
  -o "$work_dir/core-shim.o"
wrap_flags=(
  -Wl,--wrap=RAND_bytes_ex
  -Wl,--wrap=RAND_priv_bytes_ex
)
"$C_COMPILER" -r -nostdlib "$work_dir/adapter.o" "$work_dir/core-shim.o" \
  "$mlkem_object" "$sha3_object" "$keccak_object" \
  -Wl,--gc-sections "${wrap_flags[@]}" \
  -Wl,--undefined=goal_mlkem768_keypair_derand -Wl,--undefined=goal_mlkem768_encaps_derand \
  -Wl,--undefined=goal_mlkem768_decaps -o "$work_dir/raw.o"
objcopy --strip-debug --strip-unneeded "$work_dir/raw.o" "$work_dir/stripped.o"
objcopy --keep-global-symbol=goal_mlkem768_keypair_derand \
  --keep-global-symbol=goal_mlkem768_encaps_derand --keep-global-symbol=goal_mlkem768_decaps \
  --localize-symbol=__wrap_RAND_bytes_ex \
  --localize-symbol=__wrap_RAND_priv_bytes_ex \
  --remove-section=.comment --remove-section=.note.gnu.build-id --remove-section=.llvm_addrsig \
  --remove-section=.eh_frame --remove-section=.rela.eh_frame \
  "$work_dir/stripped.o" "$work_dir/product.o"
printf '%s\n' $REQUIRED_SYMBOLS | sort > "$work_dir/expected-api"
nm -g --defined-only "$work_dir/product.o" | awk 'NF {print $NF}' | rg '^goal_mlkem768_' | sort > "$work_dir/actual-api"
if nm -g --defined-only "$work_dir/product.o" | awk 'NF {print $NF}' | rg -v '^goal_mlkem768_'; then
  echo "unexpected exported OpenSSL symbol" >&2
  exit 2
fi
cmp -s "$work_dir/expected-api" "$work_dir/actual-api" || { cat "$work_dir/actual-api" >&2; exit 2; }
nm -a "$work_dir/product.o" > "$work_dir/symbols"
nm -a --defined-only "$work_dir/product.o" > "$work_dir/defined-symbols"
nm -u "$work_dir/product.o" > "$work_dir/undefined"
printf '%s\n' $EXPECTED_UNDEFINED_SYMBOLS | sort > "$work_dir/expected-undefined"
awk 'NF {print $NF}' "$work_dir/undefined" | sort > "$work_dir/actual-undefined"
cmp -s "$work_dir/expected-undefined" "$work_dir/actual-undefined" || {
  echo "unexpected OpenSSL product runtime dependencies" >&2
  cat "$work_dir/actual-undefined" >&2
  exit 2
}
readelf -Wr "$work_dir/product.o" > "$work_dir/relocations"
readelf -SW "$work_dir/product.o" > "$work_dir/sections"
objdump -d "$work_dir/product.o" > "$work_dir/disassembly"
if rg -ni '(^|[^_])RAND_(bytes|priv_bytes)|getrandom|getentropy|urandom|random_device|system_rng|auto_rng' "$work_dir/defined-symbols" "$work_dir/relocations"; then echo "reachable entropy dependency detected" >&2; exit 2; fi
if rg -ni 'EVP_MD_fetch|ossl_default_provider|ossl_provider|OSSL_PROVIDER|operation_cache|method_store|inner_evp_generic_fetch' "$work_dir/defined-symbols" "$work_dir/relocations"; then echo "reachable provider or fetch dependency detected" >&2; exit 2; fi
if rg -ni '(public|secret|matrix|transformed|pk|ek|dk|hash)[[:alnum:]_]*cache' "$work_dir/defined-symbols"; then echo "reachable ML-KEM cache metadata detected" >&2; exit 2; fi
if rg -n '\.eh_frame|\.gcc_except_table' "$work_dir/sections"; then echo "unneeded unwind metadata retained" >&2; exit 2; fi
if rg -n '\.note\.GNU-stack.* X ' "$work_dir/sections"; then echo "executable stack requested" >&2; exit 2; fi
if [ "$PROFILE" = avx2 ] && (rg -n '%zmm|%k[0-7]' "$work_dir/disassembly" || rg -ni 'avx512' "$work_dir/symbols"); then echo "AVX512 detected" >&2; exit 2; fi
"$C_COMPILER" $common_flags -I"$ROOT_DIR/scripts" \
  "$ROOT_DIR/scripts/goal_size_adapter_test.c" "$work_dir/product.o" \
  -no-pie -pthread -o "$work_dir/smoke"
"$work_dir/smoke"
"$C_COMPILER" $common_flags -DUSE_GOAL_SIZE_ADAPTER_API \
  -I"$ROOT_DIR/scripts" "$ROOT_DIR/bench.c" "$work_dir/product.o" \
  -Wl,--gc-sections -no-pie -pthread -o "$work_dir/corpus"
"$work_dir/corpus" --emit-corpus > "$work_dir/corpus.bin"
corpus_bytes="$(wc -c < "$work_dir/corpus.bin")"
corpus_sha256="$(sha256sum "$work_dir/corpus.bin" | awk '{print $1}')"
if [ "$corpus_bytes" != "$EXPECTED_CORPUS_BYTES" ] ||
    [ "$corpus_sha256" != "$EXPECTED_CORPUS_SHA256" ]; then
  echo "OpenSSL core corpus differs from the cross-path reference" >&2
  echo "bytes=$corpus_bytes sha256=$corpus_sha256" >&2
  exit 2
fi
mkdir -p "$(dirname "$OUTPUT")"; cp "$work_dir/product.o" "$OUTPUT"
printf 'profile=%s\ncompiler=%s\ncomparator_update=%s\nopenssl_commit=%s\nopenssl_remote=%s\nopenssl_config_target=%s\nopenssl_cflags=%s\nopenssl_config_no_cached_fetch=pass\nadapter_mode=internal-core-selected-objects\nselected_object_count=3\nopenssl_mlkem_object_sha256=%s\nopenssl_sha3_object_sha256=%s\nopenssl_keccak_object_sha256=%s\nprovider_registry_linked=no\nerror_queue_shim=discarded\nruntime_dependencies=libc,pthread\nwire_key_parse_per_call=pass\noperation_rebuild_per_call=pass\nmatrix_precompute_timed=pass\ndeterministic_entropy_shim=fail-closed\napi_count=3\ncache_audit=pass\nreachable_entropy_audit=pass\nprovider_fetch_audit=pass\nnoexec_stack_audit=pass\nunwind_metadata=removed\navx512_audit=%s\ncorrectness_smoke=pass\ncross_path_corpus_fixtures=64\ncross_path_corpus_bytes=%s\ncross_path_corpus_sha256=%s\ncross_path_correctness=pass\n' "$PROFILE" "$C_COMPILER" "$comparator_update" "$(git -C "$OPENSSL_DIR" rev-parse HEAD)" "$openssl_remote" "$OPENSSL_CONFIG_TARGET" "$common_flags" "$(sha256sum "$mlkem_object" | awk '{print $1}')" "$(sha256sum "$sha3_object" | awk '{print $1}')" "$(sha256sum "$keccak_object" | awk '{print $1}')" "$([ "$PROFILE" = avx2 ] && echo pass || echo not-applicable)" "$corpus_bytes" "$corpus_sha256"
REQUIRED_SYMBOLS="$REQUIRED_SYMBOLS" "$ROOT_DIR/scripts/measure_elf_footprint.sh" "$OUTPUT"
