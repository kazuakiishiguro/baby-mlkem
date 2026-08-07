#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/goal_speed_profile.sh"
COMPARATOR="${COMPARATOR:-}"
PROFILE="${PROFILE:-native}"
C_COMPILER="${C_COMPILER:-clang}"
STACK_RUNS="${STACK_RUNS:-8}"
STACK_USABLE_BYTES="${STACK_USABLE_BYTES:-1048576}"
SIZE_ENFORCE="${SIZE_ENFORCE:-1}"
UPDATE_REPOS="${UPDATE_REPOS:-1}"
REQUIRE_CLEAN_WORKTREE="${REQUIRE_CLEAN_WORKTREE:-1}"

case "$COMPARATOR" in
  kyber)
    comparator_key=kyber
    comparator_slug=kyber
    comparator_label=Kyber
    comparator_dir="${KYBER_DIR:-/tmp/kyber}"
    ;;
  kyber-fair)
    comparator_key=kyber_fair
    comparator_slug=kyber-fair
    comparator_label="Kyber fair-flags"
    comparator_dir="${KYBER_DIR:-/tmp/kyber}"
    ;;
  pqclean)
    comparator_key=pqclean
    comparator_slug=pqclean
    comparator_label=PQClean
    comparator_dir="${PQCLEAN_DIR:-/tmp/PQClean}"
    ;;
  mlkem-native)
    comparator_key=mlkem_native
    comparator_slug=mlkem-native
    comparator_label=mlkem-native
    comparator_dir="${MLKEM_NATIVE_DIR:-$ROOT_DIR/../mlkem-native}"
    ;;
  liboqs)
    comparator_key=liboqs
    comparator_slug=liboqs
    comparator_label=liboqs
    comparator_dir="${LIBOQS_DIR:-/tmp/liboqs}"
    ;;
  boringssl)
    comparator_key=boringssl
    comparator_slug=boringssl
    comparator_label=BoringSSL
    comparator_dir="${BORINGSSL_DIR:-/tmp/boringssl}"
    ;;
  libcrux)
    comparator_key=libcrux
    comparator_slug=libcrux
    comparator_label=libcrux
    comparator_dir="${LIBCRUX_BENCH_DIR:-/tmp/libcrux-mlkem-bench}"
    comparator_version="${LIBCRUX_CRATE_VERSION:-0.0.10}"
    ;;
  libjade)
    comparator_key=libjade
    comparator_slug=libjade
    comparator_label="libjade Kyber768 AVX2"
    comparator_dir="${LIBJADE_DIST_ROOT:-/tmp/libjade-dist-src-amd64}"
    comparator_kem_dir="${LIBJADE_KEM_DIR:-$comparator_dir/libjade/crypto_kem/kyber_kyber768_avx2}"
    comparator_version="${LIBJADE_RELEASE_TAG:-release/2023.05-2}"
    comparator_dist_url="${LIBJADE_DIST_URL:-https://github.com/formosa-crypto/libjade/releases/download/release/2023.05-2/libjade-dist-src-amd64.tar.gz}"
    comparator_latest_api="${LIBJADE_LATEST_API:-https://api.github.com/repos/formosa-crypto/libjade/releases/latest}"
    comparator_assembly_sha="${LIBJADE_EXPECTED_ASSEMBLY_SHA256:-358736656400f28f75db858c1be703a3140c8f6fac17b99279abc857112cf5d1}"
    comparator_header_sha="${LIBJADE_EXPECTED_HEADER_SHA256:-e4ee2af96ac4c4f3184764c4e8565eb52d58670d4b58ef98b9635415162f9ca7}"
    comparator_jazz_sha="${LIBJADE_EXPECTED_JAZZ_SHA256:-ef7b8c32a0ef5d52150decbeea34161b986c3c580122c459c69fa28265a84f5f}"
    ;;
  botan)
    comparator_key=botan
    comparator_slug=botan
    comparator_label="Botan ML-KEM-768"
    comparator_dir="${BOTAN_DIR:-/tmp/botan-mlkem}"
    comparator_modules="${BOTAN_MODULES:-ml_kem,keccak_perm_bmi2}"
    ;;
  openssl)
    comparator_key=openssl
    comparator_slug=openssl
    comparator_label="OpenSSL ML-KEM-768"
    comparator_dir="${OPENSSL_DIR:-/tmp/openssl-mlkem-$PROFILE}"
    comparator_repo_url="${OPENSSL_REPO_URL:-https://github.com/openssl/openssl.git}"
    ;;
  *)
    echo "unsupported size comparator: ${COMPARATOR:-<unset>}" >&2
    echo "expected kyber, kyber-fair, pqclean, mlkem-native, liboqs," >&2
    echo "boringssl, libcrux, libjade, botan, or openssl" >&2
    exit 2
    ;;
esac
REPORT_FILE="${REPORT_FILE:-/tmp/baby-mlkem-goal-${PROFILE}-${comparator_slug}-size.txt}"

case "$PROFILE" in
  native|avx2) ;;
  *)
    echo "unsupported goal size profile: $PROFILE (expected native|avx2)" >&2
    exit 2
    ;;
esac
for name in SIZE_ENFORCE UPDATE_REPOS REQUIRE_CLEAN_WORKTREE; do
  value="${!name}"
  if [ "$value" != "0" ] && [ "$value" != "1" ]; then
    echo "$name must be 0 or 1" >&2
    exit 2
  fi
done
if ! [[ "$STACK_RUNS" =~ ^[0-9]+$ ]] || [ "$STACK_RUNS" -lt 8 ]; then
  echo "STACK_RUNS must be an integer >= 8" >&2
  exit 2
fi
if ! [[ "$STACK_USABLE_BYTES" =~ ^[0-9]+$ ]] ||
    [ "$STACK_USABLE_BYTES" -lt 65536 ]; then
  echo "STACK_USABLE_BYTES must be an integer >= 65536" >&2
  exit 2
fi
for command in "$C_COMPILER" git make rg nm objdump sha256sum awk lscpu; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command not found: $command" >&2
    exit 2
  fi
done
if [ ! -d "$(dirname "$REPORT_FILE")" ]; then
  echo "report directory does not exist: $(dirname "$REPORT_FILE")" >&2
  exit 2
fi
if [ "$REQUIRE_CLEAN_WORKTREE" = "1" ] &&
    [ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=normal)" ]; then
  echo "goal size verification requires a clean committed worktree" >&2
  exit 2
fi
if [ "$COMPARATOR" = libcrux ] || [ "$COMPARATOR" = libjade ] ||
    [ "$COMPARATOR" = botan ] || [ "$COMPARATOR" = openssl ]; then
  comparator_update=delegated-to-product-builder
else
  if ! git -C "$comparator_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "missing $comparator_label git checkout: $comparator_dir" >&2
    exit 2
  fi
  if [ -n "$(git -C "$comparator_dir" status --porcelain --untracked-files=normal)" ]; then
    echo "$comparator_label checkout must be clean: $comparator_dir" >&2
    exit 2
  fi

  if [ "$UPDATE_REPOS" = "1" ]; then
    git -C "$comparator_dir" pull --ff-only
    comparator_update=pass
  else
    comparator_update=skipped
  fi
  if [ -n "$(git -C "$comparator_dir" status --porcelain --untracked-files=normal)" ]; then
    echo "$comparator_label checkout became dirty after update" >&2
    exit 2
  fi
fi

goal_speed_configure_profile "$PROFILE" "$C_COMPILER"
stack_cflags="$OPT_CFLAGS $ARCH_CFLAGS $EXTRA_CFLAGS -std=c99"
case "$COMPARATOR" in
  kyber)
    comparator_cflags="$UPSTREAM_CFLAGS"
    ;;
  kyber-fair)
    comparator_cflags="$FAIR_UPSTREAM_CFLAGS"
    ;;
  pqclean)
    comparator_cflags="$PQCLEAN_AVX2_CFLAGS"
    ;;
  mlkem-native)
    comparator_cflags="$MLKEM_NATIVE_CFLAGS"
    ;;
  liboqs)
    comparator_cflags="$LIBOQS_CFLAGS"
    ;;
  boringssl)
    comparator_cflags="$BORINGSSL_C_FLAGS"
    comparator_cxxflags="$BORINGSSL_CXX_FLAGS"
    ;;
  libcrux)
    comparator_cflags="$RUSTFLAGS_BENCH"
    ;;
  libjade)
    comparator_cflags="$LIBJADE_HARNESS_CFLAGS"
    ;;
  botan)
    comparator_cflags="$BOTAN_CXXFLAGS"
    comparator_cxx="$BOTAN_CXX"
    comparator_disabled_modules="$BOTAN_DISABLED_MODULES"
    comparator_cxx_stdlib_flags="$GOAL_CXX_STDLIB_FLAGS"
    ;;
  openssl)
    comparator_cflags="$OPENSSL_CFLAGS"
    ;;
esac
if [ "$COMPARATOR" = botan ] &&
    ! command -v "$comparator_cxx" >/dev/null 2>&1; then
  echo "matching Botan C++ compiler not found: $comparator_cxx" >&2
  exit 2
fi

work_dir="$(mktemp -d /tmp/baby-mlkem-goal-size.XXXXXX)"
local_artifact="$work_dir/baby_mlkem768_product.o"
comparator_artifact="$work_dir/${comparator_slug}_mlkem768_product.o"
local_stack_report="$work_dir/local-stack.txt"
comparator_stack_report="$work_dir/comparator-stack.txt"
local_footprint="$work_dir/local-footprint.txt"
comparator_footprint="$work_dir/comparator-footprint.txt"
comparator_build_report="$work_dir/comparator-build.txt"
raw_report="$work_dir/report.txt"
cleanup() {
  make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT

if command -v flock >/dev/null 2>&1; then
  exec 9>"$ROOT_DIR/.bench-compare.lock"
  if ! flock -n 9; then
    echo "waiting_for_bench_lock=$ROOT_DIR/.bench-compare.lock" >&2
    flock 9
  fi
fi

make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null
make -C "$ROOT_DIR" product test-product CC="$C_COMPILER" >/dev/null
cp "$ROOT_DIR/baby_mlkem768_product.o" "$local_artifact"

local_api_count="$(nm -g --defined-only "$local_artifact" |
  awk '$3 ~ /^baby_mlkem768_/ { count++ } END { print count + 0 }')"
if [ "$local_api_count" -ne 3 ]; then
  echo "local product must export exactly three baby_mlkem768 APIs" >&2
  exit 2
fi
cache_pattern='mlkem_internal_caches_enabled|kpke_public_cache_(ek|valid|generation)'
cache_pattern+='|kpke_secret_cache_(dk|valid)|mlkem_ek_hash_cache'
cache_pattern+='|mlkem_cache_generation_counter'
if nm "$local_artifact" | rg -n "$cache_pattern"; then
  echo "local product retained persistent cache metadata" >&2
  exit 2
fi
if [ "$PROFILE" = "avx2" ]; then
  if objdump -d "$local_artifact" | rg -n '%zmm|%k[0-7]' ||
      nm "$local_artifact" | rg -n 'avx512'; then
    echo "local AVX2-only product retained AVX512 code" >&2
    exit 2
  fi
  local_avx512_audit=pass
else
  local_avx512_audit=not-applicable
fi

STACK_RUNS="$STACK_RUNS" STACK_USABLE_BYTES="$STACK_USABLE_BYTES" \
C_COMPILER="$C_COMPILER" STACK_CFLAGS="$stack_cflags" \
  "$ROOT_DIR/scripts/measure_stack_highwater.sh" \
  "$local_artifact" local > "$local_stack_report"
local_max_stack="$(sed -n 's/^max_stack_bytes=//p' "$local_stack_report")"
MAX_STACK_BYTES="$local_max_stack" \
  "$ROOT_DIR/scripts/measure_product_size.sh" \
  "$local_artifact" > "$local_footprint"

case "$COMPARATOR" in
  kyber|kyber-fair)
    PROFILE="$PROFILE" OUTPUT="$comparator_artifact" \
    KYBER_DIR="$comparator_dir" C_COMPILER="$C_COMPILER" \
    UPSTREAM_CFLAGS="$comparator_cflags" ALLOW_CACHED_COMPARATOR=0 \
      "$ROOT_DIR/scripts/build_goal_kyber_product.sh" \
      > "$comparator_build_report"
    ;;
  pqclean)
    PROFILE="$PROFILE" OUTPUT="$comparator_artifact" \
    PQCLEAN_DIR="$comparator_dir" C_COMPILER="$C_COMPILER" \
    PQCLEAN_AVX2_CFLAGS="$comparator_cflags" \
      "$ROOT_DIR/scripts/build_goal_pqclean_product.sh" \
      > "$comparator_build_report"
    ;;
  mlkem-native)
    PROFILE="$PROFILE" OUTPUT="$comparator_artifact" \
    MLKEM_NATIVE_DIR="$comparator_dir" C_COMPILER="$C_COMPILER" \
    MLKEM_NATIVE_AUTO="$MLKEM_NATIVE_AUTO" \
    MLKEM_NATIVE_CFLAGS="$comparator_cflags" \
      "$ROOT_DIR/scripts/build_goal_mlkem_native_product.sh" \
      > "$comparator_build_report"
    ;;
  liboqs)
    PROFILE="$PROFILE" OUTPUT="$comparator_artifact" \
    LIBOQS_DIR="$comparator_dir" C_COMPILER="$C_COMPILER" \
    LIBOQS_DIST_BUILD="$LIBOQS_DIST_BUILD" \
    LIBOQS_OPT_TARGET="$LIBOQS_OPT_TARGET" \
    LIBOQS_CFLAGS="$comparator_cflags" \
      "$ROOT_DIR/scripts/build_goal_liboqs_product.sh" \
      > "$comparator_build_report"
    ;;
  boringssl)
    PROFILE="$PROFILE" OUTPUT="$comparator_artifact" \
    BORINGSSL_DIR="$comparator_dir" C_COMPILER="$C_COMPILER" \
    BORINGSSL_C_FLAGS="$comparator_cflags" \
    BORINGSSL_CXX_FLAGS="$comparator_cxxflags" \
      "$ROOT_DIR/scripts/build_goal_boringssl_product.sh" \
      > "$comparator_build_report"
    ;;
  libcrux)
    PROFILE="$PROFILE" OUTPUT="$comparator_artifact" \
    LIBCRUX_BENCH_DIR="$comparator_dir" C_COMPILER="$C_COMPILER" \
    LIBCRUX_CRATE_VERSION="$comparator_version" \
    LIBCRUX_ENABLE_SIMD256=1 UPDATE_REPOS="$UPDATE_REPOS" \
    RUSTFLAGS_BENCH="$comparator_cflags" \
      "$ROOT_DIR/scripts/build_goal_libcrux_product.sh" \
      > "$comparator_build_report"
    ;;
  libjade)
    PROFILE="$PROFILE" OUTPUT="$comparator_artifact" \
    LIBJADE_DIST_ROOT="$comparator_dir" \
    LIBJADE_KEM_DIR="$comparator_kem_dir" \
    LIBJADE_RELEASE_TAG="$comparator_version" \
    LIBJADE_DIST_URL="$comparator_dist_url" \
    LIBJADE_LATEST_API="$comparator_latest_api" \
    LIBJADE_EXPECTED_ASSEMBLY_SHA256="$comparator_assembly_sha" \
    LIBJADE_EXPECTED_HEADER_SHA256="$comparator_header_sha" \
    LIBJADE_EXPECTED_JAZZ_SHA256="$comparator_jazz_sha" \
    LIBJADE_HARNESS_CFLAGS="$comparator_cflags" \
    UPDATE_REPOS="$UPDATE_REPOS" C_COMPILER="$C_COMPILER" \
      "$ROOT_DIR/scripts/build_goal_libjade_product.sh" \
      > "$comparator_build_report"
    ;;
  botan)
    PROFILE="$PROFILE" OUTPUT="$comparator_artifact" \
    BOTAN_DIR="$comparator_dir" BOTAN_MODULES="$comparator_modules" \
    BOTAN_CXXFLAGS="$comparator_cflags" \
    BOTAN_DISABLED_MODULES="$comparator_disabled_modules" \
    UPDATE_REPOS="$UPDATE_REPOS" C_COMPILER="$C_COMPILER" \
      "$ROOT_DIR/scripts/build_goal_botan_product.sh" \
      > "$comparator_build_report"
    ;;
  openssl)
    PROFILE="$PROFILE" OUTPUT="$comparator_artifact" \
    OPENSSL_DIR="$comparator_dir" OPENSSL_REPO_URL="$comparator_repo_url" \
    OPENSSL_PRODUCT_CFLAGS="$comparator_cflags" \
    UPDATE_REPOS="$UPDATE_REPOS" C_COMPILER="$C_COMPILER" \
      "$ROOT_DIR/scripts/build_goal_openssl_product.sh" \
      > "$comparator_build_report"
    ;;
esac
if [ "$COMPARATOR" = libcrux ]; then
  comparator_update="$(sed -n 's/^comparator_update=//p' "$comparator_build_report")"
  comparator_version="$(sed -n 's/^libcrux_crate_version=//p' "$comparator_build_report")"
  comparator_source="$(sed -n 's/^libcrux_crate_source=//p' "$comparator_build_report")"
  comparator_checksum="$(sed -n 's/^libcrux_crate_checksum=//p' "$comparator_build_report")"
  comparator_lock_sha="$(sed -n 's/^libcrux_lock_sha256=//p' "$comparator_build_report")"
  if [ -z "$comparator_update" ] || [ -z "$comparator_version" ] ||
      [ -z "$comparator_checksum" ] || [ -z "$comparator_lock_sha" ]; then
    echo "failed to parse libcrux product provenance" >&2
    exit 2
  fi
elif [ "$COMPARATOR" = libjade ]; then
  comparator_update="$(sed -n 's/^comparator_update=//p' "$comparator_build_report")"
  comparator_version="$(sed -n 's/^libjade_release_tag=//p' "$comparator_build_report")"
  comparator_source="$(sed -n 's/^libjade_dist_url=//p' "$comparator_build_report")"
  comparator_semantics="$(sed -n 's/^libjade_semantics=//p' "$comparator_build_report")"
  comparator_assembly_sha="$(sed -n 's/^libjade_assembly_sha256=//p' "$comparator_build_report")"
  comparator_header_sha="$(sed -n 's/^libjade_header_sha256=//p' "$comparator_build_report")"
  comparator_jazz_sha="$(sed -n 's/^libjade_jazz_sha256=//p' "$comparator_build_report")"
  comparator_archive_sha="$(sed -n 's/^libjade_archive_sha256=//p' "$comparator_build_report")"
  comparator_latest_tag="$(sed -n 's/^latest_release_tag=//p' "$comparator_build_report")"
  comparator_latest_audit="$(sed -n 's/^latest_release_audit=//p' "$comparator_build_report")"
  if [ -z "$comparator_update" ] || [ -z "$comparator_version" ] ||
      [ -z "$comparator_source" ] || [ -z "$comparator_semantics" ] ||
      [ -z "$comparator_assembly_sha" ] || [ -z "$comparator_header_sha" ] ||
      [ -z "$comparator_jazz_sha" ] || [ -z "$comparator_archive_sha" ] ||
      [ -z "$comparator_latest_tag" ] || [ -z "$comparator_latest_audit" ]; then
    echo "failed to parse libjade product provenance" >&2
    exit 2
  fi
elif [ "$COMPARATOR" = botan ]; then
  comparator_update="$(sed -n 's/^comparator_update=//p' "$comparator_build_report")"
  comparator_version="$(sed -n 's/^botan_version=//p' "$comparator_build_report")"
  comparator_commit="$(sed -n 's/^botan_commit=//p' "$comparator_build_report")"
  comparator_source="$(sed -n 's/^botan_remote=//p' "$comparator_build_report")"
  comparator_modules_resolved="$(sed -n 's/^botan_modules_resolved=//p' "$comparator_build_report")"
  botan_adapter_mode="$(sed -n 's/^adapter_mode=//p' "$comparator_build_report")"
  botan_wire_parse="$(sed -n 's/^wire_key_parse_per_call=//p' "$comparator_build_report")"
  botan_operation_rebuild="$(sed -n 's/^operation_rebuild_per_call=//p' "$comparator_build_report")"
  botan_matrix_timed="$(sed -n 's/^matrix_precompute_timed=//p' "$comparator_build_report")"
  botan_unwind_retained="$(sed -n \
    's/^functional_exception_unwind_retained=//p' \
    "$comparator_build_report")"
  botan_correctness="$(sed -n 's/^correctness_smoke=//p' "$comparator_build_report")"
  if [ -z "$comparator_version" ] || [ -z "$comparator_commit" ] ||
      [ -z "$comparator_source" ] || [ -z "$comparator_modules_resolved" ] ||
      [ "$botan_adapter_mode" != internal-core-direct ] ||
      [ "$botan_wire_parse" != pass ] ||
      [ "$botan_operation_rebuild" != pass ] ||
      [ "$botan_matrix_timed" != pass ] ||
      [ "$botan_unwind_retained" != pass ] ||
      [ "$botan_correctness" != pass ]; then
    echo "failed to validate Botan product provenance or no-cache contract" >&2
    exit 2
  fi
  if { [ "$UPDATE_REPOS" = "1" ] && [ "$comparator_update" != pass ]; } ||
      { [ "$UPDATE_REPOS" = "0" ] && [ "$comparator_update" != skipped ]; }; then
    echo "Botan comparator update status does not match UPDATE_REPOS" >&2
    exit 2
  fi
elif [ "$COMPARATOR" = openssl ]; then
  comparator_update="$(sed -n 's/^comparator_update=//p' "$comparator_build_report")"
  comparator_commit="$(sed -n 's/^openssl_commit=//p' "$comparator_build_report")"
  comparator_source="$(sed -n 's/^openssl_remote=//p' "$comparator_build_report")"
  openssl_effective_cflags="$(sed -n 's/^openssl_cflags=//p' "$comparator_build_report")"
  openssl_no_cached_fetch="$(sed -n 's/^openssl_config_no_cached_fetch=//p' "$comparator_build_report")"
  openssl_adapter_mode="$(sed -n 's/^adapter_mode=//p' "$comparator_build_report")"
  openssl_selected_objects="$(sed -n 's/^selected_object_count=//p' "$comparator_build_report")"
  openssl_mlkem_sha="$(sed -n 's/^openssl_mlkem_object_sha256=//p' "$comparator_build_report")"
  openssl_sha3_sha="$(sed -n 's/^openssl_sha3_object_sha256=//p' "$comparator_build_report")"
  openssl_keccak_sha="$(sed -n 's/^openssl_keccak_object_sha256=//p' "$comparator_build_report")"
  openssl_provider_registry="$(sed -n 's/^provider_registry_linked=//p' "$comparator_build_report")"
  openssl_error_queue="$(sed -n 's/^error_queue_shim=//p' "$comparator_build_report")"
  openssl_runtime_dependencies="$(sed -n 's/^runtime_dependencies=//p' "$comparator_build_report")"
  openssl_wire_parse="$(sed -n 's/^wire_key_parse_per_call=//p' "$comparator_build_report")"
  openssl_operation_rebuild="$(sed -n 's/^operation_rebuild_per_call=//p' "$comparator_build_report")"
  openssl_matrix_timed="$(sed -n 's/^matrix_precompute_timed=//p' "$comparator_build_report")"
  openssl_entropy_shim="$(sed -n 's/^deterministic_entropy_shim=//p' "$comparator_build_report")"
  openssl_api_count="$(sed -n 's/^api_count=//p' "$comparator_build_report")"
  openssl_cache_audit="$(sed -n 's/^cache_audit=//p' "$comparator_build_report")"
  openssl_entropy_audit="$(sed -n 's/^reachable_entropy_audit=//p' "$comparator_build_report")"
  openssl_provider_audit="$(sed -n 's/^provider_fetch_audit=//p' "$comparator_build_report")"
  openssl_noexec_audit="$(sed -n 's/^noexec_stack_audit=//p' "$comparator_build_report")"
  openssl_unwind="$(sed -n 's/^unwind_metadata=//p' "$comparator_build_report")"
  openssl_avx512="$(sed -n 's/^avx512_audit=//p' "$comparator_build_report")"
  openssl_smoke="$(sed -n 's/^correctness_smoke=//p' "$comparator_build_report")"
  openssl_corpus_fixtures="$(sed -n 's/^cross_path_corpus_fixtures=//p' "$comparator_build_report")"
  openssl_corpus_bytes="$(sed -n 's/^cross_path_corpus_bytes=//p' "$comparator_build_report")"
  openssl_corpus_sha="$(sed -n 's/^cross_path_corpus_sha256=//p' "$comparator_build_report")"
  openssl_corpus_correctness="$(sed -n 's/^cross_path_correctness=//p' "$comparator_build_report")"
  if [ "$PROFILE" = avx2 ]; then
    openssl_expected_avx512=pass
  else
    openssl_expected_avx512=not-applicable
  fi
  if [ -z "$comparator_commit" ] || [ "$comparator_source" != "$comparator_repo_url" ] ||
      [[ "$openssl_effective_cflags" != "$comparator_cflags "* ]] ||
      [ "$openssl_no_cached_fetch" != pass ] ||
      [ "$openssl_adapter_mode" != internal-core-selected-objects ] ||
      [ "$openssl_selected_objects" != 3 ] ||
      ! [[ "$openssl_mlkem_sha" =~ ^[0-9a-f]{64}$ ]] ||
      ! [[ "$openssl_sha3_sha" =~ ^[0-9a-f]{64}$ ]] ||
      ! [[ "$openssl_keccak_sha" =~ ^[0-9a-f]{64}$ ]] ||
      [ "$openssl_provider_registry" != no ] ||
      [ "$openssl_error_queue" != discarded ] ||
      [ "$openssl_runtime_dependencies" != libc,pthread ] ||
      [ "$openssl_wire_parse" != pass ] ||
      [ "$openssl_operation_rebuild" != pass ] ||
      [ "$openssl_matrix_timed" != pass ] ||
      [ "$openssl_entropy_shim" != fail-closed ] ||
      [ "$openssl_api_count" != 3 ] || [ "$openssl_cache_audit" != pass ] ||
      [ "$openssl_entropy_audit" != pass ] || [ "$openssl_provider_audit" != pass ] ||
      [ "$openssl_noexec_audit" != pass ] || [ "$openssl_unwind" != removed ] ||
      [ "$openssl_avx512" != "$openssl_expected_avx512" ] ||
      [ "$openssl_smoke" != pass ] || [ "$openssl_corpus_fixtures" != 64 ] ||
      [ "$openssl_corpus_bytes" != 381228 ] ||
      [ "$openssl_corpus_sha" != e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67 ] ||
      [ "$openssl_corpus_correctness" != pass ]; then
    echo "failed to validate OpenSSL product provenance or core-only contract" >&2
    exit 2
  fi
  if { [ "$UPDATE_REPOS" = "1" ] && [ "$comparator_update" != pass ]; } ||
      { [ "$UPDATE_REPOS" = "0" ] && [ "$comparator_update" != skipped ]; }; then
    echo "OpenSSL comparator update status does not match UPDATE_REPOS" >&2
    exit 2
  fi
fi
comparator_stack_linker="$C_COMPILER"
comparator_stack_ldflags=""
if [ "$COMPARATOR" = botan ]; then
  comparator_stack_linker="$comparator_cxx"
  comparator_stack_ldflags="-no-pie -pthread -ldl -lm"
  if [ -n "$comparator_cxx_stdlib_flags" ]; then
    comparator_stack_ldflags="$comparator_cxx_stdlib_flags $comparator_stack_ldflags"
  fi
elif [ "$COMPARATOR" = openssl ]; then
  comparator_stack_ldflags="-no-pie -pthread"
fi
STACK_RUNS="$STACK_RUNS" STACK_USABLE_BYTES="$STACK_USABLE_BYTES" \
C_COMPILER="$C_COMPILER" STACK_CFLAGS="$stack_cflags" \
STACK_LINKER="$comparator_stack_linker" \
STACK_LDFLAGS="$comparator_stack_ldflags" \
  "$ROOT_DIR/scripts/measure_stack_highwater.sh" \
  "$comparator_artifact" goal > "$comparator_stack_report"
comparator_max_stack="$(sed -n 's/^max_stack_bytes=//p' \
  "$comparator_stack_report")"
REQUIRED_SYMBOLS='goal_mlkem768_keypair_derand goal_mlkem768_encaps_derand goal_mlkem768_decaps' \
MAX_STACK_BYTES="$comparator_max_stack" \
  "$ROOT_DIR/scripts/measure_elf_footprint.sh" \
  "$comparator_artifact" > "$comparator_footprint"

local_primary="$(sed -n 's/^primary_bytes=//p' "$local_footprint")"
comparator_primary="$(sed -n 's/^primary_bytes=//p' "$comparator_footprint")"
local_writable="$(sed -n 's/^writable_bytes=//p' "$local_footprint")"
comparator_writable="$(sed -n 's/^writable_bytes=//p' "$comparator_footprint")"
if [ -z "$local_primary" ] || [ -z "$comparator_primary" ] ||
    [ -z "$local_max_stack" ] || [ -z "$comparator_max_stack" ]; then
  echo "failed to parse size or stack measurements" >&2
  exit 2
fi
primary_delta=$((local_primary - comparator_primary))
stack_delta=$((local_max_stack - comparator_max_stack))
primary_ratio="$(awk -v local="$local_primary" -v other="$comparator_primary" \
  'BEGIN { printf "%.6f", local / other }')"
stack_ratio="$(awk -v local="$local_max_stack" -v other="$comparator_max_stack" \
  'BEGIN { printf "%.6f", local / other }')"
if [ "$local_primary" -le "$comparator_primary" ]; then
  size_gate=PASS
else
  size_gate=FAIL
fi

host_cpu="$(lscpu | awk -F: '/Model name/ && !seen {
  gsub(/^[[:space:]]+/, "", $2)
  print $2
  seen = 1
}')"
{
  printf "goal_size_scope=%s-only\n" "$comparator_slug"
  printf "goal_completion_qualifying=no\n"
  printf "goal_comparator=%s\n" "$COMPARATOR"
  printf "goal_profile=%s\n" "$PROFILE"
  printf "goal_report_utc=%s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf "baby_mlkem_commit=%s\n" "$(git -C "$ROOT_DIR" rev-parse HEAD)"
  printf "baby_mlkem_remote=%s\n" "$(git -C "$ROOT_DIR" remote get-url origin)"
  if [ "$COMPARATOR" = libcrux ]; then
    printf "libcrux_crate_version=%s\n" "$comparator_version"
    printf "libcrux_crate_source=%s\n" "$comparator_source"
    printf "libcrux_crate_checksum=%s\n" "$comparator_checksum"
    printf "libcrux_lock_sha256=%s\n" "$comparator_lock_sha"
  elif [ "$COMPARATOR" = libjade ]; then
    printf "libjade_release_tag=%s\n" "$comparator_version"
    printf "libjade_dist_url=%s\n" "$comparator_source"
    printf "libjade_semantics=%s\n" "$comparator_semantics"
    printf "libjade_assembly_sha256=%s\n" "$comparator_assembly_sha"
    printf "libjade_header_sha256=%s\n" "$comparator_header_sha"
    printf "libjade_jazz_sha256=%s\n" "$comparator_jazz_sha"
    printf "libjade_archive_sha256=%s\n" "$comparator_archive_sha"
    printf "libjade_latest_release_tag=%s\n" "$comparator_latest_tag"
    printf "libjade_latest_release_audit=%s\n" "$comparator_latest_audit"
  elif [ "$COMPARATOR" = botan ]; then
    printf "botan_version=%s\n" "$comparator_version"
    printf "botan_commit=%s\n" "$comparator_commit"
    printf "botan_remote=%s\n" "$comparator_source"
    printf "botan_modules_requested=%s\n" "$comparator_modules"
    printf "botan_modules_resolved=%s\n" "$comparator_modules_resolved"
    printf "botan_adapter_mode=%s\n" "$botan_adapter_mode"
    printf "botan_no_cache_contract=pass\n"
  elif [ "$COMPARATOR" = openssl ]; then
    printf "openssl_commit=%s\n" "$comparator_commit"
    printf "openssl_remote=%s\n" "$comparator_source"
    printf "openssl_adapter_mode=%s\n" "$openssl_adapter_mode"
    printf "openssl_selected_object_count=%s\n" "$openssl_selected_objects"
    printf "openssl_core_only_contract=pass\n"
  else
    printf "%s_commit=%s\n" "$comparator_key" \
      "$(git -C "$comparator_dir" rev-parse HEAD)"
    printf "%s_remote=%s\n" "$comparator_key" \
      "$(git -C "$comparator_dir" remote get-url origin)"
  fi
  printf "comparator_update=%s\n" "$comparator_update"
  printf "host_kernel=%s\n" "$(uname -sr)"
  printf "host_cpu=%s\n" "$host_cpu"
  printf "compiler=%s\n" "$C_COMPILER"
  printf "compiler_version=%s\n" "$("$C_COMPILER" --version | sed -n '1p')"
  printf "local_opt_cflags=%s\n" "$OPT_CFLAGS"
  printf "local_extra_cflags=%s\n" "$EXTRA_CFLAGS"
  printf "local_arch_cflags=%s\n" "$ARCH_CFLAGS"
  if [ "$COMPARATOR" = libcrux ]; then
    printf "libcrux_rustflags=%s\n" "$comparator_cflags"
  elif [ "$COMPARATOR" = libjade ]; then
    printf "libjade_harness_cflags=%s\n" "$comparator_cflags"
  elif [ "$COMPARATOR" = botan ]; then
    printf "botan_cxx=%s\n" "$comparator_cxx"
    printf "botan_cxx_version=%s\n" \
      "$("$comparator_cxx" --version | sed -n '1p')"
    printf "botan_cxxflags=%s\n" "$comparator_cflags"
    printf "botan_disabled_modules=%s\n" \
      "${comparator_disabled_modules:-<none>}"
  else
    printf "%s_cflags=%s\n" "$comparator_key" "$comparator_cflags"
  fi
  if [ "$COMPARATOR" = boringssl ]; then
    printf "boringssl_cxxflags=%s\n" "$comparator_cxxflags"
  fi
  printf "stack_runs=%s\n" "$STACK_RUNS"
  printf "stack_usable_bytes=%s\n" "$STACK_USABLE_BYTES"
  printf "local_api_count=%s\n" "$local_api_count"
  printf "local_cache_audit=pass\n"
  printf "local_avx512_audit=%s\n" "$local_avx512_audit"
  sed 's/^/local_footprint_/' "$local_footprint"
  sed 's/^/local_stack_/' "$local_stack_report"
  sed "s/^/${comparator_key}_build_/" "$comparator_build_report"
  sed "s/^/${comparator_key}_footprint_/" "$comparator_footprint"
  sed "s/^/${comparator_key}_stack_/" "$comparator_stack_report"
  printf "local_primary_bytes=%s\n" "$local_primary"
  printf "%s_primary_bytes=%s\n" "$comparator_key" "$comparator_primary"
  printf "local_writable_bytes=%s\n" "$local_writable"
  printf "%s_writable_bytes=%s\n" "$comparator_key" "$comparator_writable"
  printf "local_max_stack_bytes=%s\n" "$local_max_stack"
  printf "%s_max_stack_bytes=%s\n" "$comparator_key" "$comparator_max_stack"
  printf "local_over_%s_primary_ratio=%s\n" "$comparator_key" "$primary_ratio"
  printf "local_minus_%s_primary_bytes=%s\n" "$comparator_key" "$primary_delta"
  printf "local_over_%s_stack_ratio=%s\n" "$comparator_key" "$stack_ratio"
  printf "local_minus_%s_stack_bytes=%s\n" "$comparator_key" "$stack_delta"
  printf "%s_size_gate=%s\n" "$comparator_key" "$size_gate"
} > "$raw_report"

cp "$raw_report" "$REPORT_FILE"
cat "$REPORT_FILE"
printf "goal_%s_size_report=%s\n" "$comparator_key" "$REPORT_FILE"
if [ "$SIZE_ENFORCE" = "1" ] && [ "$size_gate" != "PASS" ]; then
  echo "$comparator_label size gate failed: local primary exceeds comparator" >&2
  exit 1
fi
