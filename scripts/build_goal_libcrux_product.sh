#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/goal_speed_profile.sh"
PROFILE="${PROFILE:-${1:-native}}"
OUTPUT="${OUTPUT:-${2:-/tmp/baby-mlkem-libcrux-${PROFILE}-product.o}}"
LIBCRUX_BENCH_DIR="${LIBCRUX_BENCH_DIR:-/tmp/libcrux-mlkem-bench}"
LIBCRUX_CRATE_VERSION="${LIBCRUX_CRATE_VERSION:-0.0.10}"
LIBCRUX_ENABLE_SIMD256="${LIBCRUX_ENABLE_SIMD256:-1}"
UPDATE_REPOS="${UPDATE_REPOS:-0}"
C_COMPILER="${C_COMPILER:-clang}"
CARGO_BIN="${CARGO_BIN:-cargo}"
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
if [ "$UPDATE_REPOS" != "0" ] && [ "$UPDATE_REPOS" != "1" ]; then
  echo "UPDATE_REPOS must be 0 or 1" >&2
  exit 2
fi
if [ "$LIBCRUX_ENABLE_SIMD256" != "1" ]; then
  echo "normalized libcrux product requires LIBCRUX_ENABLE_SIMD256=1" >&2
  exit 2
fi
if ! [[ "$LIBCRUX_CRATE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "invalid libcrux crate version: $LIBCRUX_CRATE_VERSION" >&2
  exit 2
fi
if ! [[ "$BUILD_JOBS" =~ ^[1-9][0-9]*$ ]]; then
  echo "BUILD_JOBS must be a positive integer" >&2
  exit 2
fi
if [ "$(uname -m)" != "x86_64" ]; then
  echo "normalized libcrux SIMD256 product currently requires x86_64" >&2
  exit 2
fi
for tool in "$C_COMPILER" "$CARGO_BIN" rustc nm objcopy objdump \
    python3 readelf rg sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool" >&2
    exit 2
  fi
done

rustflags_override="${RUSTFLAGS_BENCH:-}"
goal_speed_configure_profile "$PROFILE" "$C_COMPILER"
if [ -n "$rustflags_override" ]; then
  RUSTFLAGS_BENCH="$rustflags_override"
fi
case "$PROFILE" in
  native)
    if [[ "$RUSTFLAGS_BENCH" != *"target-cpu=native"* ]]; then
      echo "native libcrux flags are missing target-cpu=native" >&2
      exit 2
    fi
    ;;
  avx2)
    if [[ "$RUSTFLAGS_BENCH" != *"target-cpu=x86-64-v3"* ]]; then
      echo "AVX2-only libcrux flags are missing target-cpu=x86-64-v3" >&2
      exit 2
    fi
    if [[ "$RUSTFLAGS_BENCH" == *"target-cpu=native"* ]] ||
        [[ "$RUSTFLAGS_BENCH" =~ target-feature=[^[:space:]]*\+avx512 ]]; then
      echo "AVX2-only libcrux flags enable a native or AVX512 target" >&2
      exit 2
    fi
    ;;
esac

project_dir="$LIBCRUX_BENCH_DIR"
target_dir="$project_dir/target-product-$PROFILE"
work_dir="$(mktemp -d /tmp/baby-mlkem-libcrux-product.XXXXXX)"
cache_report="$work_dir/cache-audit.txt"
metadata_file="$work_dir/metadata.json"
cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT
mkdir -p "$project_dir/src"

cat > "$work_dir/Cargo.toml" <<EOF_MANIFEST
[package]
name = "libcrux_mlkem_product"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
libcrux-ml-kem = { version = "=${LIBCRUX_CRATE_VERSION}", default-features = false, features = ["mlkem768", "simd256"] }

[profile.release]
lto = "fat"
codegen-units = 1
panic = "abort"
debug = false
strip = false
EOF_MANIFEST
if [ ! -f "$project_dir/Cargo.toml" ] ||
    ! cmp -s "$work_dir/Cargo.toml" "$project_dir/Cargo.toml"; then
  cp "$work_dir/Cargo.toml" "$project_dir/Cargo.toml"
fi
if [ ! -f "$project_dir/src/lib.rs" ] ||
    ! cmp -s "$ROOT_DIR/scripts/goal_size_libcrux_adapter.rs" \
      "$project_dir/src/lib.rs"; then
  cp "$ROOT_DIR/scripts/goal_size_libcrux_adapter.rs" "$project_dir/src/lib.rs"
fi

if [ "$UPDATE_REPOS" = "1" ]; then
  search_output="$("$CARGO_BIN" search libcrux-ml-kem --limit 1)"
  latest_version="$(awk -F'"' '$1 ~ /^libcrux-ml-kem = / { print $2; exit }' <<< "$search_output")"
  if [ -z "$latest_version" ] || [ "$latest_version" != "$LIBCRUX_CRATE_VERSION" ]; then
    printf '%s\n' "$search_output" >&2
    echo "configured libcrux version is not the crates.io latest: configured=$LIBCRUX_CRATE_VERSION latest=${latest_version:-unknown}" >&2
    exit 2
  fi
  "$CARGO_BIN" update --manifest-path "$project_dir/Cargo.toml" >/dev/null
  comparator_update=pass
  latest_version_audit=pass
else
  comparator_update=skipped
  latest_version=unchecked
  latest_version_audit=skipped
fi
if [ ! -f "$project_dir/Cargo.lock" ]; then
  echo "libcrux Cargo.lock is missing; rerun with UPDATE_REPOS=1" >&2
  exit 2
fi
"$CARGO_BIN" metadata --manifest-path "$project_dir/Cargo.toml" \
  --locked --format-version=1 > "$metadata_file"
mapfile -t metadata_values < <(python3 - "$metadata_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    metadata = json.load(handle)
def package(name):
    matches = [p for p in metadata["packages"] if p["name"] == name]
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one resolved {name} package")
    return matches[0]

for name in ("libcrux-ml-kem", "libcrux-sha3"):
    resolved = package(name)
    print(resolved["version"])
    print(resolved["manifest_path"])
    print(resolved["source"] or "")
PY
)
if [ "${#metadata_values[@]}" -ne 6 ]; then
  echo "failed to parse resolved libcrux package metadata" >&2
  exit 2
fi
resolved_version="${metadata_values[0]}"
libcrux_manifest="${metadata_values[1]}"
libcrux_source="${metadata_values[2]}"
libcrux_sha3_version="${metadata_values[3]}"
libcrux_sha3_manifest="${metadata_values[4]}"
libcrux_sha3_source="${metadata_values[5]}"
if [ "$resolved_version" != "$LIBCRUX_CRATE_VERSION" ]; then
  echo "resolved libcrux version mismatch: $resolved_version" >&2
  exit 2
fi
if [[ "$libcrux_source" != registry+* ]] ||
    [[ "$libcrux_sha3_source" != registry+* ]]; then
  echo "libcrux dependencies are not from registry sources" >&2
  exit 2
fi
libcrux_source_dir="$(dirname "$libcrux_manifest")"
libcrux_sha3_source_dir="$(dirname "$libcrux_sha3_manifest")"
if [ ! -d "$libcrux_source_dir/src" ] ||
    [ ! -d "$libcrux_sha3_source_dir/src" ]; then
  echo "resolved libcrux source directories are incomplete" >&2
  exit 2
fi
libcrux_checksum="$(python3 - "$project_dir/Cargo.lock" \
  "$LIBCRUX_CRATE_VERSION" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as handle:
    lock = tomllib.load(handle)
packages = [
    p for p in lock["package"]
    if p["name"] == "libcrux-ml-kem" and p["version"] == sys.argv[2]
]
if len(packages) != 1 or "checksum" not in packages[0]:
    raise SystemExit("missing unique libcrux checksum in Cargo.lock")
print(packages[0]["checksum"])
PY
)"

cache_pattern='(pk|public_key|matrix|hash)[[:alnum:]_]*cache'
cache_pattern+='|indcpa_enc_precomp|once_cell|lazy_static'
cache_scan_status=0
rg -n -i --glob '*.rs' "$cache_pattern" \
  "$libcrux_source_dir/src" "$libcrux_sha3_source_dir/src" \
  > "$cache_report" || cache_scan_status=$?
if [ "$cache_scan_status" -gt 1 ]; then
  echo "failed to audit libcrux comparator sources" >&2
  exit 2
fi
if [ -s "$cache_report" ]; then
  cat "$cache_report" >&2
  echo "persistent comparator cache detected; product build refused" >&2
  exit 2
fi

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
normalization_rustflags="-C codegen-units=1 -C debuginfo=0 -C panic=abort"
normalization_rustflags+=" --remap-path-prefix=$project_dir=/libcrux-product"
normalization_rustflags+=" --remap-path-prefix=$cargo_home=/cargo"
effective_rustflags="$RUSTFLAGS_BENCH $normalization_rustflags"
RUSTFLAGS="$effective_rustflags" \
LIBCRUX_ENABLE_SIMD256=1 \
LIBCRUX_DISABLE_SIMD256=0 \
CARGO_INCREMENTAL=0 \
CARGO_TARGET_DIR="$target_dir" \
  "$CARGO_BIN" build --manifest-path "$project_dir/Cargo.toml" \
    --release --locked --lib -j "$BUILD_JOBS" --quiet

archive="$target_dir/release/liblibcrux_mlkem_product.a"
if [ ! -f "$archive" ]; then
  echo "libcrux static product archive was not produced" >&2
  exit 2
fi
"$C_COMPILER" -r -nostdlib "$archive" -o "$work_dir/product.o" \
  -Wl,--gc-sections \
  -Wl,--undefined=goal_mlkem768_keypair_derand \
  -Wl,--undefined=goal_mlkem768_encaps_derand \
  -Wl,--undefined=goal_mlkem768_decaps
objcopy --strip-debug --remove-section=.note.gnu.build-id \
  "$work_dir/product.o" "$work_dir/product-stripped.o"

api_count="$(nm -g --defined-only "$work_dir/product-stripped.o" |
  awk '$3 ~ /^goal_mlkem768_/ { count++ } END { print count + 0 }')"
if [ "$api_count" -ne 3 ]; then
  echo "libcrux product must export exactly three goal APIs" >&2
  exit 2
fi
if readelf -Wr "$work_dir/product-stripped.o" |
    rg -ni 'getrandom|randombytes|rand_core|OsRng|ThreadRng|syscall|urandom'; then
  echo "reachable libcrux product code depends on an entropy source" >&2
  exit 2
fi
if nm "$work_dir/product-stripped.o" |
    rg -ni 'key_cache|public_key_cache|matrix_cache|hash_cache|once_cell|lazy_static'; then
  echo "reachable libcrux product retained persistent cache metadata" >&2
  exit 2
fi
if readelf -SW "$work_dir/product-stripped.o" |
    rg -n '\.note\.GNU-stack.* X '; then
  echo "libcrux product requests an executable stack" >&2
  exit 2
fi
if [ "$PROFILE" = "avx2" ]; then
  if objdump -d "$work_dir/product-stripped.o" | rg -n '%zmm|%k[0-7]' ||
      nm "$work_dir/product-stripped.o" | rg -ni 'avx512'; then
    echo "AVX512 code detected in libcrux AVX2-only product" >&2
    exit 2
  fi
  avx512_audit=pass
else
  avx512_audit=not-applicable
fi

"$C_COMPILER" -O2 -I"$ROOT_DIR/scripts" \
  "$ROOT_DIR/scripts/goal_size_adapter_test.c" \
  "$work_dir/product-stripped.o" -Wl,-z,noexecstack \
  -o "$work_dir/product_test"
"$work_dir/product_test"
mkdir -p "$(dirname "$OUTPUT")"
cp "$work_dir/product-stripped.o" "$OUTPUT"

printf "profile=%s\n" "$PROFILE"
printf "c_linker=%s\n" "$C_COMPILER"
printf "c_linker_version=%s\n" "$("$C_COMPILER" --version | sed -n '1p')"
printf "rustc_version=%s\n" "$(rustc --version)"
printf "cargo_version=%s\n" "$("$CARGO_BIN" --version)"
printf "libcrux_crate_version=%s\n" "$resolved_version"
printf "libcrux_crate_source=%s\n" "$libcrux_source"
printf "libcrux_crate_checksum=%s\n" "$libcrux_checksum"
printf "libcrux_sha3_version=%s\n" "$libcrux_sha3_version"
printf "libcrux_sha3_source=%s\n" "$libcrux_sha3_source"
printf "libcrux_lock_sha256=%s\n" \
  "$(sha256sum "$project_dir/Cargo.lock" | awk '{print $1}')"
printf "comparator_update=%s\n" "$comparator_update"
printf "latest_crate_version=%s\n" "$latest_version"
printf "latest_version_audit=%s\n" "$latest_version_audit"
printf "libcrux_enable_simd256=%s\n" "$LIBCRUX_ENABLE_SIMD256"
printf "rustflags_bench=%s\n" "$RUSTFLAGS_BENCH"
printf "normalization_rustflags=%s\n" "$normalization_rustflags"
printf "build_jobs=%s\n" "$BUILD_JOBS"
printf "api_count=%s\n" "$api_count"
printf "cache_audit=pass\n"
printf "reachable_entropy_audit=pass\n"
printf "noexec_stack_audit=pass\n"
printf "avx512_audit=%s\n" "$avx512_audit"
printf "correctness_smoke=pass\n"
REQUIRED_SYMBOLS="$REQUIRED_SYMBOLS" \
  "$ROOT_DIR/scripts/measure_elf_footprint.sh" "$OUTPUT"
