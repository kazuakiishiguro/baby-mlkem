#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ITERS="${1:-2000}"
LIBCRUX_BENCH_DIR="${LIBCRUX_BENCH_DIR:-/tmp/libcrux-mlkem-bench}"
LIBCRUX_CRATE_VERSION="${LIBCRUX_CRATE_VERSION:-0.0.8}"
UPDATE_REPOS="${UPDATE_REPOS:-0}"
PIN_CPU="${PIN_CPU:-}"
if [ -n "${C_COMPILER:-}" ]; then
  C_COMPILER="$C_COMPILER"
elif command -v clang >/dev/null 2>&1; then
  C_COMPILER="clang"
else
  C_COMPILER="gcc"
fi
SKIP_LOCAL_BUILD="${SKIP_LOCAL_BUILD:-0}"
LOCAL_BENCH_BIN="${LOCAL_BENCH_BIN:-$ROOT_DIR/benchc}"
CARGO_BIN="${CARGO_BIN:-cargo}"
RUSTFLAGS_BENCH="${RUSTFLAGS_BENCH:--C target-cpu=native -C codegen-units=1}"
LIBCRUX_ENABLE_SIMD256="${LIBCRUX_ENABLE_SIMD256:-1}"
LOCAL_ROUNDTRIP_METRIC="${LOCAL_ROUNDTRIP_METRIC:-mlkem_roundtrip_ns_per_op}"
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-libcrux.XXXXXX)"
BENCH_LOCK_FILE="${BENCH_LOCK_FILE:-$ROOT_DIR/.bench-compare.lock}"
CLEAN_LOCAL_BUILD_ARTIFACTS="${CLEAN_LOCAL_BUILD_ARTIFACTS:-1}"
LOCAL_BUILD_DONE=0

cleanup() {
  rm -rf "$WORK_DIR"
  if [ "$CLEAN_LOCAL_BUILD_ARTIFACTS" = "1" ] && [ "$LOCAL_BUILD_DONE" = "1" ]; then
    make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

RUNNER=()
if [ -n "$PIN_CPU" ]; then
  if ! command -v taskset >/dev/null 2>&1; then
    echo "taskset not found but PIN_CPU was set" >&2
    exit 1
  fi
  RUNNER=(taskset -c "$PIN_CPU")
fi

if ! command -v "$C_COMPILER" >/dev/null 2>&1; then
  echo "compiler not found: $C_COMPILER" >&2
  exit 1
fi
if ! command -v "$CARGO_BIN" >/dev/null 2>&1; then
  echo "cargo not found: $CARGO_BIN" >&2
  exit 1
fi

if command -v flock >/dev/null 2>&1; then
  exec 9>"$BENCH_LOCK_FILE"
  if ! flock -n 9; then
    echo "waiting_for_bench_lock=$BENCH_LOCK_FILE" >&2
    flock 9
  fi
else
  echo "warning: flock not found; running without benchmark lock" >&2
fi

mkdir -p "$LIBCRUX_BENCH_DIR/src"
cat > "$LIBCRUX_BENCH_DIR/Cargo.toml" <<EOF
[package]
name = "libcrux_mlkem_bench"
version = "0.1.0"
edition = "2021"

[dependencies]
libcrux-ml-kem = "${LIBCRUX_CRATE_VERSION}"

[profile.release]
lto = "fat"
codegen-units = 1
panic = "abort"
strip = true
EOF

cat > "$LIBCRUX_BENCH_DIR/src/main.rs" <<'RUST_EOF'
use libcrux_ml_kem::mlkem768;
use std::hint::black_box;
use std::process::ExitCode;
use std::time::Instant;

fn fill_seed(seed: &mut [u8], counter: u64) {
    let mut x = counter
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0xD1B5_4A32_D192_ED03);
    for b in seed.iter_mut() {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        *b = x as u8;
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    }
}

fn parse_iters() -> Result<usize, String> {
    let mut args = std::env::args();
    let _prog = args.next();
    match args.next() {
        None => Ok(2000),
        Some(v) => v
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| "invalid iteration count".to_string()),
    }
}

fn main() -> ExitCode {
    let iters = match parse_iters() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };

    let mut kp_seed = [0u8; 64];
    let mut enc_seed = [0u8; 32];

    for i in 0..16usize {
        fill_seed(&mut kp_seed, (i as u64) * 2 + 1);
        fill_seed(&mut enc_seed, (i as u64) * 2 + 2);
        let kp = mlkem768::avx2::generate_key_pair(kp_seed);
        let (ct, ss1) = mlkem768::avx2::encapsulate(kp.public_key(), enc_seed);
        let ss2 = mlkem768::avx2::decapsulate(kp.private_key(), &ct);
        if ss1 != ss2 {
            eprintln!("warmup mismatch at {}", i);
            return ExitCode::from(1);
        }
    }

    let t0 = Instant::now();
    for i in 0..iters {
        fill_seed(&mut kp_seed, (i as u64) + 11);
        let kp = mlkem768::avx2::generate_key_pair(black_box(kp_seed));
        black_box(kp);
    }
    let keygen_ns = t0.elapsed().as_nanos() as f64;

    fill_seed(&mut kp_seed, 101);
    let kp_fixed = mlkem768::avx2::generate_key_pair(kp_seed);

    let t0 = Instant::now();
    for i in 0..iters {
        fill_seed(&mut enc_seed, (i as u64) + 2000);
        let (ct, ss) = mlkem768::avx2::encapsulate(kp_fixed.public_key(), black_box(enc_seed));
        black_box(ct);
        black_box(ss);
    }
    let encaps_ns = t0.elapsed().as_nanos() as f64;

    let mut cts = Vec::with_capacity(iters);
    let mut shared = Vec::with_capacity(iters);
    for i in 0..iters {
        fill_seed(&mut enc_seed, (i as u64) + 4000);
        let (ct, ss) = mlkem768::avx2::encapsulate(kp_fixed.public_key(), enc_seed);
        cts.push(ct);
        shared.push(ss);
    }

    let t0 = Instant::now();
    for i in 0..iters {
        let ss2 = mlkem768::avx2::decapsulate(kp_fixed.private_key(), &cts[i]);
        if ss2 != shared[i] {
            eprintln!("decaps mismatch at {}", i);
            return ExitCode::from(1);
        }
    }
    let decaps_ns = t0.elapsed().as_nanos() as f64;

    let t0 = Instant::now();
    for i in 0..iters {
        fill_seed(&mut kp_seed, (i as u64) * 2 + 7001);
        fill_seed(&mut enc_seed, (i as u64) * 2 + 7002);
        let kp = mlkem768::avx2::generate_key_pair(kp_seed);
        let (ct, ss1) = mlkem768::avx2::encapsulate(kp.public_key(), enc_seed);
        let ss2 = mlkem768::avx2::decapsulate(kp.private_key(), &ct);
        if ss1 != ss2 {
            eprintln!("roundtrip mismatch at {}", i);
            return ExitCode::from(1);
        }
    }
    let roundtrip_ns = t0.elapsed().as_nanos() as f64;

    let denom = iters as f64;
    println!("libcrux_mlkem768_iterations={iters}");
    println!("libcrux_mlkem768_keygen_ns_per_op={:.2}", keygen_ns / denom);
    println!("libcrux_mlkem768_encaps_ns_per_op={:.2}", encaps_ns / denom);
    println!("libcrux_mlkem768_decaps_ns_per_op={:.2}", decaps_ns / denom);
    println!("libcrux_mlkem768_roundtrip_ns_per_op={:.2}", roundtrip_ns / denom);

    ExitCode::SUCCESS
}
RUST_EOF

if [ "$UPDATE_REPOS" = "1" ]; then
  if ! "$CARGO_BIN" update --manifest-path "$LIBCRUX_BENCH_DIR/Cargo.toml" >/dev/null; then
    echo "warning: cargo update failed for libcrux bench project" >&2
  fi
fi

echo "[1/4] Building local benchmark"
echo "local_AVX2_BACKEND=${AVX2_BACKEND:-core (Makefile default)}"
echo "local_roundtrip_metric=${LOCAL_ROUNDTRIP_METRIC}"
echo "pin_cpu=${PIN_CPU:-<unset>}"
echo "c_compiler=${C_COMPILER}"
echo "update_repos=${UPDATE_REPOS}"
echo "libcrux_bench_dir=${LIBCRUX_BENCH_DIR}"
echo "libcrux_crate_version=${LIBCRUX_CRATE_VERSION}"
echo "libcrux_enable_simd256=${LIBCRUX_ENABLE_SIMD256}"
echo "rustflags_bench=${RUSTFLAGS_BENCH}"
echo "skip_local_build=${SKIP_LOCAL_BUILD}"
if [ "$SKIP_LOCAL_BUILD" = "0" ]; then
  make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null
  make -C "$ROOT_DIR" bench CC="$C_COMPILER" >/dev/null
  LOCAL_BUILD_DONE=1
else
  if [ ! -x "$LOCAL_BENCH_BIN" ]; then
    echo "LOCAL_BENCH_BIN is not executable: $LOCAL_BENCH_BIN" >&2
    exit 1
  fi
fi
LOCAL_OUT="$("${RUNNER[@]}" "$LOCAL_BENCH_BIN" "$ITERS")"

echo "[2/4] Building libcrux benchmark harness"
(
  cd "$LIBCRUX_BENCH_DIR"
  RUSTFLAGS="$RUSTFLAGS_BENCH" \
  LIBCRUX_ENABLE_SIMD256="$LIBCRUX_ENABLE_SIMD256" \
  CARGO_TARGET_DIR="$LIBCRUX_BENCH_DIR/target" \
  "$CARGO_BIN" build --release --quiet
)

echo "[3/4] Running libcrux benchmark harness"
LIBCRUX_BIN="$LIBCRUX_BENCH_DIR/target/release/libcrux_mlkem_bench"
if [ ! -x "$LIBCRUX_BIN" ]; then
  echo "libcrux benchmark binary missing: $LIBCRUX_BIN" >&2
  exit 1
fi
LIBCRUX_OUT="$("${RUNNER[@]}" "$LIBCRUX_BIN" "$ITERS")"

echo "[4/4] Results"
echo "--- local (baby-mlkem) ---"
echo "$LOCAL_OUT"
echo "--- libcrux ml-kem-768 ---"
echo "$LIBCRUX_OUT"

local_rt="$(echo "$LOCAL_OUT" | awk -F= -v metric="$LOCAL_ROUNDTRIP_METRIC" '$1 == metric {print $2; exit}')"
libcrux_rt="$(echo "$LIBCRUX_OUT" | awk -F= '/libcrux_mlkem768_roundtrip_ns_per_op/{print $2}')"

if [ -n "$local_rt" ] && [ -n "$libcrux_rt" ]; then
  awk -v l="$local_rt" -v c="$libcrux_rt" 'BEGIN {
    printf("local_vs_libcrux_speedup=%.3fx\n", c / l);
  }'
fi
