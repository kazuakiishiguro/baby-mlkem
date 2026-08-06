#!/usr/bin/env bash

GOAL_AVX2_FLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"

_goal_speed_cxx_for_compiler() {
  local compiler="$1"
  local compiler_name="${compiler##*/}"
  local compiler_dir
  local candidate

  if [[ "$compiler" == */* ]]; then
    compiler_dir="${compiler%/*}"
  else
    compiler_dir="$(dirname "$(command -v "$compiler")")"
  fi

  case "$compiler_name" in
    clang)
      candidate="$compiler_dir/clang++"
      ;;
    clang-*)
      candidate="$compiler_dir/clang++-${compiler_name#clang-}"
      ;;
    gcc)
      candidate="$compiler_dir/g++"
      ;;
    gcc-*)
      candidate="$compiler_dir/g++-${compiler_name#gcc-}"
      ;;
    *)
      if "$compiler" --version 2>/dev/null | head -n 1 | grep -qi clang; then
        candidate="$(command -v clang++ || true)"
      else
        candidate="$(command -v g++ || true)"
      fi
      ;;
  esac

  if [ -z "$candidate" ] || [ ! -x "$candidate" ]; then
    echo "matching C++ compiler not found for: $compiler" >&2
    return 2
  fi
  printf '%s\n' "$candidate"
}

_goal_speed_export_common() {
  local compiler="$1"
  local compiler_family
  local libstdcpp

  CXX_COMPILER="$(_goal_speed_cxx_for_compiler "$compiler")" || return
  if "$compiler" --version 2>/dev/null | head -n 1 | grep -qi clang; then
    compiler_family=clang
    BOTAN_CC_FAMILY=clang
  else
    compiler_family=gcc
    BOTAN_CC_FAMILY=gcc
  fi
  BOTAN_CXX="$CXX_COMPILER"
  BOTAN_ALLOW_COMPILER_FALLBACK=0
  GCC_INSTALL_DIR=""
  GOAL_CXX_STDLIB_FLAGS=""

  if [ "$compiler_family" = "clang" ]; then
    OPT_CFLAGS="-O3 -fno-semantic-interposition -fvisibility=hidden"
    EXTRA_CFLAGS="-fomit-frame-pointer -fno-stack-protector -falign-loops=64 -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-strict-aliasing"
    if ! printf '#include <cstddef>\n' |
        "$CXX_COMPILER" -x c++ -fsyntax-only - >/dev/null 2>&1; then
      if command -v g++ >/dev/null 2>&1; then
        libstdcpp="$(g++ -print-file-name=libstdc++.so)"
        if [ "$libstdcpp" != "libstdc++.so" ] && [ -f "$libstdcpp" ]; then
          GCC_INSTALL_DIR="$(dirname "$libstdcpp")"
        fi
      fi
      if [ -z "$GCC_INSTALL_DIR" ]; then
        echo "C++ standard library headers unavailable for $CXX_COMPILER" >&2
        return 2
      fi
      if ! printf '#include <cstddef>\n' |
          "$CXX_COMPILER" "--gcc-install-dir=$GCC_INSTALL_DIR" -x c++ -fsyntax-only - >/dev/null 2>&1; then
        echo "C++ standard library headers unavailable for $CXX_COMPILER" >&2
        return 2
      fi
      GOAL_CXX_STDLIB_FLAGS="--gcc-install-dir=$GCC_INSTALL_DIR"
    fi
  else
    OPT_CFLAGS="-O2 -flto -fno-semantic-interposition"
    EXTRA_CFLAGS="-funroll-loops -fomit-frame-pointer -fno-stack-protector -falign-loops=32 -finline-functions"
  fi
  ASFLAGS="-Wa,--noexecstack"
  MLKEM_NATIVE_AUTO=1
  LIBOQS_DIST_BUILD=OFF
  export CXX_COMPILER BOTAN_CXX BOTAN_CC_FAMILY
  export BOTAN_ALLOW_COMPILER_FALLBACK GCC_INSTALL_DIR GOAL_CXX_STDLIB_FLAGS
  export OPT_CFLAGS EXTRA_CFLAGS ASFLAGS MLKEM_NATIVE_AUTO LIBOQS_DIST_BUILD
}

goal_speed_configure_profile() {
  if [ "$#" -ne 2 ]; then
    echo "goal_speed_configure_profile expects: profile compiler" >&2
    return 2
  fi

  local profile="$1"
  local compiler="$2"
  local cflags

  _goal_speed_export_common "$compiler" || return
  case "$profile" in
    native)
      BENCH_ISA_PROFILE=native
      BENCH_PROFILE_TAG=goal-native
      ARCH_CFLAGS="-march=native"
      cflags="-march=native -mavx2 -mbmi2 -mpopcnt"
      MLKEM_NATIVE_CFLAGS="$cflags -maes"
      MLKEM_NATIVE_HARNESS_CFLAGS="-O3 $MLKEM_NATIVE_CFLAGS -fomit-frame-pointer -std=c99"
      UPSTREAM_CFLAGS="-O3 $cflags -fomit-frame-pointer -std=c99"
      FAIR_UPSTREAM_CFLAGS="$OPT_CFLAGS $cflags $EXTRA_CFLAGS -std=c99"
      PQCLEAN_CLEAN_CFLAGS="-O3 -march=native -std=c99"
      PQCLEAN_AVX2_CFLAGS="-mavx2 -mbmi2 -mpopcnt -O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -Wpointer-arith -Wshadow -std=c99 -I../../../common"
      PQCLEAN_HARNESS_CFLAGS="-O3 $cflags -std=c99"
      LIBOQS_OPT_TARGET=native
      LIBOQS_CFLAGS="-O3 -march=native"
      LIBOQS_HARNESS_CFLAGS="-O3 -march=native"
      BORINGSSL_C_FLAGS="-O3 -march=native"
      BORINGSSL_CXX_FLAGS="-O3 -march=native${GOAL_CXX_STDLIB_FLAGS:+ $GOAL_CXX_STDLIB_FLAGS}"
      BORINGSSL_HARNESS_FLAGS="-O3 -march=native"
      RUSTFLAGS_BENCH="-C target-cpu=native -C codegen-units=1"
      LIBJADE_HARNESS_CFLAGS="-D_GNU_SOURCE -O3 $cflags -fomit-frame-pointer -std=c99"
      BOTAN_CXXFLAGS="-O3 $cflags -fomit-frame-pointer -fno-semantic-interposition${GOAL_CXX_STDLIB_FLAGS:+ $GOAL_CXX_STDLIB_FLAGS}"
      BOTAN_DISABLED_MODULES=""
      BOTAN_HARNESS_CXXFLAGS="-O3 -march=native${GOAL_CXX_STDLIB_FLAGS:+ $GOAL_CXX_STDLIB_FLAGS}"
      OPENSSL_CFLAGS="-O3 -fno-semantic-interposition $cflags"
      OPENSSL_HARNESS_CFLAGS="-O3 -march=native"
      OPENSSL_IA32CAP=""
      ;;
    avx2)
      BENCH_ISA_PROFILE=avx2
      BENCH_PROFILE_TAG=goal-avx2
      ARCH_CFLAGS="$GOAL_AVX2_FLAGS"
      cflags="$GOAL_AVX2_FLAGS"
      MLKEM_NATIVE_CFLAGS="$cflags -maes"
      MLKEM_NATIVE_HARNESS_CFLAGS="-O3 $MLKEM_NATIVE_CFLAGS -fomit-frame-pointer -std=c99"
      UPSTREAM_CFLAGS="-O3 $cflags -fomit-frame-pointer -std=c99"
      FAIR_UPSTREAM_CFLAGS="$OPT_CFLAGS $cflags $EXTRA_CFLAGS -std=c99"
      PQCLEAN_CLEAN_CFLAGS="-O3 $cflags -std=c99"
      PQCLEAN_AVX2_CFLAGS="$cflags -O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -Wpointer-arith -Wshadow -std=c99 -I../../../common"
      PQCLEAN_HARNESS_CFLAGS="-O3 $cflags -std=c99"
      LIBOQS_OPT_TARGET=x86-64-v3
      LIBOQS_CFLAGS="-O3 $cflags"
      LIBOQS_HARNESS_CFLAGS="-O3 $cflags"
      BORINGSSL_C_FLAGS="-O3 $cflags"
      BORINGSSL_CXX_FLAGS="-O3 $cflags${GOAL_CXX_STDLIB_FLAGS:+ $GOAL_CXX_STDLIB_FLAGS}"
      BORINGSSL_HARNESS_FLAGS="-O3 $cflags"
      RUSTFLAGS_BENCH="-C target-cpu=x86-64-v3 -C codegen-units=1"
      LIBJADE_HARNESS_CFLAGS="-D_GNU_SOURCE -O3 $cflags -fomit-frame-pointer -std=c99"
      BOTAN_CXXFLAGS="-O3 $cflags -fomit-frame-pointer -fno-semantic-interposition${GOAL_CXX_STDLIB_FLAGS:+ $GOAL_CXX_STDLIB_FLAGS}"
      BOTAN_DISABLED_MODULES=keccak_perm_avx512
      BOTAN_HARNESS_CXXFLAGS="-O3 $cflags${GOAL_CXX_STDLIB_FLAGS:+ $GOAL_CXX_STDLIB_FLAGS}"
      OPENSSL_CFLAGS="-O3 -fno-semantic-interposition $cflags"
      OPENSSL_HARNESS_CFLAGS="-O3 $cflags"
      OPENSSL_IA32CAP=":~0x10000"
      ;;
    *)
      echo "unsupported goal speed profile: $profile (expected native|avx2)" >&2
      return 2
      ;;
  esac

  export BENCH_ISA_PROFILE BENCH_PROFILE_TAG ARCH_CFLAGS
  export MLKEM_NATIVE_CFLAGS MLKEM_NATIVE_HARNESS_CFLAGS UPSTREAM_CFLAGS FAIR_UPSTREAM_CFLAGS
  export PQCLEAN_CLEAN_CFLAGS PQCLEAN_AVX2_CFLAGS PQCLEAN_HARNESS_CFLAGS
  export LIBOQS_OPT_TARGET LIBOQS_CFLAGS LIBOQS_HARNESS_CFLAGS
  export BORINGSSL_C_FLAGS BORINGSSL_CXX_FLAGS BORINGSSL_HARNESS_FLAGS
  export RUSTFLAGS_BENCH LIBJADE_HARNESS_CFLAGS
  export BOTAN_CXXFLAGS BOTAN_DISABLED_MODULES BOTAN_HARNESS_CXXFLAGS
  export OPENSSL_CFLAGS OPENSSL_HARNESS_CFLAGS OPENSSL_IA32CAP
}

goal_speed_print_profile() {
  local key
  local -a keys=(
    BENCH_ISA_PROFILE BENCH_PROFILE_TAG CXX_COMPILER GCC_INSTALL_DIR
    GOAL_CXX_STDLIB_FLAGS OPT_CFLAGS EXTRA_CFLAGS ARCH_CFLAGS ASFLAGS
    MLKEM_NATIVE_AUTO MLKEM_NATIVE_CFLAGS MLKEM_NATIVE_HARNESS_CFLAGS UPSTREAM_CFLAGS
    FAIR_UPSTREAM_CFLAGS PQCLEAN_CLEAN_CFLAGS PQCLEAN_AVX2_CFLAGS
    PQCLEAN_HARNESS_CFLAGS LIBOQS_DIST_BUILD LIBOQS_OPT_TARGET
    LIBOQS_CFLAGS LIBOQS_HARNESS_CFLAGS BORINGSSL_C_FLAGS
    BORINGSSL_CXX_FLAGS BORINGSSL_HARNESS_FLAGS RUSTFLAGS_BENCH
    LIBJADE_HARNESS_CFLAGS BOTAN_CXX BOTAN_CC_FAMILY
    BOTAN_ALLOW_COMPILER_FALLBACK BOTAN_CXXFLAGS BOTAN_DISABLED_MODULES
    BOTAN_HARNESS_CXXFLAGS OPENSSL_CFLAGS OPENSSL_HARNESS_CFLAGS
    OPENSSL_IA32CAP
  )
  for key in "${keys[@]}"; do
    printf '%s=%s\n' "$key" "${!key}"
  done
}
