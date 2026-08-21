# Current mlkem-native production-size gate

This directory records the exact primary-size comparison for baby-mlkem at
code commit `d5e58a82e49d4853c7e66148e451740c708c2afe` against the same current
`mlkem-native` source used by the 2026-08-22 speed gates.

## Results

| Profile | baby-mlkem primary | mlkem-native primary | Difference | Max stack | Gate |
|---|---:|---:|---:|---:|---|
| Clang native | 53,163 B | 51,186 B | +1,977 B | 8,056 B vs 20,448 B | FAIL |
| Clang AVX2-only | 45,032 B | 51,267 B | -6,235 B | 4,512 B vs 21,120 B | PASS |

The native gate is still open because the local primary artifact exceeds the
current mlkem-native artifact by 1,977 bytes. The AVX2-only primary and stack
gates pass. These reports cover the exact mlkem-native comparator; they do not
replace the full ten-comparator size matrix.

## Method and provenance

- baby-mlkem commit: `d5e58a82e49d4853c7e66148e451740c708c2afe`
- mlkem-native commit: `69d24e37b8a04c6050ec55bc84a4228d7051bb4b`
- mlkem-native remote: `https://github.com/pq-code-package/mlkem-native.git`
- compiler: Ubuntu Clang 18.1.3
- native ISA: `-march=native`
- AVX2 ISA: `-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f`
- stack probe: 8 runs on a 1 MiB guarded alternate stack
- correctness smoke: pass for both profiles
- comparator cache and reachable-randomness audits: pass

The comparator is used only for measurement and is not linked into the
baby-mlkem production artifact.

## Files and hashes

| File | SHA-256 |
|---|---|
| `native-mlkem-native.txt` | `773c9af3dd9408138ad0fe3e830aa04c58647e519702fa9154a01a536ac7598c` |
| `avx2-mlkem-native.txt` | `1bce2d7aa485d6f3ff8d63a82f3d52ac5fe7b1ae1e327e7a5a94c97b4f6fe79e` |

## Reproduction

```bash
PROFILE=native COMPARATOR=mlkem-native UPDATE_REPOS=0 \
  MLKEM_NATIVE_AUTO=0 MLKEM_NATIVE_DIR=/path/to/mlkem-native \
  C_COMPILER=clang STACK_RUNS=8 \
  ./scripts/verify_goal_comparator_size.sh

PROFILE=avx2 COMPARATOR=mlkem-native UPDATE_REPOS=0 \
  MLKEM_NATIVE_AUTO=0 MLKEM_NATIVE_DIR=/path/to/mlkem-native \
  C_COMPILER=clang STACK_RUNS=8 \
  ./scripts/verify_goal_comparator_size.sh
```
