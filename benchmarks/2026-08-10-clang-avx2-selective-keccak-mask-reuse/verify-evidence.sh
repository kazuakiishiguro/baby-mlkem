#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$REPORT_DIR/../.." && pwd)"
EXPECTED_BASELINE=a75152c5f4502528809633747b2502a4b0cfeadc83daa428f92ddb4e3f86738f
EXPECTED_CANDIDATE=668bc7877907af53e849dcf85693f15600142c9f6a7ed965d39a094548bcf98c
EXPECTED_BASELINE_REF=df1501ffb2efb6cfbc8563b4a7e0d8d93960feec
EXPECTED_CANDIDATE_REF=424a14181f08559e55749be5f9eb4601d94f7252
EXPECTED_CORPUS=e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67

pass() {
  printf '%s=PASS\n' "$1"
}

require_line() {
  local label="$1" pattern="$2" file="$3"
  rg -q -- "$pattern" "$REPORT_DIR/$file"
  pass "$label"
}

recalculate_batch() {
  local file="$1"
  local operations=(keygen encaps decaps roundtrip)
  local baseline_columns=(3 5 7 9)
  local candidate_columns=(4 6 8 10)
  local index operation calculated recorded rows

  rows="$(awk '/^[0-9][0-9] / {count++} END {print count + 0}' "$file")"
  [[ "$rows" -eq 16 ]]
  for index in "${!operations[@]}"; do
    operation="${operations[$index]}"
    calculated="$(awk -v b="${baseline_columns[$index]}" \
      -v c="${candidate_columns[$index]}" \
      '/^[0-9][0-9] / {sum += log($b / $c); count++}
       END {printf "%.9f", exp(sum / count)}' "$file")"
    recorded="$(sed -n "s/^${operation}_gmean=\([0-9.]*\)x$/\1/p" \
      "$file")"
    [[ "$calculated" = "$recorded" ]]
  done
  awk '/^[0-9][0-9] / {
    expected = ($1 % 2) ? "candidate-first" : "baseline-first"
    if ($2 != expected) exit 1
  }' "$file"
}

(cd "$REPORT_DIR" && sha256sum -c checksums.sha256 >/dev/null)
pass checksums

require_line baseline_hash "^artifact_sha256=$EXPECTED_BASELINE$" size-baseline.txt
require_line baseline_size '^primary_bytes=48210$' size-baseline.txt
require_line candidate_hash "^artifact_sha256=$EXPECTED_CANDIDATE$" size-candidate.txt
require_line candidate_code '^code_bytes=42191$' size-candidate.txt
require_line candidate_readonly '^readonly_data_bytes=5955$' size-candidate.txt
require_line candidate_size '^primary_bytes=48146$' size-candidate.txt
require_line candidate_writable '^writable_bytes=26593$' size-candidate.txt
require_line size_delta '^primary_bytes 48210 48146 -64$' section-accounting.txt
require_line cst32_delta \
  '^section=\.rodata\.cst32 baseline_bytes=3040 candidate_bytes=2912 delta=-128$' \
  section-accounting.txt
require_line shared_section \
  '^section=\.rodata\.MLKEM_AVX2_SHARED_CONSTANTS baseline_bytes=0 candidate_bytes=64 delta=\+64$' \
  section-accounting.txt
require_line text_identity '^text_section_raw_bytes_identical=PASS$' section-accounting.txt
require_line section_gate '^section_isolation=PASS$' section-accounting.txt
cmp "$REPORT_DIR/text-sections-baseline.sha256" \
  "$REPORT_DIR/text-sections-candidate.sha256"
[[ "$(wc -l < "$REPORT_DIR/text-sections-candidate.sha256")" -eq 23 ]]
pass recorded_text_identity

sample_rows=0
for batch in {1..3}; do
  file="$REPORT_DIR/product-ab-batch${batch}-16x100k.txt"
  recalculate_batch "$file"
  rg -q "^baseline_product_sha256=$EXPECTED_BASELINE$" "$file"
  rg -q "^candidate_product_sha256=$EXPECTED_CANDIDATE$" "$file"
  rg -q '^normal_core_alias_check=PASS$' "$file"
  sample_rows=$((sample_rows + 16))
done
[[ "$sample_rows" -eq 48 ]]
[[ "$(rg -l '^regression_gate=FAIL$' \
  "$REPORT_DIR"/product-ab-batch*-16x100k.txt | wc -l)" -eq 3 ]]
pass product_batch_recalculation
pass product_batch_failures_retained

operations=(keygen encaps decaps roundtrip)
baseline_columns=(3 5 7 9)
candidate_columns=(4 6 8 10)
for index in "${!operations[@]}"; do
  operation="${operations[$index]}"
  calculated="$(awk -v b="${baseline_columns[$index]}" \
    -v c="${candidate_columns[$index]}" \
    '/^[0-9][0-9] / {sum += log($b / $c); count++}
     END {printf "%.9f", exp(sum / count)}' \
    "$REPORT_DIR"/product-ab-batch*-16x100k.txt)"
  recorded="$(sed -n "s/^${operation}_gmean=\([0-9.]*\)x$/\1/p" \
    "$REPORT_DIR/product-ab-combined-48x100k.txt")"
  [[ "$calculated" = "$recorded" ]]
done
[[ "$(awk '/^[123] [0-9][0-9] / {count++} END {print count + 0}' \
  "$REPORT_DIR/product-ab-combined-48x100k.txt")" -eq 48 ]]
require_line combined_minimum '^minimum_ratio=0\.996360694x$' \
  product-ab-combined-48x100k.txt
require_line combined_gate '^regression_gate=PASS$' \
  product-ab-combined-48x100k.txt
require_line no_speed_credit '^speed_credit=NONE_text_sections_byte_identical$' \
  product-ab-combined-48x100k.txt
pass product_combined_recalculation

matrix_rows="$(awk '/^(clang|gcc)-(native|avx2|scalar) status=PASS/ {count++}
  END {print count + 0}' "$REPORT_DIR/correctness-matrix.txt")"
[[ "$matrix_rows" -eq 6 ]]
require_line matrix_gate '^validation_matrix=PASS$' correctness-matrix.txt
require_line nontarget_identity '^non_target_product_identity=5/5$' \
  correctness-matrix.txt
for entry in \
  'size-clang-native.txt:^primary_bytes=69611$' \
  'size-clang-avx2.txt:^primary_bytes=48146$' \
  'size-clang-scalar.txt:^primary_bytes=62098$' \
  'size-gcc-native.txt:^primary_bytes=59148$' \
  'size-gcc-avx2.txt:^primary_bytes=53443$' \
  'size-gcc-scalar.txt:^primary_bytes=22994$'; do
  file="${entry%%:*}"
  pattern="${entry#*:}"
  rg -q -- "$pattern" "$REPORT_DIR/$file"
done
pass size_matrix

corpus_rows="$(rg -c '^cross_path_corpus=' "$REPORT_DIR/cross-path-corpus.txt")"
[[ "$corpus_rows" -eq 16 ]]
require_line corpus_hash "^cross_path_corpus_sha256=$EXPECTED_CORPUS$" \
  cross-path-corpus.txt
require_line sanitizer_gate '^sanitizer_gate=PASS$' sanitizers.txt
! rg -n 'ERROR: AddressSanitizer|runtime error:|UndefinedBehaviorSanitizer' \
  "$REPORT_DIR"/sanitizer-*.txt
require_line stack_gate '^maximum_stack_nonincrease=PASS$' stack.txt
require_line abi_gate '^abi_isa_audit=PASS$' abi-audit.txt
require_line postcommit_gate '^postcommit_reproduction=PASS$' postcommit-smoke.txt
require_line source_gate '^source_isolation=PASS$' source-audit.txt
require_line broad_rejected '^screen_gate=FAIL$' rejected-candidates.txt
require_line selective_accepted '^status=ACCEPTED$' rejected-candidates.txt

cmp "$REPORT_DIR/undefined-symbols-baseline.txt" \
  "$REPORT_DIR/undefined-symbols-candidate.txt"
[[ -z "$(comm -23 "$REPORT_DIR/defined-symbols-baseline.txt" \
  "$REPORT_DIR/defined-symbols-candidate.txt")" ]]
expected_symbols=$'R MLKEM_AVX2_ROTL64_56_MASK\nR MLKEM_AVX2_ROTL64_8_MASK'
[[ "$(comm -13 "$REPORT_DIR/defined-symbols-baseline.txt" \
  "$REPORT_DIR/defined-symbols-candidate.txt")" = "$expected_symbols" ]]
pass recorded_symbol_audit

git -C "$ROOT_DIR" cat-file -e "$EXPECTED_BASELINE_REF^{commit}"
git -C "$ROOT_DIR" cat-file -e "$EXPECTED_CANDIDATE_REF^{commit}"
changed_files="$(git -C "$ROOT_DIR" diff-tree --no-commit-id --name-only -r \
  "$EXPECTED_CANDIDATE_REF" | sort)"
expected_files=$'avx2_shared_constants.S\nbaby-mlkem.c\nMakefile'
[[ "$changed_files" = "$expected_files" ]]
git -C "$ROOT_DIR" show "$EXPECTED_CANDIDATE_REF:avx2_shared_constants.S" |
  rg -q '^\.hidden MLKEM_AVX2_ROTL64_8_MASK$'
git -C "$ROOT_DIR" show "$EXPECTED_CANDIDATE_REF:avx2_shared_constants.S" |
  rg -q '^\.hidden MLKEM_AVX2_ROTL64_56_MASK$'
pass committed_source_audit

tmp_dir="$(mktemp -d /tmp/baby-mlkem-selective-mask-evidence.XXXXXX)"
mkdir "$tmp_dir/baseline" "$tmp_dir/candidate"
git -C "$ROOT_DIR" archive "$EXPECTED_BASELINE_REF" |
  tar -x -C "$tmp_dir/baseline"
git -C "$ROOT_DIR" archive "$EXPECTED_CANDIDATE_REF" |
  tar -x -C "$tmp_dir/candidate"
flags='-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f'
make -s -j8 -C "$tmp_dir/baseline" CC=clang ARCH_CFLAGS="$flags" \
  baby_mlkem768_product.o >"$tmp_dir/baseline-build.txt" 2>&1
make -s -j8 -C "$tmp_dir/candidate" CC=clang ARCH_CFLAGS="$flags" \
  test test-product >"$tmp_dir/candidate-build.txt" 2>&1
make -s -C "$tmp_dir/candidate" CC=clang ARCH_CFLAGS="$flags" \
  check-ntt-roots >"$tmp_dir/generator-check.txt" 2>&1
base="$tmp_dir/baseline/baby_mlkem768_product.o"
cand="$tmp_dir/candidate/baby_mlkem768_product.o"
[[ "$(sha256sum "$base" | awk '{print $1}')" = "$EXPECTED_BASELINE" ]]
[[ "$(sha256sum "$cand" | awk '{print $1}')" = "$EXPECTED_CANDIDATE" ]]
base_size="$($ROOT_DIR/scripts/measure_product_size.sh "$base")"
cand_size="$($ROOT_DIR/scripts/measure_product_size.sh "$cand")"
[[ "$(sed -n 's/^primary_bytes=//p' <<<"$base_size")" -eq 48210 ]]
[[ "$(sed -n 's/^primary_bytes=//p' <<<"$cand_size")" -eq 48146 ]]
pass clean_product_reproduction

objdump -h "$base" | awk '$2 ~ /^\.text/ {print $2}' > "$tmp_dir/base-text.txt"
objdump -h "$cand" | awk '$2 ~ /^\.text/ {print $2}' > "$tmp_dir/cand-text.txt"
cmp "$tmp_dir/base-text.txt" "$tmp_dir/cand-text.txt"
mkdir "$tmp_dir/base-text" "$tmp_dir/cand-text"
i=0
while IFS= read -r section; do
  i=$((i + 1))
  objcopy --dump-section "$section=$tmp_dir/base-text/$i.bin" "$base"
  objcopy --dump-section "$section=$tmp_dir/cand-text/$i.bin" "$cand"
  cmp "$tmp_dir/base-text/$i.bin" "$tmp_dir/cand-text/$i.bin"
done < "$tmp_dir/base-text.txt"
[[ "$i" -eq 23 ]]
[[ "$(readelf -rW "$cand" | rg -c 'MLKEM_AVX2_ROTL64_8_MASK')" -eq 2 ]]
[[ "$(readelf -rW "$cand" | rg -c 'MLKEM_AVX2_ROTL64_56_MASK')" -eq 2 ]]
cmp <(nm -u "$base" | sed 's/^[[:space:]]*//' | sort) \
  <(nm -u "$cand" | sed 's/^[[:space:]]*//' | sort)
! objdump -d "$cand" | rg -q '\b%?zmm[0-9]+\b|\b%?k[0-7]\b'
! readelf -SW "$cand" | rg -q '\.note\.GNU-stack.* X '
pass live_text_symbol_isa_audit

while IFS= read -r target; do
  [[ -z "$target" || "$target" =~ ^https?:// ]] && continue
  [[ -e "$REPORT_DIR/$target" ]]
done < <(rg -o '\]\([^)]+\)' "$REPORT_DIR/README.md" |
  sed 's/^](//; s/)$//; s/#.*$//' | sort -u)
pass report_links

rg -q 'benchmarks/2026-08-10-clang-avx2-selective-keccak-mask-reuse/README.md' \
  "$ROOT_DIR/README.md"
rg -q '\| AVX2-only \| Clang 18\.1\.3 \| 42,191 \| 5,955 \| 48,146 \|' \
  "$ROOT_DIR/README.md"
rg -q '3,097 bytes larger than OpenSSL AVX2-only' "$ROOT_DIR/README.md"
pass root_readme

printf 'evidence_gate=PASS\n'
