#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$REPORT_DIR/../.." && pwd)"
EXPECTED_BASELINE=668bc7877907af53e849dcf85693f15600142c9f6a7ed965d39a094548bcf98c
EXPECTED_CANDIDATE=bdf2c0a541ff857137991666d08f904e9952664fdf192ad75053aa60502f3a8d
EXPECTED_BASELINE_REF=424a14181f08559e55749be5f9eb4601d94f7252
EXPECTED_CANDIDATE_REF=8fab80d9cd14556fd5514f56fd1d8b7bdeca98e8
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
require_line baseline_code '^code_bytes=42191$' size-baseline.txt
require_line baseline_readonly '^readonly_data_bytes=5955$' size-baseline.txt
require_line baseline_size '^primary_bytes=48146$' size-baseline.txt
require_line candidate_hash "^artifact_sha256=$EXPECTED_CANDIDATE$" size-candidate.txt
require_line candidate_code '^code_bytes=41546$' size-candidate.txt
require_line candidate_readonly '^readonly_data_bytes=5955$' size-candidate.txt
require_line candidate_size '^primary_bytes=47501$' size-candidate.txt
require_line candidate_writable '^writable_bytes=26593$' size-candidate.txt
require_line size_delta '^primary_bytes 48146 47501 -645$' section-accounting.txt
require_line finish_delta \
  '^section=\.text\.kpke_encrypt_finish_avx2 baseline_bytes=3841 candidate_bytes=3196 delta=-645 status=changed$' \
  section-accounting.txt
require_line changed_text_count '^changed_text_sections=1$' section-accounting.txt
require_line unchanged_text_count '^unchanged_text_sections=22$' section-accounting.txt
require_line changed_readonly_count '^changed_readonly_sections=1$' \
  section-accounting.txt
require_line unchanged_readonly_count '^unchanged_readonly_sections=13$' \
  section-accounting.txt
require_line changed_readonly '^changed_readonly_section=\.rodata$' \
  section-accounting.txt
require_line rodata_delta \
  '^section=\.rodata baseline_bytes=115 candidate_bytes=115 delta=\+0 status=compiler_pool_reordered$' \
  section-accounting.txt
require_line rodata_diff_bytes '^rodata_differing_bytes=12$' section-accounting.txt
require_line rodata_multiset '^rodata_permuted_u16_multiset_identical=PASS$' \
  section-accounting.txt
require_line readonly_size_identity '^readonly_data_size_unchanged=PASS$' \
  section-accounting.txt
require_line section_gate '^section_isolation=PASS$' section-accounting.txt

[[ "$(wc -l < "$REPORT_DIR/text-sections-baseline.sha256")" -eq 23 ]]
[[ "$(wc -l < "$REPORT_DIR/text-sections-candidate.sha256")" -eq 23 ]]
manifest_diff="$(diff -u "$REPORT_DIR/text-sections-baseline.sha256" \
  "$REPORT_DIR/text-sections-candidate.sha256" || true)"
[[ "$(rg -c '^[+-][0-9a-f]{64}  \.text\.' <<<"$manifest_diff")" -eq 2 ]]
[[ "$(rg -c '^[+-][0-9a-f]{64}  \.text\.kpke_encrypt_finish_avx2$' \
  <<<"$manifest_diff")" -eq 2 ]]
pass recorded_text_isolation

[[ "$(wc -l < "$REPORT_DIR/readonly-sections-baseline.sha256")" -eq 14 ]]
[[ "$(wc -l < "$REPORT_DIR/readonly-sections-candidate.sha256")" -eq 14 ]]
readonly_manifest_diff="$(diff -u \
  "$REPORT_DIR/readonly-sections-baseline.sha256" \
  "$REPORT_DIR/readonly-sections-candidate.sha256" || true)"
[[ "$(rg -c '^[+-][0-9a-f]{64}  \.rodata$' \
  <<<"$readonly_manifest_diff")" -eq 2 ]]
[[ "$(rg -c '^[+-][0-9a-f]{64}  \.rodata\.' \
  <<<"$readonly_manifest_diff" || true)" -eq 0 ]]
pass recorded_readonly_isolation

recalculate_batch "$REPORT_DIR/product-ab-screen-16x50k.txt"
require_line screen_minimum '^minimum_ratio=0\.995553757x$' \
  product-ab-screen-16x50k.txt
require_line screen_gate '^regression_gate=PASS$' product-ab-screen-16x50k.txt
pass product_screen_recalculation

sample_rows=0
for batch in {1..3}; do
  file="$REPORT_DIR/product-ab-batch${batch}-16x100k.txt"
  recalculate_batch "$file"
  rg -q "^baseline_product_sha256=$EXPECTED_BASELINE$" "$file"
  rg -q "^candidate_product_sha256=$EXPECTED_CANDIDATE$" "$file"
  rg -q '^common_benchmark_object_sha256=dbb898fba2eaea946e24274382339f6622b8234918377e085850d8ef84f49985$' \
    "$file"
  rg -q '^normal_core_alias_check=PASS$' "$file"
  sample_rows=$((sample_rows + 16))
done
[[ "$sample_rows" -eq 48 ]]
rg -q '^regression_gate=PASS$' "$REPORT_DIR/product-ab-batch1-16x100k.txt"
rg -q '^regression_gate=PASS$' "$REPORT_DIR/product-ab-batch2-16x100k.txt"
rg -q '^regression_gate=FAIL$' "$REPORT_DIR/product-ab-batch3-16x100k.txt"
require_line batch3_keygen '^keygen_gmean=0\.989333708x$' \
  product-ab-batch3-16x100k.txt
require_line batch3_order_drift '^keygen_baseline_first_median=0\.983237570x$' \
  product-ab-batch3-16x100k.txt
[[ "$(rg -l '^regression_gate=FAIL$' \
  "$REPORT_DIR"/product-ab-batch*-16x100k.txt | wc -l)" -eq 1 ]]
pass product_batch_recalculation
pass product_batch3_failure_retained

cmp <(
  for batch in {1..3}; do
    awk -v b="$batch" '/^[0-9][0-9] / {print b, $0}' \
      "$REPORT_DIR/product-ab-batch${batch}-16x100k.txt"
  done
) <(awk '/^[123] [0-9][0-9] /' \
  "$REPORT_DIR/product-ab-combined-48x100k.txt")

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
require_line combined_keygen '^keygen_gmean=0\.997679015x$' \
  product-ab-combined-48x100k.txt
require_line combined_encaps '^encaps_gmean=0\.998804022x$' \
  product-ab-combined-48x100k.txt
require_line combined_decaps '^decaps_gmean=0\.998471748x$' \
  product-ab-combined-48x100k.txt
require_line combined_roundtrip '^roundtrip_gmean=0\.997218785x$' \
  product-ab-combined-48x100k.txt
require_line combined_minimum '^minimum_ratio=0\.997218785x$' \
  product-ab-combined-48x100k.txt
require_line combined_gate '^regression_gate=PASS$' \
  product-ab-combined-48x100k.txt
require_line no_speed_credit '^speed_credit=NONE_size_only_candidate$' \
  product-ab-combined-48x100k.txt
pass product_combined_recalculation

require_line artifact_baseline "^baseline_product_sha256=$EXPECTED_BASELINE$" \
  artifact-identity.txt
require_line artifact_candidate "^candidate_product_sha256=$EXPECTED_CANDIDATE$" \
  artifact-identity.txt
require_line artifact_postcommit "^postcommit_product_sha256=$EXPECTED_CANDIDATE$" \
  artifact-identity.txt
require_line benchmark_pair '^fixed_benchmark_pair=PASS$' artifact-identity.txt

matrix_rows="$(awk '/^(clang|gcc)-(native|avx2|scalar) status=PASS/ {count++}
  END {print count + 0}' "$REPORT_DIR/correctness-matrix.txt")"
[[ "$matrix_rows" -eq 6 ]]
require_line matrix_gate '^validation_matrix=PASS$' correctness-matrix.txt
require_line nontarget_identity '^non_target_product_identity=5/5$' \
  correctness-matrix.txt
for entry in \
  'size-clang-native.txt:^primary_bytes=69611$' \
  'size-clang-avx2.txt:^primary_bytes=47501$' \
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
require_line corpus_count '^cross_path_corpus_verified=16$' cross-path-corpus.txt
require_line corpus_hash "^cross_path_corpus_sha256=$EXPECTED_CORPUS$" \
  cross-path-corpus.txt
require_line sanitizer_gate '^sanitizer_gate=PASS$' sanitizers.txt
require_line sanitizer_product '^product_output_bytes=0$' sanitizers.txt
require_line sanitizer_sink '^stage_sink=5682381251832549115$' sanitizers.txt
! rg -n 'ERROR: AddressSanitizer|runtime error:|UndefinedBehaviorSanitizer' \
  "$REPORT_DIR"/sanitizer-*.txt
require_line stack_gate '^maximum_stack_nonincrease=PASS$' stack.txt
require_line stack_max '^maximum 4512 4512 0$' stack.txt
require_line abi_gate '^abi_isa_audit=PASS$' abi-audit.txt
require_line postcommit_gate '^postcommit_reproduction=PASS$' postcommit-smoke.txt
require_line postcommit_hash "^artifact_sha256=$EXPECTED_CANDIDATE$" \
  postcommit-smoke.txt
require_line source_gate '^source_isolation=PASS$' source-audit.txt
pass validation_evidence

cmp "$REPORT_DIR/defined-symbols-baseline.txt" \
  "$REPORT_DIR/defined-symbols-candidate.txt"
cmp "$REPORT_DIR/undefined-symbols-baseline.txt" \
  "$REPORT_DIR/undefined-symbols-candidate.txt"
pass recorded_symbol_identity

git -C "$ROOT_DIR" cat-file -e "$EXPECTED_BASELINE_REF^{commit}"
git -C "$ROOT_DIR" cat-file -e "$EXPECTED_CANDIDATE_REF^{commit}"
changed_files="$(git -C "$ROOT_DIR" diff-tree --no-commit-id --name-only -r \
  "$EXPECTED_CANDIDATE_REF")"
[[ "$changed_files" = 'baby-mlkem.c' ]]
numstat="$(git -C "$ROOT_DIR" diff-tree --no-commit-id --numstat -r \
  "$EXPECTED_CANDIDATE_REF")"
[[ "$numstat" = $'1\t0\tbaby-mlkem.c' ]]
git -C "$ROOT_DIR" show --format= --no-ext-diff "$EXPECTED_CANDIDATE_REF" -- \
  baby-mlkem.c | rg -q '^\+#pragma clang loop unroll\(disable\)$'
pass committed_source_audit

tmp_dir="$(mktemp -d /tmp/baby-mlkem-inv-add-loop-evidence.XXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT
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
[[ "$(sed -n 's/^primary_bytes=//p' <<<"$base_size")" -eq 48146 ]]
[[ "$(sed -n 's/^primary_bytes=//p' <<<"$cand_size")" -eq 47501 ]]
pass clean_product_reproduction

objdump -h "$base" | awk '$2 ~ /^\.text/ {print $2}' >"$tmp_dir/base-text.txt"
objdump -h "$cand" | awk '$2 ~ /^\.text/ {print $2}' >"$tmp_dir/cand-text.txt"
cmp "$tmp_dir/base-text.txt" "$tmp_dir/cand-text.txt"
mkdir "$tmp_dir/base-text" "$tmp_dir/cand-text"
text_count=0
unchanged_count=0
changed_sections=()
while IFS= read -r section; do
  text_count=$((text_count + 1))
  objcopy --dump-section "$section=$tmp_dir/base-text/$text_count.bin" "$base"
  objcopy --dump-section "$section=$tmp_dir/cand-text/$text_count.bin" "$cand"
  if cmp -s "$tmp_dir/base-text/$text_count.bin" \
    "$tmp_dir/cand-text/$text_count.bin"; then
    unchanged_count=$((unchanged_count + 1))
  else
    changed_sections+=("$section")
  fi
done <"$tmp_dir/base-text.txt"
[[ "$text_count" -eq 23 ]]
[[ "$unchanged_count" -eq 22 ]]
[[ "${#changed_sections[@]}" -eq 1 ]]
[[ "${changed_sections[0]}" = '.text.kpke_encrypt_finish_avx2' ]]

objdump -h "$base" | awk \
  '$2 ~ /^\.rodata/ || $2 ~ /^\.eh_frame/ || $2 ~ /^\.gcc_except_table/ {print $2}' \
  >"$tmp_dir/base-readonly.txt"
objdump -h "$cand" | awk \
  '$2 ~ /^\.rodata/ || $2 ~ /^\.eh_frame/ || $2 ~ /^\.gcc_except_table/ {print $2}' \
  >"$tmp_dir/cand-readonly.txt"
cmp "$tmp_dir/base-readonly.txt" "$tmp_dir/cand-readonly.txt"
mkdir "$tmp_dir/base-readonly" "$tmp_dir/cand-readonly"
readonly_count=0
unchanged_readonly_count=0
changed_readonly_sections=()
while IFS= read -r section; do
  readonly_count=$((readonly_count + 1))
  objcopy --dump-section "$section=$tmp_dir/base-readonly/$readonly_count.bin" "$base"
  objcopy --dump-section "$section=$tmp_dir/cand-readonly/$readonly_count.bin" "$cand"
  if cmp -s "$tmp_dir/base-readonly/$readonly_count.bin" \
    "$tmp_dir/cand-readonly/$readonly_count.bin"; then
    unchanged_readonly_count=$((unchanged_readonly_count + 1))
  else
    changed_readonly_sections+=("$section")
    base_changed_readonly="$tmp_dir/base-readonly/$readonly_count.bin"
    cand_changed_readonly="$tmp_dir/cand-readonly/$readonly_count.bin"
  fi
done <"$tmp_dir/base-readonly.txt"
[[ "$readonly_count" -eq 14 ]]
[[ "$unchanged_readonly_count" -eq 13 ]]
[[ "${#changed_readonly_sections[@]}" -eq 1 ]]
[[ "${changed_readonly_sections[0]}" = '.rodata' ]]
[[ "$(sha256sum "$base_changed_readonly" | awk '{print $1}')" = \
  '7fc03b64d2966a618cb8000b4641ea01935e8860976fcf9d9283706c658a123d' ]]
[[ "$(sha256sum "$cand_changed_readonly" | awk '{print $1}')" = \
  '5a8807303602169c4ff1c12a6e8b9e3eba93d63f8cd47a6d72aaa751064b30b1' ]]
readonly_byte_diff="$(cmp -l "$base_changed_readonly" \
  "$cand_changed_readonly" || true)"
[[ "$(wc -l <<<"$readonly_byte_diff")" -eq 12 ]]
cmp <(head -c 64 "$base_changed_readonly") \
  <(head -c 64 "$cand_changed_readonly")
cmp <(tail -c +81 "$base_changed_readonly") \
  <(tail -c +81 "$cand_changed_readonly")
cmp <(od -An -v -j64 -N16 -t x2 "$base_changed_readonly" |
  tr -s ' ' '\n' | sed '/^$/d' | sort) \
  <(od -An -v -j64 -N16 -t x2 "$cand_changed_readonly" |
  tr -s ' ' '\n' | sed '/^$/d' | sort)

cmp <(nm -g --defined-only "$base" | awk '{print $2, $3}' | sort) \
  <(nm -g --defined-only "$cand" | awk '{print $2, $3}' | sort)
cmp <(nm -u "$base" | sed 's/^[[:space:]]*//' | sort) \
  <(nm -u "$cand" | sed 's/^[[:space:]]*//' | sort)
! objdump -d "$cand" | rg -q '\b%?zmm[0-9]+\b|\b%?k[0-7]\b'
! readelf -SW "$cand" | rg -q '\.note\.GNU-stack.* X '
pass live_section_symbol_isa_audit

while IFS= read -r target; do
  [[ -z "$target" || "$target" =~ ^https?:// ]] && continue
  [[ -e "$REPORT_DIR/$target" ]]
done < <(rg -o '\]\([^)]+\)' "$REPORT_DIR/README.md" |
  sed 's/^](//; s/)$//; s/#.*$//' | sort -u)
pass report_links

rg -q 'benchmarks/2026-08-10-clang-avx2-rolled-inverse-add-loop/README.md' \
  "$ROOT_DIR/README.md"
rg -q '\| AVX2-only \| Clang 18\.1\.3 \| 41,546 \| 5,955 \| 47,501 \|' \
  "$ROOT_DIR/README.md"
rg -q '2,452 bytes larger than OpenSSL AVX2-only' "$ROOT_DIR/README.md"
rg -q 'Batch 3 fails its standalone floor at keygen' "$ROOT_DIR/README.md"
pass root_readme

printf 'evidence_gate=PASS\n'
