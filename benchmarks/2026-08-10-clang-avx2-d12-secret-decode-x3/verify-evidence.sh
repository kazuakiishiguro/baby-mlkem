#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$REPORT_DIR/../.." && pwd)"
EXPECTED_CANDIDATE=bcbc68b7a6fac3b6d25e02706f244bb0b92a130cb40ec7b1422b69762dbb5168
EXPECTED_CORPUS=e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67

pass() {
  printf '%s=PASS\n' "$1"
}

require_line() {
  local label="$1" pattern="$2" file="$3"
  rg -q -- "$pattern" "$REPORT_DIR/$file"
  pass "$label"
}

require_line candidate_size '^primary_bytes=50096$' size-candidate.txt
require_line candidate_code '^code_bytes=42541$' size-candidate.txt
require_line candidate_readonly '^readonly_data_bytes=7555$' size-candidate.txt
require_line candidate_hash "^artifact_sha256=$EXPECTED_CANDIDATE$" size-candidate.txt
require_line baseline_size '^primary_bytes=50480$' size-baseline.txt
require_line section_delta '^primary_size_delta=-384$' section-accounting.txt
require_line section_isolation '^section_isolation=PASS$' section-accounting.txt

sample_rows="$(cat "$REPORT_DIR"/product-ab-batch*-16x100k.txt |
  awk '/^[0-9][0-9] / {count++} END {print count + 0}')"
[[ "$sample_rows" -eq 96 ]]
pass product_sample_count

operations=(keygen encaps decaps roundtrip)
baseline_columns=(3 5 7 9)
candidate_columns=(4 6 8 10)
for batch in {1..6}; do
  batch_file="$REPORT_DIR/product-ab-batch${batch}-16x100k.txt"
  for index in "${!operations[@]}"; do
    operation="${operations[$index]}"
    calculated="$(awk -v b="${baseline_columns[$index]}" \
      -v c="${candidate_columns[$index]}" \
      '/^[0-9][0-9] / {sum += log($b / $c); count++}
       END {printf "%.9f", exp(sum / count)}' "$batch_file")"
    recorded="$(sed -n "s/^${operation}_gmean=\([0-9.]*\)x$/\1/p" \
      "$batch_file")"
    [[ "$calculated" = "$recorded" ]]
  done
done
pass product_batch_recalculation

for index in "${!operations[@]}"; do
  operation="${operations[$index]}"
  calculated="$(awk -v b="${baseline_columns[$index]}" \
    -v c="${candidate_columns[$index]}" \
    '/^[0-9][0-9] / {sum += log($b / $c); count++}
     END {printf "%.9f", exp(sum / count)}' \
    "$REPORT_DIR"/product-ab-batch*-16x100k.txt)"
  recorded="$(sed -n "s/^${operation}_gmean=\([0-9.]*\)x$/\1/p" \
    "$REPORT_DIR/product-ab-combined-96x100k.txt")"
  [[ "$calculated" = "$recorded" ]]
done
pass product_combined_recalculation

alias_passes="$(rg --no-filename '^normal_core_alias_check=PASS$' \
  "$REPORT_DIR"/product-ab-batch*-16x100k.txt | wc -l)"
[[ "$alias_passes" -eq 6 ]]
pass product_alias
require_line first_48_disclosure '^product_regression_gate=FAIL$' product-ab-first-48x100k.txt
require_line first_48_ratio '^minimum_combined_ratio=0\.992953188x$' product-ab-first-48x100k.txt
require_line combined_ratio '^minimum_combined_ratio=0\.995151170x$' product-ab-combined-96x100k.txt
require_line product_gate '^product_regression_gate=PASS$' product-ab-combined-96x100k.txt

require_line direct_validation '^direct_validation=PASS$' direct-validation.txt
require_line direct_baseline_size '^baseline_function_bytes=589$' direct-validation.txt
require_line direct_candidate_size '^candidate_function_bytes=205$' direct-validation.txt
require_line interrupted_reproduction '^measurement_gate=REJECTED_HOST_INTERRUPTION$' direct-d12-x3-postcommit-reproduction-30x50m.txt

matrix_rows="$(awk '/^(clang|gcc)-(native|avx2|scalar) status=PASS/ {count++} END {print count + 0}' \
  "$REPORT_DIR/correctness-matrix.txt")"
[[ "$matrix_rows" -eq 6 ]]
pass correctness_matrix
require_line matrix_gate '^validation_matrix=PASS$' correctness-matrix.txt
require_line sanitizer_gate '^sanitizer_gate=PASS$' sanitizers.txt
require_line sanitizer_sink '^complete_stage_sink=4297556503821386549$' sanitizers.txt

corpus_rows="$(rg -c '^cross_path_corpus=' "$REPORT_DIR/cross-path-corpus.txt")"
[[ "$corpus_rows" -eq 16 ]]
pass corpus_count
require_line corpus_hash "^cross_path_corpus_sha256=$EXPECTED_CORPUS$" cross-path-corpus.txt
require_line root_gate '^ntt_root_reproducibility=PASS$' ntt-roots.txt
require_line stack_gate '^maximum_stack_nonincrease=PASS$' stack.txt
require_line abi_gate '^abi_isa_audit=PASS$' abi-audit.txt
require_line postcommit_gate '^postcommit_reproduction=PASS$' postcommit-smoke.txt
require_line postcommit_hash "^artifact_sha256=$EXPECTED_CANDIDATE$" postcommit-smoke.txt
require_line source_gate '^source_isolation=PASS$' source-audit.txt

tmp_dir="$(mktemp -d /tmp/baby-mlkem-d12-evidence.XXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT
clang -O3 -fno-semantic-interposition -fvisibility=hidden \
  -fomit-frame-pointer -fno-stack-protector -falign-loops=64 \
  -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -fno-strict-aliasing -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt \
  -mno-avx512f "$REPORT_DIR/direct-d12-x3-harness.c" \
  -o "$tmp_dir/direct-d12-x3"
"$tmp_dir/direct-d12-x3" validate > "$tmp_dir/validation.txt"
rg -q '^validated_cases=20484$' "$tmp_dir/validation.txt"
baseline_hex="$(nm -S --size-sort "$tmp_dir/direct-d12-x3" |
  awk '$4 == "baseline_decode_x3" {print $2}')"
candidate_hex="$(nm -S --size-sort "$tmp_dir/direct-d12-x3" |
  awk '$4 == "candidate_decode_x3" {print $2}')"
[[ "$((16#$baseline_hex))" -eq 589 ]]
[[ "$((16#$candidate_hex))" -eq 205 ]]
pass direct_harness_reproduction

while IFS= read -r target; do
  [[ -z "$target" || "$target" =~ ^https?:// ]] && continue
  [[ -e "$REPORT_DIR/$target" ]]
done < <(rg -o '\]\([^)]+' "$REPORT_DIR/README.md" |
  sed 's/^](//; s/#.*$//' | sort -u)
pass report_links

rg -q 'benchmarks/2026-08-10-clang-avx2-d12-secret-decode-x3/README.md' \
  "$ROOT_DIR/README.md"
rg -q '\| AVX2-only \| Clang 18\.1\.3 \| 42,541 \| 7,555 \| 50,096 \|' \
  "$ROOT_DIR/README.md"
rg -q '5,047 bytes larger than OpenSSL AVX2-only' "$ROOT_DIR/README.md"
pass root_readme

printf 'evidence_gate=PASS\n'
