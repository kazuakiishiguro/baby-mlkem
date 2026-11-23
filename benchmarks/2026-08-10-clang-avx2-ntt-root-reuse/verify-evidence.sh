#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$REPORT_DIR/../.." && pwd)"
EXPECTED_BASELINE=827f362023df33ba047637df373b28eee9349448e9becc419b882570fabb792a
EXPECTED_CANDIDATE=6d2f660ef7a830827b5e35aa8cbde0d13f90aebda481a1f69ac94f8df949bb91
EXPECTED_COMMIT=1809825900eb257ad1baf240423281748b267a0b
EXPECTED_CORPUS=e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67

pass() {
  printf '%s=PASS\n' "$1"
}

require_line() {
  local label="$1" pattern="$2" file="$3"
  rg -q -- "$pattern" "$REPORT_DIR/$file"
  pass "$label"
}

recalculate_operations() {
  local file="$1"
  local operations=(keygen encaps decaps roundtrip)
  local baseline_columns=(3 5 7 9)
  local candidate_columns=(4 6 8 10)
  local index operation calculated recorded

  for index in "${!operations[@]}"; do
    operation="${operations[$index]}"
    calculated="$(awk -v b="${baseline_columns[$index]}" \
      -v c="${candidate_columns[$index]}" \
      '/^[0-9][0-9] / {sum += log($b / $c); count++}
       END {printf "%.9f", exp(sum / count)}' "$file")"
    recorded="$(sed -n "s/^${operation}_gmean=\([0-9.]*\)x$/\1/p" "$file")"
    [[ "$calculated" = "$recorded" ]]
  done
}

recalculate_direct() {
  local file="$1" expected_rows="$2" expected_gmean="$3"
  local rows calculated matches
  rows="$(awk '/^[0-9][0-9] / {count++} END {print count + 0}' "$file")"
  [[ "$rows" -eq "$expected_rows" ]]
  calculated="$(awk '/^[0-9][0-9] / {sum += log($5); count++}
    END {printf "%.9f", exp(sum / count)}' "$file")"
  [[ "$calculated" = "$expected_gmean" ]]
  matches="$(awk '/^[0-9][0-9] / && $6 == $7 {count++}
    END {print count + 0}' "$file")"
  [[ "$matches" -eq "$expected_rows" ]]
}

(cd "$REPORT_DIR" && sha256sum -c checksums.sha256 >/dev/null)
pass checksums

require_line baseline_size '^primary_bytes=49712$' size-baseline.txt
require_line baseline_hash "^artifact_sha256=$EXPECTED_BASELINE$" size-baseline.txt
require_line candidate_size '^primary_bytes=48722$' size-candidate.txt
require_line candidate_code '^code_bytes=42191$' size-candidate.txt
require_line candidate_readonly '^readonly_data_bytes=6531$' size-candidate.txt
require_line candidate_hash "^artifact_sha256=$EXPECTED_CANDIDATE$" size-candidate.txt
require_line section_accounting \
  '^text_sections_baseline=23 text_sections_candidate=23 changed_text=1 readonly_sections_baseline=15 readonly_sections_candidate=13 changed_readonly=2 removed_readonly=2 primary_delta=-990 section_isolation=PASS$' \
  section-accounting.txt
require_line changed_section \
  '^section=\.text\.ntt_mont_lazy_avx2 baseline_bytes=3584 candidate_bytes=3618 delta=\+34 status=changed$' \
  section-accounting.txt
require_line removed_low \
  '^section=\.rodata\.ZETA_NTT_TAIL_MONT_LO_L12 baseline_bytes=512 candidate_bytes=0 delta=-512 status=removed$' \
  section-accounting.txt
require_line removed_high \
  '^section=\.rodata\.ZETA_NTT_TAIL_MONT_HI_L12 baseline_bytes=512 candidate_bytes=0 delta=-512 status=removed$' \
  section-accounting.txt

relation_passes="$(rg -c '^forward_equals_reverse16_inverse_prefix=PASS$' \
  "$REPORT_DIR/root-relation.txt")"
[[ "$relation_passes" -eq 2 ]]
require_line root_relation '^root_relation=PASS$' root-relation.txt

recalculate_direct "$REPORT_DIR/direct-forward-ntt-32x2m.txt" 32 1.004281636
require_line direct_gate '^direct_regression_gate=PASS$' direct-forward-ntt-32x2m.txt
require_line direct_policy '^sample_policy=all_32_pairs_retained_no_filtering$' direct-forward-ntt-32x2m.txt
pass direct_recalculation

sample_rows="$(awk '/^[0-9][0-9] / {count++} END {print count + 0}' \
  "$REPORT_DIR"/product-ab-batch*-16x100k.txt)"
[[ "$sample_rows" -eq 48 ]]
pass product_sample_count

for batch in {1..3}; do
  recalculate_operations "$REPORT_DIR/product-ab-batch${batch}-16x100k.txt"
done
pass product_batch_recalculation

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
pass product_combined_recalculation

alias_passes="$(rg --no-filename '^normal_core_alias_check=PASS$' \
  "$REPORT_DIR"/product-ab-batch*-16x100k.txt | wc -l)"
[[ "$alias_passes" -eq 3 ]]
pass product_alias
require_line combined_ratio '^minimum_combined_ratio=0\.999748066x$' product-ab-combined-48x100k.txt
require_line product_gate '^product_regression_gate=PASS$' product-ab-combined-48x100k.txt

recalculate_operations "$REPORT_DIR/product-ab-screen-16x50k.txt"
require_line screen_ratio '^minimum_ratio=0\.997233183x$' product-ab-screen-16x50k.txt
require_line screen_gate '^screen_gate=PASS$' product-ab-screen-16x50k.txt
pass screen_recalculation

recalculate_direct "$REPORT_DIR/rejected-shuffle-direct-15x2m.txt" 15 0.974160573
recalculate_direct "$REPORT_DIR/rejected-vpermd-direct-15x2m.txt" 15 0.970389614
recalculate_direct "$REPORT_DIR/rejected-hybrid-direct-15x2m.txt" 15 0.955631975
require_line rejected_count '^rejected_candidates_retained=3$' rejected-candidates.txt
require_line candidate_selection '^candidate_selection=PASS$' rejected-candidates.txt
pass rejected_candidate_recalculation

require_line artifact_identity '^candidate_product_identity=PASS$' artifact-identity.txt
require_line benchmark_identity '^fixed_benchmark_relink_identity=PASS$' artifact-identity.txt

matrix_rows="$(awk '/^(clang|gcc)-(native|avx2|scalar) status=PASS/ {count++}
  END {print count + 0}' "$REPORT_DIR/correctness-matrix.txt")"
[[ "$matrix_rows" -eq 6 ]]
require_line matrix_gate '^validation_matrix=PASS$' correctness-matrix.txt
require_line nontarget_identity '^non_target_product_identity=5/5$' correctness-matrix.txt
require_line sanitizer_gate '^sanitizer_gate=PASS$' sanitizers.txt
require_line sanitizer_sink '^complete_stage_sink=4297556503821386549$' sanitizers.txt

corpus_rows="$(rg -c '^cross_path_corpus=' "$REPORT_DIR/cross-path-corpus.txt")"
[[ "$corpus_rows" -eq 16 ]]
require_line corpus_hash "^cross_path_corpus_sha256=$EXPECTED_CORPUS$" cross-path-corpus.txt
require_line root_gate '^ntt_root_reproducibility=PASS$' ntt-roots.txt
require_line stack_gate '^maximum_stack_nonincrease=PASS$' stack.txt
require_line abi_gate '^abi_isa_audit=PASS$' abi-audit.txt
require_line postcommit_gate '^postcommit_reproduction=PASS$' postcommit-smoke.txt
require_line postcommit_hash "^artifact_sha256=$EXPECTED_CANDIDATE$" postcommit-smoke.txt
require_line source_gate '^source_isolation=PASS$' source-audit.txt

for entry in \
  'size-clang-native.txt:^primary_bytes=69611$' \
  'size-clang-avx2.txt:^primary_bytes=48722$' \
  'size-clang-scalar.txt:^primary_bytes=62098$' \
  'size-gcc-native.txt:^primary_bytes=59148$' \
  'size-gcc-avx2.txt:^primary_bytes=53443$' \
  'size-gcc-scalar.txt:^primary_bytes=22994$'; do
  file="${entry%%:*}"
  pattern="${entry#*:}"
  rg -q -- "$pattern" "$REPORT_DIR/$file"
done
pass size_matrix

tmp_dir="$(mktemp -d /tmp/baby-mlkem-ntt-root-evidence.XXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT
clang -O3 -fno-semantic-interposition -fvisibility=hidden \
  -fomit-frame-pointer -fno-stack-protector -falign-loops=64 \
  -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -fno-strict-aliasing -Wno-unused-function \
  -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f \
  -DMLKEM_AVX2_EXTERNAL_INV_MONT -I"$ROOT_DIR" \
  "$REPORT_DIR/direct-forward-ntt-harness.c" \
  "$ROOT_DIR/ntt_roots_avx2_constants.S" -Wa,--noexecstack \
  -o "$tmp_dir/direct-forward-ntt"
taskset -c 0 "$tmp_dir/direct-forward-ntt" 2000000 > "$tmp_dir/direct.txt"
rg -q ' checksum=27154171$' "$tmp_dir/direct.txt"
pass direct_harness_reproduction

make -s -C "$ROOT_DIR" check-ntt-roots HOSTCC=clang
make -s -C "$ROOT_DIR" check-ntt-roots HOSTCC=gcc
pass root_generator_reproduction

while IFS= read -r target; do
  [[ -z "$target" || "$target" =~ ^https?:// ]] && continue
  [[ -e "$REPORT_DIR/$target" ]]
done < <(rg -o '\]\([^)]+' "$REPORT_DIR/README.md" |
  sed 's/^](//; s/#.*$//' | sort -u)
pass report_links

git -C "$ROOT_DIR" cat-file -e "$EXPECTED_COMMIT^{commit}"
rg -q 'benchmarks/2026-08-10-clang-avx2-ntt-root-reuse/README.md' \
  "$ROOT_DIR/README.md"
rg -q '\| AVX2-only \| Clang 18\.1\.3 \| 42,191 \| 6,531 \| 48,722 \|' \
  "$ROOT_DIR/README.md"
rg -q '3,673 bytes larger than OpenSSL AVX2-only' "$ROOT_DIR/README.md"
pass root_readme

printf 'evidence_gate=PASS\n'
