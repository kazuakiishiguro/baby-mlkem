# AGENT.md

## 目的

このリポジトリで「世界最速の ML-KEM 実装」を維持・検証する。

## 完了条件 (Acceptance Criteria)

次のすべてを満たしたときに、この目的は達成とみなす。

1. 正しさゲート
   - `make clean && make test` が成功すること。

2. 通常比較ゲート
   - `PIN_CPU=0 C_COMPILER=clang SHOW_FULL_OUTPUT_ON_FAIL=0 ./scripts/verify_world_fastest.sh 600 2`
     が成功し、全ラベルで `local_speedup_vs_competitor >= 1.000x` を満たすこと。

3. 最新比較ゲート
   - `PIN_CPU=0 C_COMPILER=clang UPDATE_REPOS=1 MAX_RETRIES=2 RETRY_LABELS=kyber_upstream_avx2,kyber_upstream_avx2_fair SHOW_FULL_OUTPUT_ON_FAIL=0 ./scripts/verify_world_fastest.sh 600 2`
     が成功し、全ラベルで `local_speedup_vs_competitor >= 1.000x` を満たすこと。

4. 厳格二段ゲート
   - `PIN_CPU=0 C_COMPILER=clang SHOW_FULL_OUTPUT_ON_FAIL=0 ./scripts/verify_world_fastest_strict.sh 600 2`
     が成功し、`verify_world_fastest_strict=PASS` が出力されること。

## 補足

- 比較対象実装の更新で `git pull --ff-only` が失敗した場合は、各 comparator
  script の fallback shallow clone を許可する。
- 比較ノイズ対策として kyber 系ラベルの controlled retry を許可する。
