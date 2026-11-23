# 読めるスカラー ML-KEM-768

これは初級編の完成解答である。既存の `baby-mlkem.c` を include した wrapper ではなく、FIPS 203 の ML-KEM-768 を独立に実装している。

読み進める順番:

1. `params.h` — `n, q, k, eta1, eta2, du, dv` と byte 数。
2. `poly.c` — 多項式の加減算と遅い schoolbook oracle。
3. `keccak.c` — 25 個の 64-bit lane で書いた Keccak-f と sponge。
4. `encoding.c` — ByteEncode/Decode と Compress/Decompress。
5. `sampling.c` — SHAKE rejection sampling と CBD。
6. `ntt.c` — FIPS の通常剰余 NTT、逆 NTT、NTT-domain 積。
7. `kpke.c` — 内部 K-PKE の KeyGen/Encrypt/Decrypt。
8. `mlkem.c` — Fujisaki–Okamoto 変換と implicit rejection。

章別の最小テストを動かす。

    make chapter-01-keccak && ./chapter-01-keccak
    make chapter-02-encoding && ./chapter-02-encoding
    make chapter-03-ntt && ./chapter-03-ntt
    make chapter-04-sampling && ./chapter-04-sampling
    make chapter-05-kpke && ./chapter-05-kpke

完成版を動かす。

    make test

最適化済み製品実装を oracle として byte 単位で比較する。

    make oracle

この実装では、理解を優先して `% 3329`、整数除算、実行時 zeta 生成、汎用 bit loop、単一状態 Keccak を残している。これらはすべて上級編の計測対象になる。最適化後も `make test` と `make oracle` の結果を変えてはならない。

学習用の制約:

- `edu_kpke_*` は ML-KEM 内部だけで使う。
- `*_derand` は再現可能なテスト用で、本番公開 API ではない。
- 秘密値の消去、乱数取得、入力 validation、stack 上限、constant-time machine code は製品化時に別途監査する。
- 最初から SIMD や cache を加えず、scalar baseline の profile を取ってから一つずつ変更する。
