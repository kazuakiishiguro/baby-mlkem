# ゼロから作る ML-KEM-768 — 読める実装から高速・小型実装まで

この本では、暗号の実装経験がない読者が、小さな C プログラムから始めて ML-KEM-768 を自分で組み立てる。初級編の終点は、FIPS 203 と byte 単位で一致する読みやすいスカラー実装である。上級編では、その同じ実装を測定し、正しさを保ったまま Montgomery arithmetic、固定長処理、AVX2、AVX512、局所 assembly、コードサイズ最小化へ進める。

過去の開発履歴を読む必要はない。各章で新しい概念を一つ導入し、その場で動くテストを通してから次へ進む。完成解答は `tutorial/scalar-mlkem/`、紙で追える最初の例は `tutorial/00-scratch/` にある。

## この本で到達するもの

| 段階 | 自分で書けるもの | 合格の根拠 |
| --- | --- | --- |
| 最初の 30 分 | `Z_3329[x]/(x^8+1)` の多項式積 | 手計算と C の出力が一致する |
| 初級前半 | SHA3/SHAKE、encoding、sampling、NTT | KAT、round-trip、schoolbook oracle |
| 初級後半 | K-PKE、ML-KEM-768 | ACVP projection、KEM round-trip、implicit rejection |
| 上級前半 | 測定可能な scalar/Montgomery baseline | stage benchmark と同値性 test |
| 上級後半 | AVX2/AVX512、局所 assembly、小型 product | 同一 API、同一 byte 出力、速度・サイズ gate |

ML-KEM-768 の完成時の長さは固定である。

| 値 | byte 数 |
| --- | ---: |
| encapsulation key `ek` | 1184 |
| decapsulation key `dk` | 2400 |
| ciphertext `c` | 1088 |
| shared secret `K` | 32 |

## 仕様と安全上の境界

一次資料は [NIST FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) である。規格ページには将来の訂正候補も掲載されるため、適合性を主張する前には [FIPS 203 publication page](https://csrc.nist.gov/pubs/fips/203/final) も確認する。

この教材の `edu_kpke_*` は ML-KEM を理解するための内部部品である。K-PKE を単独の公開鍵暗号として使用してはならない。また `*_derand` は既知の入力で毎回同じ出力を得るテスト専用 interface である。実運用の KeyGen と Encaps は、承認された乱数生成器から関数内部で乱数を取得する必要がある。

初級完成版は理解しやすさを優先し、整数除算、`% q`、汎用 bit loop、単一状態 Keccak を使う。秘密値の消去、入力 validation、stack 上限、fault attack、machine code の constant-time 性まで保証する製品コードではない。

## 本の進め方

自分用の空ディレクトリを一つ作り、本文を見ながらファイルを追加する。完成解答を直接編集する必要はない。

    mkdir -p tutorial/my-mlkem
    cd tutorial/my-mlkem

各章では次の順番を守る。

1. 章の目的と不変条件を読む。
2. 宣言だけを書き、compiler warning を消す。
3. 最も素直な scalar code を書く。
4. 章の test を自分の実装へ移植する。
5. test が失敗したら、最初に print するのではなく小さい入力へ縮める。
6. 困ったときだけ `tutorial/scalar-mlkem/` の同名ファイルを見る。
7. 完成条件を自分の言葉で説明してから次へ進む。

教材の完成解答を先に一度動かしておく。

    make -C tutorial test

期待する最後の行は次である。

    scalar ML-KEM-768: ALL TESTS PASSED

# 第 I 部 暗号を組む前の最小知識

## ステップ 0: KEM が何をするかを理解する

KEM は長い message を暗号化する API ではない。二者が同じ 32-byte secret を得るための仕組みである。

1. Bob が `KeyGen()` を実行し、公開する `ek` と秘密にする `dk` を得る。
2. Alice が `Encaps(ek)` を実行し、`c` と `K` を得る。
3. Alice は `c` を Bob へ送る。
4. Bob が `Decaps(dk, c)` を実行し、同じ `K` を得る。
5. 実データは `K` を鍵とする認証付き共通鍵暗号で扱う。

最初に作る API の形だけを `mlkem.h` に書く。

    void edu_mlkem768_keypair_derand(uint8_t ek[1184],
                                      uint8_t dk[2400],
                                      const uint8_t coins[64]);

    void edu_mlkem768_encaps_derand(uint8_t c[1088],
                                    uint8_t K[32],
                                    const uint8_t ek[1184],
                                    const uint8_t m[32]);

    void edu_mlkem768_decaps(uint8_t K[32],
                             const uint8_t c[1088],
                             const uint8_t dk[2400]);

ここで `coins = d || z`、Encaps の `m` は test input である。本番 API では caller から受け取らない。

### なぜ格子とノイズを使うのか

ML-KEM の内部 K-PKE は、乱数から作る行列 `A`、小さい秘密ベクトル `s`、小さい誤差 `e` を使って、おおまかに次の公開値を作る。

    t = A * s + e

`A` と `t` から `s` を回収する問題を難しくするのが `e` である。暗号文にも新しい小さい乱数と誤差を入れる。復号側は正しい `s` を知っているため大きな項を相殺でき、残った値が 0 に近いか `q/2` に近いかで message bit を戻せる。

この説明は安全性証明ではない。実装中に「なぜ小さいノイズを足しても message が戻るのか」を見失わないための地図である。

### 完成条件

- KEM と通常の message encryption の違いを説明できる。
- `ek` を公開し、`dk` と `K` を秘密にする理由を説明できる。
- deterministic API が test 専用である理由を説明できる。

## ステップ 1: 8 次の多項式環を動かす

最初から 256 次や NTT を扱わない。`tutorial/00-scratch/main.c` は、本物と同じ `q=3329` を使い、次数だけ `N=8` に縮めた完全なプログラムである。

    make -C tutorial/00-scratch test

期待する出力:

    toy ring: Z_3329[x] / (x^8 + 1)
    a + b = [5, 5, 5, 5, 0, 0, 0, 0]
    a * b = [4, 11, 20, 30, 20, 11, 4, 0]
    OK

多項式を配列で表す。

    enum { Q = 3329, N = 8 };
    typedef int16_t poly[N];

`a[i]` は `x^i` の係数である。この環では `x^N + 1 = 0` なので `x^N = -1` になる。積の次数が `N` 以上なら、符号を反転して先頭へ折り返す。

    if (degree < N)
      accum[degree] += product;
    else
      accum[degree - N] -= product;

`x^7 * x = x^8 = -1` であり、canonical representative は `3328` になる。

### 自分で追加する test

- `mod_q(-1) == 3328`
- `(q-1)+1 == 0`
- `x^7*x == -1`
- `a*0 == 0`
- `a*1 == a`
- `a*b == b*a`

### よくある失敗

- `x^8=1` として cyclic convolution を書く。
- 乗算の中間値も `int16_t` にして overflow させる。
- C の負の剰余をそのまま coefficient として使う。

### 完成条件

- negacyclic と cyclic convolution の違いを図なしで説明できる。
- `int32_t` または `int64_t` の accumulator が必要な理由を説明できる。
- 上の六つの test が通る。

## ステップ 2: 本物の parameter と遅い oracle を作る

ここから `N=256` にする。`params.h` に ML-KEM-768 だけを固定して書く。

    enum {
      EDU_N = 256,
      EDU_Q = 3329,
      EDU_K = 3,
      EDU_ETA1 = 2,
      EDU_ETA2 = 2,
      EDU_DU = 10,
      EDU_DV = 4
    };

型は多項式と長さ 3 の vector だけでよい。

    typedef struct { int16_t coeff[EDU_N]; } edu_poly;
    typedef struct { edu_poly poly[EDU_K]; } edu_polyvec;

`poly.c` に加算、減算、schoolbook multiplication を書く。schoolbook は本番経路には使わないが、後で NTT multiplication の独立 oracle になる。256 項の積をすべて足すため accumulator は `int64_t` にする。

    for (size_t i = 0; i < EDU_N; i++) {
      for (size_t j = 0; j < EDU_N; j++) {
        size_t d = i + j;
        int32_t p = (int32_t)a->coeff[i] * b->coeff[j];
        if (d < EDU_N)
          accum[d] += p;
        else
          accum[d - EDU_N] -= p;
      }
    }

### byte 数を導出する

12 bit coefficient を 256 個詰めると `256*12/8 = 384` byte になる。ML-KEM-768 は多項式を三つ持つため、K-PKE secret key 部分は `3*384 = 1152` byte である。

    EDU_POLY12_BYTES = 384
    EDU_PKE_SECRET_KEY_BYTES = 3 * 384 = 1152
    EDU_PUBLIC_KEY_BYTES = 3 * 384 + 32 = 1184
    EDU_CIPHERTEXT_BYTES = 3 * (256 * 10 / 8) + (256 * 4 / 8)
                         = 960 + 128
                         = 1088

ML-KEM decapsulation key は次の連結なので `1152+1184+32+32 = 2400` byte になる。

    dkPKE || ek || H(ek) || z

### 完成条件

- 1184、2400、1088 を暗記ではなく式から出せる。
- `N=256` の schoolbook multiplication が動く。
- schoolbook を遅いという理由で削除せず、oracle として残す。

# 第 II 部 ML-KEM の部品を一つずつ作る

## ステップ 3: Keccak、SHA3、SHAKE を作る

ML-KEM は一つの Keccak-f[1600] permutation を異なる sponge parameter で使い分ける。

| 名前 | rate | domain byte | ML-KEM での役割 |
| --- | ---: | ---: | --- |
| SHA3-256 | 136 | `0x06` | `H`、公開鍵 hash |
| SHA3-512 | 72 | `0x06` | `G`、64 byte の展開 |
| SHAKE128 | 168 | `0x1f` | 行列 coefficient の XOF |
| SHAKE256 | 136 | `0x1f` | PRF、CBD 用 byte、rejection key |

状態は 25 個の 64-bit lane で表す。

    typedef struct {
      uint64_t lane[25];
      size_t rate;
      size_t pos;
    } edu_xof;

一 round は `theta → rho → pi → chi → iota` の順である。最初は `tutorial/scalar-mlkem/keccak.c` のような短い loop 版を書く。24 round を手で展開してはいけない。

### sponge の三段階

1. Absorb: rate byte ごとに input を state へ XOR して permutation を呼ぶ。
2. Finalize: input 末尾へ domain byte、rate の最後へ `0x80` を XOR する。
3. Squeeze: permutation 後の rate 部分を出力し、足りなければ再び permutation を呼ぶ。

padding で特に重要な部分は次である。

    xor_byte(state, input_remainder_length, domain);
    xor_byte(state, rate - 1, 0x80);

### 最初の KAT

空文字列の SHA3-256 は次の 32 byte になる。

    a7ffc6f8bf1ed76651c14756a061d662
    f580ff4de43b49fa82d80a4b80f8434a

完成解答の最小 test を動かす。

    make -C tutorial/scalar-mlkem chapter-01-keccak
    ./tutorial/scalar-mlkem/chapter-01-keccak

期待結果:

    chapter 01 - SHA3-256 empty KAT: OK

### よくある失敗

- host endian の `memcpy` に依存し、little-endian byte order を明示しない。
- SHA3 と SHAKE の domain byte を同じにする。
- 最後の block を permutation せずに squeeze する。
- rotation count と lane destination の table を取り違える。

### 完成条件

- SHA3-256 empty KAT と SHAKE128 empty KAT が通る。
- SHA3 と SHAKE が同じ permutation でも別の出力になる理由を説明できる。
- SHAKE128 を複数回 squeeze しても、一度に同じ長さを得た場合と一致する。

## ステップ 4: ByteEncode、ByteDecode、Compress を作る

ML-KEM の wire format は little-endian の bit stream である。`d` bit の coefficient 256 個は `256*d/8` byte になる。

### ByteEncode と ByteDecode

最初は汎用 bit loop を書く。速さより bit order が目で分かることを優先する。

    for (size_t i = 0; i < 256; i++) {
      for (unsigned bit = 0; bit < d; bit++) {
        size_t bit_pos = i * d + bit;
        out[bit_pos >> 3] |=
            ((value >> bit) & 1) << (bit_pos & 7);
      }
    }

`d=12` の decode では得た 12-bit 値を `q` で還元する。`d<12` では modulus は `2^d` である。

### Compress と Decompress

coefficient `x` を `d` bit へ丸める。

    Compress_d(x) = round((2^d / q) * x) mod 2^d
    Decompress_d(y) = round((q / 2^d) * y)

整数だけで書くと次になる。

    compressed = ((x * (1u << d) + q / 2) / q) & ((1u << d) - 1);
    decompressed = (y * q + (1u << (d - 1))) >> d;

用途は `d=1` の message、`d=10` の ciphertext vector `u`、`d=4` の ciphertext polynomial `v` である。

### 合格 test

    make -C tutorial/scalar-mlkem chapter-02-encoding
    ./tutorial/scalar-mlkem/chapter-02-encoding

期待結果:

    chapter 02 - encode/decode/compress: OK

test は `d=12` の完全 round-trip と、`d=10` での丸め誤差上限を確認する。

### よくある失敗

- `ByteDecode_12(ByteEncode_12(x))` と compress/decompress を同じ可逆操作だと思う。
- signed coefficient を canonical `[0,q)` へ直さず pack する。
- byte order を coefficient ごとに reset して、bit が byte 境界をまたぐ場合を壊す。
- `d=4` の mask を `0x1f` にする。

### 完成条件

- `d=12` の 384-byte round-trip が通る。
- compress/decompress が一般には元に戻らない理由を説明できる。
- `u` と `v` で bit 数が違う理由を「通信量と復号失敗確率の trade-off」と説明できる。

## ステップ 5: NTT と逆 NTT を作る

schoolbook multiplication は `O(N^2)` である。NTT は多項式を積を計算しやすい表現へ変換する。ML-KEM の NTT は 7 stage の incomplete NTT なので、変換後の coefficient を一つずつ単純に掛けるのではなく、2 coefficient の BaseCaseMultiply を使う。

### zeta を仕様から作る

root `17` と 7-bit reversal を使う。

    zeta[i] = 17^BitRev7(i) mod 3329

学習版では起動時に 128 個を生成してよい。最適化編で static table に変える。

### forward NTT

`length` を 128 から 2 まで半分にし、butterfly を行う。

    k = 1;
    for (length = 128; length >= 2; length >>= 1) {
      for (start = 0; start < 256; start += 2 * length) {
        root = zeta[k++];
        for (j = start; j < start + length; j++) {
          t = root * f[j + length] mod q;
          f[j + length] = f[j] - t mod q;
          f[j]          = f[j] + t mod q;
        }
      }
    }

### inverse NTT

順序を逆にし、最後に `128^-1 mod q = 3303` を掛ける。

    k = 127;
    for (length = 2; length <= 128; length <<= 1) {
      ...
      low  = f[j];
      high = f[j + length];
      f[j]          = low + high mod q;
      f[j + length] = zeta[k] * (high - low) mod q;
      ...
    }

### NTT-domain multiplication

4 coefficient ごとに正負二つの gamma を使う。

    BaseCase(a0+a1*x, b0+b1*x, gamma):
      c0 = a0*b0 + a1*b1*gamma
      c1 = a0*b1 + a1*b0

    pair 0 uses  zeta[64+i]
    pair 1 uses -zeta[64+i]

### 二重 oracle

次の二つを必ず両方 test する。

1. `inverse_ntt(ntt(a)) == a`
2. `inverse_ntt(MultiplyNTTs(ntt(a),ntt(b))) == schoolbook(a,b)`

一つ目だけでは、forward と inverse が同じ誤った順序を共有する場合を見逃す。

    make -C tutorial/scalar-mlkem chapter-03-ntt
    ./tutorial/scalar-mlkem/chapter-03-ntt

期待結果:

    chapter 03 - inverse NTT and multiplication oracle: OK

### よくある失敗

- `zeta[0]` から forward NTT を始める。
- bit reversal を 8 bit で行う。
- inverse の差を `low-high` にする。
- NTT-domain で coefficient-wise multiplication を行う。
- schoolbook oracle まで NTT と同じ helper で書き、同じ bug を共有する。

### 完成条件

- 100 個以上の deterministic polynomial pair で schoolbook と一致する。
- NTT が message の暗号化そのものではないと説明できる。
- BaseCaseMultiply が必要な理由を説明できる。

## ステップ 6: rejection sampling と CBD を作る

ML-KEM は二種類の分布を使う。行列 `A` の coefficient は `[0,q)` からほぼ一様に選び、秘密・誤差は `-2` から `2` 付近の小さい値にする。

### SampleNTT

input は `rho || suffix0 || suffix1` の 34 byte であり、SHAKE128 を必要なだけ squeeze する。3 byte から二つの 12-bit candidate を作る。

    first  = b0 | ((b1 & 0x0f) << 8)
    second = (b1 >> 4) | (b2 << 4)

candidate が `q` 未満なら採用し、そうでなければ捨てる。256 個集まるまで続ける。`candidate % q` としてはならない。それでは分布が偏る。

### SamplePolyCBD

ML-KEM-768 では `eta=2` である。各 coefficient に 4 bit を使う。

    x = bit[4i+0] + bit[4i+1]
    y = bit[4i+2] + bit[4i+3]
    coefficient = x - y

PRF input は `seed || nonce`、出力は SHAKE256 から得る。同じ seed でも polynomial ごとに nonce を増やす。

### 行列の suffix 順序

数学上の行列を `A[row][column]` として保存する場合は次である。

    A[row][column] = SampleNTT(rho || byte(column) || byte(row))

この一行を comment と test の両方へ残す。transpose bug は K-PKE round-trip だけでは見つからない場合がある。

### 合格 test

    make -C tutorial/scalar-mlkem chapter-04-sampling
    ./tutorial/scalar-mlkem/chapter-04-sampling

seed を `00,01,...,1f`、suffix を `01,02` とした先頭は次になる。

    sample prefix: 1642 1316 3309 3204 1436 289 1683 2323

### よくある失敗

- rejected 12-bit value を `mod q` で再利用する。
- SHAKE block の途中で parser state を失う。
- CBD の bit order を MSB-first にする。
- matrix の row と column を二度 transpose する。

### 完成条件

- SampleNTT の全 coefficient が `[0,3329)` にある。
- 同じ seed/suffix で同じ polynomial になる。
- CBD coefficient が `[-2,2]` にある。
- 固定 prefix test が一致する。

## ステップ 7: vector と matrix の式を固定する

K-PKE を書く前に、index の意味を紙に固定する。

| 値 | C の保存方法 | 式 |
| --- | --- | --- |
| `A` | `matrix[row][column]` | `SampleNTT(rho||column||row)` |
| keygen の `t[row]` | row を固定 | `sum_column A[row][column]*s[column] + e[row]` |
| encrypt の `u[column]` | column を固定 | `sum_row A[row][column]*r[row] + e1[column]` |
| encrypt の `v` | vector dot | `sum_i t[i]*r[i] + e2 + mu` |

全ての積は NTT domain で行い、`u` と `v` だけ inverse NTT で通常 domain に戻す。`s_hat` と `t_hat` は key の中でも NTT domain のまま encode する。

三項 dot product は最初は明示的に書く。

    out = MultiplyNTTs(a0, b0);
    out += MultiplyNTTs(a1, b1);
    out += MultiplyNTTs(a2, b2);

汎用 matrix library を導入しない。固定された `k=3` の index が見える方が、最初の実装では安全である。

### 完成条件

- keygen が `A*s`、encrypt が `A^T*r` を使うことを説明できる。
- key 内で通常 domain と NTT domain のどちらが encode されるか答えられる。
- `matrix[row][column]` の SHAKE suffix を即答できる。

# 第 III 部 K-PKE から ML-KEM を組み立てる

## ステップ 8: K-PKE.KeyGen を作る

`kpke.c` を作る。K-PKE はこの章以降でも ML-KEM 内部からだけ呼ぶ。

### seed expansion

FIPS 203 では 32-byte `d` の末尾に parameter `k=3` を追加し、SHA3-512 で 64 byte に展開する。

    domain_seed = d || byte(3)
    rho || sigma = SHA3-512(domain_seed)

`d` だけを hash する古い Kyber 形式にすると、自己 round-trip は通っても FIPS output と一致しない。

### secret と error

    s[i] = CBD(PRF(sigma, i), eta1)       for i=0..2
    e[i] = CBD(PRF(sigma, i+3), eta1)     for i=0..2
    s_hat[i] = NTT(s[i])
    e_hat[i] = NTT(e[i])

### public vector

    t_hat[row] = sum_column A_hat[row][column] * s_hat[column]
                 + e_hat[row]

### wire format

    dkPKE = ByteEncode_12(s_hat[0])
          || ByteEncode_12(s_hat[1])
          || ByteEncode_12(s_hat[2])

    ekPKE = ByteEncode_12(t_hat[0])
          || ByteEncode_12(t_hat[1])
          || ByteEncode_12(t_hat[2])
          || rho

この時点で `dkPKE=1152` byte、`ekPKE=1184` byte になる。

### 完成条件

- 同じ `d` から常に同じ key pair が得られる。
- `rho` が public key の最後の 32 byte にある。
- `d||3` を使う理由を parameter-set domain separation と説明できる。

## ステップ 9: K-PKE.Encrypt と Decrypt を作る

### Encrypt

public key から `t_hat` と `rho` を decode し、同じ `A` を再生成する。32-byte randomness `r_seed` から次を作る。

    r[i]  = CBD(PRF(r_seed, i),   eta1)  for i=0..2
    e1[i] = CBD(PRF(r_seed, i+3), eta2)  for i=0..2
    e2    = CBD(PRF(r_seed, 6),   eta2)

次に計算する。

    r_hat = NTT(r)
    u = inverse_NTT(A_hat^T * r_hat) + e1
    mu = Decompress_1(ByteDecode_1(message))
    v = inverse_NTT(t_hat^T * r_hat) + e2 + mu

暗号文は lossy compression を行って pack する。

    c = ByteEncode_10(Compress_10(u[0]))
      || ByteEncode_10(Compress_10(u[1]))
      || ByteEncode_10(Compress_10(u[2]))
      || ByteEncode_4(Compress_4(v))

### Decrypt

暗号文を decode/decompress し、secret key の `s_hat` を decode する。

    u = Decompress_10(ByteDecode_10(c1))
    v = Decompress_4(ByteDecode_4(c2))
    w = v - inverse_NTT(s_hat^T * NTT(u))
    message = ByteEncode_1(Compress_1(w))

正しい ciphertext では、`w` の各 coefficient が 0 または `q/2` の近くに残る。

### 合格 test

    make -C tutorial/scalar-mlkem chapter-05-kpke
    ./tutorial/scalar-mlkem/chapter-05-kpke

期待結果:

    chapter 05 - internal K-PKE round trip: OK

### この test だけでは足りない

Encrypt と Decrypt が同じ transpose error、nonce error、古い seed expansion を共有すると round-trip だけは通ることがある。次章で固定 projection と独立 product oracle を追加する。

### よくある失敗

- `r` と `e1` の nonce 範囲を重ねる。
- `u` の計算で `A` を使い、`A^T` を使わない。
- `t_hat` を inverse NTT してから dot product する。
- message bit 1 を `q/2` ではなく `1` として加える。
- ciphertext へ 12-bit lossless encoding を使い、長さを壊す。

### 完成条件

- 1000 個以上の deterministic input で K-PKE round-trip が通る。
- ciphertext が必ず 1088 byte になる。
- K-PKE を application API として公開していない。

## ステップ 10: ML-KEM.KeyGen と Encaps を作る

ML-KEM は K-PKE をそのまま公開せず、chosen-ciphertext attack に耐える KEM へ変換する。

### KeyGen_internal(d,z)

    (ekPKE, dkPKE) = K-PKE.KeyGen(d)
    ek = ekPKE
    dk = dkPKE || ek || SHA3-256(ek) || z

offset を定数として確認する。

| 範囲 | 内容 |
| --- | --- |
| `dk[0..1151]` | `dkPKE` |
| `dk[1152..2335]` | `ek` |
| `dk[2336..2367]` | `H(ek)` |
| `dk[2368..2399]` | `z` |

### Encaps_internal(ek,m)

    K || r = SHA3-512(m || SHA3-256(ek))
    c = K-PKE.Encrypt(ek, m, r)
    return K, c

`m` は K-PKE message であると同時に shared secret と encryption randomness を導出する input になる。

### 完成条件

- `dk` の四領域を byte offset で検査する test が通る。
- Encaps の出力が 32-byte secret と 1088-byte ciphertext になる。
- public key hash を再利用しても、その値が key に埋め込まれている理由を説明できる。

## ステップ 11: Decaps と implicit rejection を作る

Decaps は ciphertext が正しい場合だけでなく、改変された場合も 32 byte を返す。明示的な失敗を返して timing や protocol behavior を分けない。

### 再暗号化による検査

    m_dash = K-PKE.Decrypt(dkPKE, c)
    K_dash || r_dash = SHA3-512(m_dash || H(ek))
    c_dash = K-PKE.Encrypt(ek, m_dash, r_dash)

`c == c_dash` なら `K_dash` を返す。異なれば次の pseudorandom fallback を返す。

    K_reject = SHAKE256(z || c, 32)

### branchless selection

ciphertext 全体の差を OR し、mask を作る。

    difference = 0;
    for (i = 0; i < 1088; i++)
      difference |= c[i] ^ c_dash[i];

    reject = (difference | (0u - difference)) >> 31;
    mask = 0u - reject;
    K[i] = (K_dash[i] & ~mask) | (K_reject[i] & mask);

C source に branch がなくても compiler が secret-dependent branch を生成しないかは、製品化時に machine code で確認する。

### 合格 test

    make -C tutorial/scalar-mlkem test

期待する主要部分:

    04 keygen projection: OK
    05 ML-KEM round trip + implicit rejection: OK
    scalar ML-KEM-768: ALL TESTS PASSED

implicit rejection test は ciphertext の 1 bit を反転し、次を確認する。

- valid shared secret と一致しない。
- 同じ `z` と改変 ciphertext なら毎回同じ fallback になる。
- API は 32 byte を返し続ける。

### よくある失敗

- mismatch 時に all-zero key を返す。
- `SHAKE256(c||z)` と順序を逆にする。
- `memcmp` の結果で早期 return する。
- `c_dash` の比較を先頭数 byte だけにする。
- invalid ciphertext の内容を error message に含める。

### 完成条件

- valid ciphertext で sender と receiver の `K` が一致する。
- 改変 ciphertext で deterministic pseudorandom fallback が返る。
- compare と select が全 1088 byte を常に処理する。

## ステップ 12: 自己一致から仕様一致へ進む

round-trip は必要だが十分ではない。異なる種類の oracle を重ねる。

### primitive KAT

- SHA3-256 empty input
- SHAKE128 empty input
- fixed SampleNTT prefix
- ByteEncode/Decode round-trip

### arithmetic oracle

- forward/inverse NTT round-trip
- NTT multiplication と schoolbook multiplication の一致
- coefficient range assertion

### keygen projection

`tutorial/scalar-mlkem/test.c` は NIST ACVP ML-KEM-768 keyGen internal projection の `d` と `z` を使い、`SHAKE256(ek)` の先頭 16 byte が次になることを確認する。

    4d7f7325503c06f0cbfac8cd8744894f

この test は特に `G(d||k)`、matrix suffix、NTT ordering、key encoding をまとめて検査する。

### 独立 product oracle

教材用 scalar と、この repository の最適化済み実装へ同じ deterministic input を渡し、全 byte を比較する。

    make -C tutorial oracle

期待結果:

    educational scalar == product oracle (16 fixtures): OK

比較対象は 16 個の fixture に対する `ek`、`dk`、`c`、Encaps の `K`、valid/invalid Decaps の `K` である。

### sanitizer

自分の作業ディレクトリでも warning と sanitizer を有効にする。

    make clean
    ASAN_OPTIONS=detect_leaks=0 make \
      CFLAGS='-O1 -g -std=c11 -Wall -Wextra -Wpedantic -fsanitize=address,undefined' test

### 初級編の卒業条件

- 空のディレクトリから各 module を作り直せる。
- FIPS の各式と C function の対応を説明できる。
- K-PKE round-trip、KEM round-trip、negative test、KAT、oracle がすべて通る。
- 初級実装を実運用へ出してよいとは考えていない。

# 第 IV 部 最適化の準備

## ステップ 13: 変更前の速度とサイズを固定する

最適化は「速そうなコードを書くこと」ではない。測定条件を固定し、同じ正しさ gate を通した一変更だけを比較することである。

教材用 baseline benchmark を動かす。

    make -C tutorial/scalar-mlkem bench

出力は環境により変わる。

    educational scalar baseline (wall-clock; lower is better)
    keygen       ... ns/op (median of 9)
    encaps       ... ns/op (median of 9)
    decaps       ... ns/op (median of 9)

### 測定条件に必ず記録するもの

- CPU model と microcode
- OS と kernel
- compiler と version
- compile flags と target ISA
- CPU pinning
- warmup 回数、sample 数、iteration 数
- keygen、encaps、decaps の input policy
- cache を operation 間で持ち越すか
- binary size の定義

Linux で一つの CPU へ固定する例:

    taskset -c 0 ./tutorial/scalar-mlkem/bench_scalar 1000

### benchmark の罠

- compiler が結果を未使用として削除する。
- keygen だけ input を変え、encaps は同じ公開鍵 cache を暗黙利用する。
- baseline と candidate を別の負荷状態で測る。
- fastest sample 一つだけを採用する。
- test/benchmark 用 table や cache を product size から除外し忘れる。

### 完成条件

- 同じ binary を 9 回測り、中央値の変動幅を把握する。
- keygen、encaps、decaps を別々に測る。
- baseline の test と oracle が通った記録を速度値と一緒に残す。

## ステップ 14: profile して hot stage を決める

推測で最適化順を決めない。

    perf stat -r 9 taskset -c 0 ./tutorial/scalar-mlkem/bench_scalar 1000
    perf record -g taskset -c 0 ./tutorial/scalar-mlkem/bench_scalar 5000
    perf report

権限上 `perf` が使えなければ、Keccak、sampling、NTT、encode、K-PKE matrix product の前後へ timing harness を置く。ただし timer call 自体の overhead を測り、十分大きい iteration 数で割る。

最適化候補ごとに次の表を一行書く。

| 項目 | 記録内容 |
| --- | --- |
| hypothesis | 何が遅く、なぜ置換で減るのか |
| affected operation | keygen / encaps / decaps |
| correctness oracle | どの test が差を検出するか |
| speed gate | 最小改善量と sample 数 |
| size gate | 増加を許す byte 数 |
| result | 採用または却下と理由 |

### 完成条件

- top hot function が全 runtime の何パーセントか分かる。
- 1% 未満の stage を最初の対象にしていない。
- speed と size の両方に事前の判定基準がある。

# 第 V 部 scalar を速くする

## ステップ 15: zeta 生成を static table にする

初級版は NTT ごとに modular exponentiation で zeta を作る。最初の小さい最適化として、128 個を一度生成し、source table として固定する。

手順:

1. 初級版の `make_zetas` で 128 個を生成する小さな tool を作る。
2. 出力 table の各値が `17^BitRev7(i) mod q` と一致する test を残す。
3. NTT から exponentiation を外す。
4. `chapter-03-ntt`、full test、oracle を実行する。
5. speed と `.rodata` 増加を測る。

table を手で転記しない。generator と relation test を残すことで、table corruption と source drift を検出できる。

### 採用条件

- NTT multiplication oracle が全件一致する。
- key/ciphertext が byte-identical である。
- measured speedup が benchmark noise より大きい。
- 256-byte 前後の table 増加をサイズ目的に照らして説明できる。

## ステップ 16: `% q` を Barrett と Montgomery に置き換える

C の `%` と整数除算は hot loop では高価になりやすい。まず reduction の契約を分ける。

- canonical reduction: `[0,q)` を返す。
- centered reduction: 小さい正負 interval を返す。
- Montgomery reduction: `a * R^-1 mod q` を返す。

`R=2^16` とし、NTT root と coefficient の representation を明示する。Montgomery 値と通常値を無言で混ぜてはいけない。

典型的な Montgomery reduction の形:

    t = (int16_t)a * QINV;
    t = (a - (int32_t)t * Q) >> 16;

この数行だけを写しても安全ではない。input range、`QINV` の符号、signed shift、出力 interval を証明して test する。

### 段階的な置換順

1. standalone reduction oracle を作る。
2. BaseCaseMultiply だけ Montgomery にする。
3. forward NTT を置換する。
4. inverse NTT と normalization を置換する。
5. matrix dot product の accumulation range を固定する。
6. 不要になった canonicalization だけを最後に削る。

各段階で schoolbook oracle と product oracle を通す。一度に全 arithmetic を置換すると、余分な `R` factor の位置を特定できなくなる。

### range test

random test だけでなく boundary を含める。

- `0, 1, q-1`
- centered interval の両端
- butterfly の最大和と最大差
- 3 項 accumulation の上下限
- inverse NTT 各 level の範囲

### 完成条件

- 各 function の input/output representation が header comment にある。
- 全 stage の最大絶対値が `int16_t` または `int32_t` に収まる根拠がある。
- scalar optimized output が初級版と byte-identical である。

## ステップ 17: bit loop と CBD を固定長化する

ML-KEM-768 で実際に使う `d` は 1、4、10、12 だけである。汎用 `edu_byte_encode(d)` を oracle として残し、固定長 helper を追加する。

例:

- 12-bit coefficient 二つを 3 byte に pack する。
- 10-bit coefficient 四つを 5 byte に pack する。
- 4-bit coefficient 二つを 1 byte に pack する。
- 1-bit coefficient 八つを 1 byte に pack する。

CBD eta=2 は 32-bit word の偶数 bit をまとめて数えられる。

    d = t & 0x55555555;
    d += (t >> 1) & 0x55555555;

その後 4 bit ごとに低い 2 bit と高い 2 bit の差を取る。汎用 bit-by-bit CBD と全 coefficient を比較する oracle を残す。

### 採用条件

- 全 `d` の exhaustive local pack pattern が generic 版と一致する。
- unaligned load/store と strict aliasing を壊さない。
- compiler が生成した命令数が実際に減る。
- code size 増加が speed goal に見合う。

## ステップ 18: Keccak を用途ごとに固定長化する

初級版の sponge は任意長 input/output を扱う。ML-KEM の hot path には固定された shape が多い。

- `SHA3-512(d||3)` は 33-byte input、64-byte output。
- `SHA3-512(m||H(ek))` は 64-byte input、64-byte output。
- PRF は `32-byte seed || 1-byte nonce`。
- matrix XOF は `32-byte rho || 2-byte suffix`。
- rejection key は `32-byte z || 1088-byte c` から 32 byte。

汎用 sponge を oracle として残し、固定長 absorb/padding/store を一用途ずつ追加する。最初から 24 round を assembly にしない。

### 検査する境界

- rate をちょうどまたぐ input
- padding lane
- suffix byte の位置
- final squeeze で本当に必要な lane
- `z||c` の順序と全 1120 byte の吸収

### 採用条件

- generic Keccak と固定長 helper が exhaustive fixture で一致する。
- complete keygen/encaps/decaps が改善する。
- helper 単体だけ速くても caller 全体が悪化するなら採用しない。

# 第 VI 部 operation 全体を設計し直す

## ステップ 19: 再計算と一時配列を減らす

primitive が速くなった後に dataflow を見る。同一 operation 内でのみ安全に再利用できるものを探す。

- public key decode と `H(ek)`
- `A` の matrix sampling
- NTT-domain の `r_hat`
- 3 行または 4 出力が共有する積の一部
- inverse NTT 最終段と error/message addition
- compress と byte encoding

最初は function を融合せず、producer と consumer の間の representation と lifetime を表にする。その後、一時 array を一つずつ削る。

### cache の境界

benchmark process 内で前回の公開鍵や行列を global cache に残すと、API call 単体より不自然に速く見える。製品 artifact の比較では、caller が契約していない persistent cache を使わない。同じ KeyGen または Encaps の内部で共有する transient work は別である。

### completion gate

- cache cold/warm の意味を benchmark label に明記する。
- production API の default path は hidden persistent state に依存しない。
- stack/BSS 増加を測る。
- operation 全体の speedup を確認する。

## ステップ 20: fusion は最後の consumer から始める

良い fusion 候補は、producer の全出力を memory に保存してから consumer が一度だけ読む場所である。

候補:

1. inverse NTT 最終 reduction + error addition
2. inverse NTT + message addition
3. compression + byte packing
4. matrix dot accumulation + final reduction
5. Keccak squeeze + rejection parser
6. PRF squeeze + CBD

fusion 前後で内部表現が変わる場合、最終 byte output だけでなく stage output も比較する。最終 KEM output 一つでは、二つの誤りが相殺される可能性がある。

### 却下する条件

- helper benchmark は速いが complete operation が遅い。
- register pressure により spill が増える。
- code duplication が primary size を大きく悪化させる。
- range proof が曖昧になる。
- compiler ごとに一方が大きく退行する。

# 第 VII 部 SIMD へ進む

## ステップ 21: AVX2 の前に lane layout を紙に書く

AVX2 では 16 個の `int16_t` coefficient を一つの YMM register に置ける。intrinsic を書く前に、次を決める。

- coefficient index と lane の対応
- NTT stage ごとの shuffle
- twiddle factor の並び
- Montgomery low/high product の組み合わせ
- signed range と reduction point
- load/store alignment の契約

最初の AVX2 function は poly add のような簡単なものではなく、profile 上の hot stage かつ scalar oracle が強いものを選ぶ。通常は NTT、BaseCaseMultiply、CBD、packing のいずれかになる。

### build matrix

最低でも三つの build を保つ。

| build | 目的 |
| --- | --- |
| scalar | ISA 非依存 oracle |
| AVX2 only | AVX512 が偶然使われていないことを確認 |
| native | 対象 CPU の最速 path |

AVX2-only の例:

    CFLAGS='-O3 -mavx2 -mno-avx512f -mno-avx512bw' make test

実際の repository では Makefile の ISA option を使い、scalar/native product test も通す。

### 完成条件

- scalar と AVX2 の stage output が全 coefficient 一致する。
- disassembly で意図しない scalar division が hot loop に残っていない。
- illegal-instruction を避ける dispatch または build contract がある。
- AVX2-only binary で test している。

## ステップ 22: 複数 Keccak state を並列化する

ML-KEM は独立した SHAKE state を同時に多数使う。

- 3x3 matrix の 9 state
- secret/error の複数 PRF state
- encryption の `r,e1,e2`

AVX2 では x4、AVX512 では x8 の state parallel Keccak が候補になる。これは一つの hash latency を短くするのではなく、独立 state の throughput を上げる最適化である。

進め方:

1. scalar 一状態を oracle とする。
2. x4 の各 lane に異なる input を入れる。
3. permutation 後の全 25 lane を scalar と比較する。
4. squeeze output を比較する。
5. rejection parser/CBD と結合する前に単体を通す。
6. x8 も同じ test を再利用する。

### よくある失敗

- four-state lane layout と one-state vector layout を混ぜる。
- suffix だけ異なる state の padding lane を共有しすぎる。
- matrix の 9 個目だけ scalar fallback になり、data order を壊す。
- parallel helper 単体の throughput だけで complete KEM 改善を主張する。

## ステップ 23: AVX512 は AVX2 の幅を倍にするだけではない

AVX512 では 32 個の `int16_t` lane、mask register、より多い vector register を使える。単純な YMM から ZMM への置換より、複数 output の共有項を register に保持する設計が重要になる。

候補:

- keygen の 3 output column accumulation
- encryption の `u[0..2]` と `v` の 4 output accumulation
- x8 matrix sampling
- compact signed `int8_t` noise から consumer 直前で widen
- inverse NTT と add/compress の共有 final stage

ただし AVX512 は downclock、compiler 差、VNNI の有無を分けて測る。対象 CPU で AVX512 が存在するだけでは採用理由にならない。

### 完成条件

- AVX512/VNNI 有効、AVX512 有効かつ VNNI 無効、AVX2-only を別々に測る。
- GCC と Clang の両方で correctness を確認する。
- non-target build の code/output が意図せず変わっていない。
- complete operation と roundtrip が改善する。

## ステップ 24: assembly は compiler output を読んでから使う

assembly の対象は、C intrinsic で表現した正しい algorithm があり、profile と disassembly から具体的な無駄が確認できた小さい範囲に限定する。

良い候補:

- 固定 register mapping の Keccak round core
- 固定 twiddle schedule の NTT stage
- fixed-length SHA3 absorb/squeeze
- compiler が毎回 spill/reload する共有 accumulation

悪い候補:

- API 全体を一度に assembly 化する。
- oracle がない parser を assembly 化する。
- 1 CPU の最小 sample だけを根拠にする。
- ABI、callee-saved register、stack alignment を test しない。

assembly path には scalar/intrinsic oracle、ABI test、ISA inspection、stack check を付ける。

# 第 VIII 部 小さくする

## ステップ 25: product artifact を分離する

サイズを測る対象から次を外す。

- test vector
- benchmark harness
- debug print
- generic oracle
- schoolbook multiplication
- 未使用 ISA path
- generator

一方、実行に必要な dispatch、constant table、wrapper、linked assembly は全て含める。速さを測る artifact とサイズを測る artifact の code path が違ってはいけない。

この repository の product API は `baby_mlkem_api.h` であり、次で構築・計測できる。

    make product
    make product-size
    make test-product

### linker と section

    -ffunction-sections -fdata-sections
    -Wl,--gc-sections

section GC を使った場合も、公開 API 三関数を呼ぶ smoke program を link して測る。object file 全体の大きさと、実際に reachable な product footprint を混同しない。

### 完成条件

- primary footprint の定義が固定されている。
- test/bench data が product に入っていない。
- speed benchmark が測る API と size artifact の API が同じである。
- symbol/section report から上位の size contributor を説明できる。

## ステップ 26: table、汎用性、重複 code を選ぶ

速度用 table は `.rodata` を増やし、汎用 loop は `.text` を減らすが遅くなることがある。最小化は単純に source line を減らす作業ではない。

候補を一つずつ測る。

- zeta table を生成 code に戻すか
- compiler ごとの duplicated helper を共有するか
- fixed-length Keccak helper を generic sponge に戻すか
- AVX2/AVX512 constant を共有できるか
- inline を外して call overhead と text reduction を比較するか
- rare fallback を cold section に分けるか

速度とサイズの Pareto frontier を記録する。両方で劣る候補は却下し、一方だけ優れる候補は目的に応じて残す。

# 第 IX 部 「最速・最小」を検証可能な主張にする

## ステップ 27: 比較対象と条件を先に固定する

「世界最速」は永久的な事実ではない。次を固定した再現可能な比較の短縮表現としてだけ使う。

- CPU と利用 ISA
- compiler/toolchain
- ML-KEM-768 API と deterministic/random input policy
- cache policy
- keygen、encaps、decaps、roundtrip の全 label
- competitor source と build option
- iteration、warmup、sample、統計量
- speed と size を測る同一 product artifact

一つの operation だけ勝っていても KEM 全体の最速とは呼ばない。全 label に事前の最小 speedup を設定する。

## ステップ 28: paired benchmark と noise gate を使う

baseline を全回測ってから candidate を全回測ると、温度や background load の drift を拾う。可能なら次の順で対にする。

    baseline, candidate, candidate, baseline

複数 pair から ratio を作り、median、geometric mean、confidence interval を見る。改善が noise floor と同程度なら、速くなったとは判定しない。

記録する最低項目:

- raw sample
- pair ごとの direction
- median ratio
- geometric mean
- wins/total
- confidence interval または bootstrap interval
- CPU migration と outlier の扱い

## ステップ 29: repository の正式 gate を通す

初級版で algorithm を理解し、自分の candidate を product path へ統合した後は repository 全体の gate を使う。

正しさ:

    make clean
    make test
    make test-product
    make check-ntt-roots

通常の比較:

    PIN_CPU=0 C_COMPILER=clang SHOW_FULL_OUTPUT_ON_FAIL=0 \
      ./scripts/verify_world_fastest.sh 600 2

厳格な二段比較:

    PIN_CPU=0 C_COMPILER=clang SHOW_FULL_OUTPUT_ON_FAIL=0 \
      ./scripts/verify_world_fastest_strict.sh 600 2

外部 comparator の取得や更新には network が必要になる。最終 run では、比較対象、toolchain、raw report を保存する。

### 不合格時にすること

- 失敗 label だけを隠さない。
- iteration を減らして通しやすくしない。
- faster sample が出るまで無制限に再実行しない。
- correctness failure を benchmark noise と扱わない。
- size artifact を別 build に差し替えない。

原因を stage benchmark へ戻して特定し、仮説が外れた candidate は理由とともに却下する。

## ステップ 30: 最短の推奨最適化順

初級完成版から次の順で進むと、各段階の学習目的が分離しやすい。

1. baseline の CPU pinning と中央値を固定する。
2. zeta を生成 table にする。
3. reduction oracle を作り、Montgomery BaseCaseMultiply を導入する。
4. forward/inverse NTT を Montgomery 化する。
5. d12/d10/d4/d1 の固定 packer を作る。
6. CBD eta2 を bit-parallel 化する。
7. fixed 33-byte/34-byte/64-byte Keccak input を specialized する。
8. PRF+CBD、SHAKE+rejection parser を融合する。
9. K-PKE の 3/4 output accumulation で共有項を再利用する。
10. AVX2 NTT と packer を scalar oracle と比較する。
11. AVX2 x4 Keccak で matrix/noise throughput を上げる。
12. AVX512 x8 と 4-output accumulation を評価する。
13. compiler が残した具体的 bottleneck だけ assembly 化する。
14. production artifact から oracle/test/unused path を除く。
15. full correctness、speed、size gate を同一 artifact で通す。

一項目ごとに「正しさ test → stage speed → complete operation → size」の順で判定する。二つ以上の algorithm change を同じ candidate に入れない。

# 付録 A 完成解答のファイル対応

| 読む順 | ファイル | 主な内容 |
| ---: | --- | --- |
| 1 | `tutorial/00-scratch/main.c` | N=8 negacyclic ring |
| 2 | `tutorial/scalar-mlkem/params.h` | ML-KEM-768 parameter と size |
| 3 | `tutorial/scalar-mlkem/poly.c` | mod q、加減算、schoolbook oracle |
| 4 | `tutorial/scalar-mlkem/keccak.c` | Keccak-f、SHA3、SHAKE |
| 5 | `tutorial/scalar-mlkem/encoding.c` | encode/decode/compress |
| 6 | `tutorial/scalar-mlkem/ntt.c` | 通常剰余 NTT と BaseCaseMultiply |
| 7 | `tutorial/scalar-mlkem/sampling.c` | rejection sampling、CBD、matrix |
| 8 | `tutorial/scalar-mlkem/kpke.c` | 内部 K-PKE |
| 9 | `tutorial/scalar-mlkem/mlkem.c` | KEM transform、implicit rejection |
| 10 | `tutorial/scalar-mlkem/test.c` | KAT、projection、negative test |
| 11 | `tutorial/scalar-mlkem/test_oracle.c` | 製品実装との全 byte 比較 |
| 12 | `tutorial/scalar-mlkem/bench.c` | 初級 baseline benchmark |

# 付録 B 最終 checklist

初級実装:

- [ ] SHA3/SHAKE KAT が通る。
- [ ] d12 encoding round-trip が通る。
- [ ] fixed SampleNTT prefix が一致する。
- [ ] NTT multiplication が schoolbook と一致する。
- [ ] K-PKE round-trip が通る。
- [ ] ACVP keygen projection が一致する。
- [ ] ML-KEM valid round-trip が通る。
- [ ] 改変 ciphertext で implicit rejection が動く。
- [ ] product oracle と全 byte が一致する。
- [ ] sanitizer と warning build が通る。

最適化実装:

- [ ] scalar oracle を残している。
- [ ] arithmetic representation と range が文書化されている。
- [ ] scalar、AVX2-only、native の build が通る。
- [ ] persistent hidden cache に依存しない。
- [ ] complete keygen/encaps/decaps を測っている。
- [ ] speed と size が同じ product artifact を対象にしている。
- [ ] raw sample と却下した実験を残している。
- [ ] comparison 条件を固定した上でのみ最速・最小を主張している。

この checklist を全部通したとき、最初の 8 次多項式から ML-KEM-768 の byte 列、さらに高速 product artifact までが一本の因果関係としてつながる。目標は最終 code を写すことではなく、各置換がなぜ正しく、なぜ速く、なぜ小さいかを自分で説明できることである。
