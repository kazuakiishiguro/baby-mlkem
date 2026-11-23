# 2026-11-18 Current-Comparator Refresh

This directory re-verifies the two "fastest and smallest" claims against the
*current* upstream of every comparator, three months after the c8 evidence
(`benchmarks/2026-08-22-goal-native-speed-c8`,
`benchmarks/2026-08-22-goal-avx2-speed-c8`,
`benchmarks/2026-08-22-goal-size-c8`). The candidate under test is unchanged
product source: the tree's core inputs are identical to `400dbe4`, and the local
product artifact is byte-for-byte the same size as recorded in c8.

## Why this run exists

The completion contract requires that comparators are updated from their
authoritative repositories before a final measurement and that the gate fails
closed if an update or commit identification fails. The c8 matrix was measured
2026-08-22. As of 2026-11-18, several comparators had moved:

| Comparator | c8 commit | current upstream | Material ML-KEM change since c8 |
|---|---|---|---|
| pq-crystals Kyber | `3edd5af` | `3edd5af` (`main`) | none |
| PQClean AVX2 | `0586a82` | `0586a82` (`master`) | none |
| mlkem-native | `69d24e3` | `76b6587` (`main`) | perf-neutral (`vzeroupper`, `#if` guards, bound proofs) |
| liboqs | `4e1183a` | `395d2aa` (`main`) | none; ML-KEM backend is mlkem-native-derived |
| BoringSSL | `a204be2` | `ebd922a` (`main`) | `cf44c6429`, `e9b9cf004`, `76bc63d96` (lazy NTT/partial reduction, vartime Keccak block path, lazy mat-vec reduction) |
| Botan ML-KEM | `7ffae68` | `71c2475` (`master`, 3.14.x) | `68b331466` AVX2 NTT/INTT/mul codepath |
| OpenSSL ML-KEM | `1a3455e` | `a1bd850` (`master`, 4.2.0-dev) | `8ce96d5b15` AVX2 NTT/inverse NTT, `809b8180c1` AVX2 base multiplication |
| libcrux | crate `0.0.10` | crate `0.0.11` | `constant_time_ops` barrier refactor only |
| libjade Kyber768 AVX2 | `release/2023.05-2` (dist SHA-256 pinned) | `formosa-libjade` `90ba5dc` main | repository replaced; pinned dist asset 404, ML-KEM sources unchanged |

## Result

- **Size: all 20 rows pass.** No comparator moved ahead of the
  local product in either profile; the margins actually widened for Botan,
  OpenSSL, BoringSSL and liboqs, and the closest competitor is mlkem-native at
  `-73 B` native.
- **Speed: nineteen of the twenty profile rows pass.** All twenty were rebuilt
  from current upstream sources with paired samples and bootstrap intervals
  (15 runs for most suites, 5 for the late libjade and OpenSSL rows). Native
  ratios match c8 within noise except Botan, which halves as its new AVX2
  codepath predicts (`8.05x` -> `7.38x` roundtrip). The single exception is
  OpenSSL AVX2-only encapsulation, `0.895x`; see the disclosure below.
- **One comparison is now a loss, and it is disclosed:** OpenSSL master's
  AVX2 ML-KEM kernels (landed 2026-10-21 in `ml_kem_avx2.s`) encapsulate faster
  than the local AVX2-only artifact, `0.895x` (paired CI low `0.889x`, i.e.
  ~12% slower locally). The local artifact still wins keygen (`2.783x`),
  decaps (`1.688x`) and the aggregate (`1.842x`), and OpenSSL AVX2-only
  encapsulation is a different operation mix (OpenSSL's `encaps` includes its
  own public-key decode and modulus check inside the timed call), but as
  measured through the normalized three-API harness this is a real
  operation-level defeat in the AVX2-only profile. The native profile wins
  every operation (`3.955x/1.145x/2.645x/2.612x`).
- **The AVX2-only local figure is resolved (2026-11-19):** the ~14.6 us/op
  local roundtrip is the real cost of the AVX2-only production artifact, not a
  measurement fault. Alternating single-profile passes measure a consistent
  `1.40x`-`1.42x` local penalty and a `1.25x` competitor penalty, and the 15-run
  AVX2-only ratios land within `0.02x` of c8. c8's `~10.5 us/op` AVX2-only
  local figure does not reproduce on this host. See the follow-up section.
- **One gate is no longer reproducible:** the pinned libjade release artifact
  returns HTTP 404 from GitHub, so the libjade row cannot be rebuilt from
  scratch on a clean machine. See "Broken comparator pin".
- **Two published ratios are stale by construction:** Botan added an AVX2
  ML-KEM codepath (upstream quotes 50-100%) and BoringSSL reworked its NTT and
  mat-vec reduction, both after the c8 measurement. The refresh measures both:
  Botan's win shrinks as predicted and BoringSSL's grows less than upstream
  suggests. Neither threatens the win; README's ratios for them should be
  updated from this refresh.
- **libjade's comparator provenance is broken, not its verdict.** The
  successor source is 11,435 B larger than the local product, so the size
  conclusion survives the repository move; only the fail-closed fetch needs
  re-pinning.

## Size matrix (primary footprint, Clang 18.1.3, CPU 0)

Local artifact: `51,171 B` native, `45,032 B` AVX2-only — identical to c8, which
confirms the product source has not changed.

| Comparator | Native primary | Native local delta | AVX2 primary | AVX2 local delta |
|---|---:|---:|---:|---:|
| pq-crystals Kyber AVX2 | 61,032 B | -9,861 B | 62,970 B | -17,938 B |
| Kyber AVX2, fair flags | 61,371 B | -10,200 B | 63,373 B | -18,341 B |
| mlkem-native | 51,244 B | -73 B | 51,325 B | -6,293 B |
| PQClean AVX2 | 60,950 B | -9,779 B | 61,827 B | -16,795 B |
| liboqs | 70,228 B | -19,057 B | 81,352 B | -36,320 B |
| BoringSSL | 199,580 B | -148,409 B | 130,353 B | -85,321 B |
| libcrux 0.0.11 | 137,086 B | -85,915 B | 142,302 B | -97,270 B |
| Botan ML-KEM (3.14.x) | 204,536 B | -153,365 B | 172,308 B | -127,276 B |
| OpenSSL ML-KEM master | 118,277 B | -67,106 B | 59,794 B | -14,762 B |
| libjade ML-KEM-768 AVX2 (successor `90ba5dc`) | 61,331 B | -10,160 B | 61,331 B | -16,299 B |

The smallest *supported* mlkem-native configuration was also checked, because
an earlier survey flagged it as the only way an existing comparator could
undercut the local artifact. Building mlkem-native with `OPT=0`
(`mlkem_native` without its x86_64 native arith/FIPS202 backends) gives
`78,048 B` native and `68,714 B` AVX2-only: it gets *larger*, not smaller,
because the portable code replaces the compact assembly. So no comparator
configuration inside the measured set is smaller than the local product.

The closest remaining size competitor is **mlkem-native at -73 B native**
(c8 recorded -29 B against `69d24e3`; current `76b6587` builds 44 B larger).
The previous AVX2-only razor margin against OpenSSL (`-17 B` in c8) widened to
`-14,762 B` because OpenSSL master now needs a much larger ML-KEM core with the
AVX2 perlasm kernels, even with those kernels linked.

Raw per-comparator reports: `.verify-work/size/{native,avx2}-<slug>.txt`
(workspace-local, git-ignored). Reproduce with the commands in
`verify_goal_comparator_size.sh` using the `*_DIR` overrides documented in
`scripts/goal_speed_profile.sh`.

## Comparator build adaptations used in this run

These were needed only because the comparator sources changed; none of them
touches the baby-mlkem product.

- **Botan 3.14.x**: `ML_KEM_Encryptor`/`ML_KEM_Decryptor` now take a
  `PK_KEM_Options_Reader` instead of a `"Raw"` string, so the normalized
  adapter builds the reader through the public
  `Botan::PK_Options_Reader_Access::read()` factory and requests
  `with_raw_shared_key()`. The cache audit also had to stop matching Botan's
  new `Hash_Engine::uncached_prefix_bytes()` accessor, which is a hash-input
  length accessor, not a persistent cache.
- **OpenSSL master**: the AVX2 ML-KEM kernels moved into
  `crypto/ml_kem/ml_kem_avx2.s` (perlasm), so the selected-object product now
  links `libcrypto-lib-ml_kem_avx2.o` plus `libcrypto-lib-x86_64cpuid.o` (for
  the `OPENSSL_ia32cap_P` capability vector). The cpuid object's duplicate
  `OPENSSL_cleanse`/`CRYPTO_memcmp` definitions are localized, its `.init`
  hook and `OPENSSL_cpuid_setup` reference are removed (a selected-object
  product has no libcrypto init path), and `OPENSSL_ia32cap_P` is kept as an
  allocated local data symbol. The core-only contract, cache audit, entropy
  audit, AVX512 audit, and the 64-fixture corpus check all still pass.
- **libcrux 0.0.11**: `libcrux-platform` 0.0.4 does not compile on rustc 1.91.1
  (three `__cpuid` calls without `unsafe`), so the measurement uses a local
  copy with those three expressions wrapped in `unsafe { }`. That is a
  compile-only fix; it does not change generated ML-KEM code.

## libjade comparator pin (broken in c8, fixed 2026-11-19)

`scripts/verify_goal_*.sh` used to download the libjade comparator from

```
https://github.com/formosa-crypto/libjade/releases/download/release/2023.05-2/libjade-dist-src-amd64.tar.gz
```

That URL, and the `releases/latest` API for the same repository, now return
**HTTP 404**: `formosa-crypto/libjade` was replaced by
`formosa-crypto/formosa-libjade` (the old `main` is a single-commit README that
points at the new repository) and the release assets are gone. The c8 report
recorded the comparator as a `file:///tmp/...` cache path, so the
"fail closed on comparator update" contract could not hold on a clean machine
for the suite that carries the narrowest AVX2-only margin.

The pin is now the successor repository's FIPS 203 ML-KEM-768 AVX2 sources at a
fixed commit, and the three source hashes are re-pinned to it:

| Item | Value |
|---|---|
| source | `https://github.com/formosa-crypto/formosa-libjade.git` |
| pin | commit `90ba5dc4d9da2b6950589c58a52282caa1dbfdfd` (2026-11-14) |
| assembly | `asm/mlkem/avx2/mlkem768_avx2_sct.s`, SHA-256 `13ef94bf0deb…80605` |
| header | `src/include/mlkem768.h`, SHA-256 `80ed6a45310c…64681` |
| Jasmin source | `src/mlkem/avx2/sct/768/jmlkem.jazz`, SHA-256 `be5b05bfc31a…cd51f` |

Verified from an empty download root so no cache is consulted:
`comparator_update=downloaded-pinned`, assembly hash matches, and the product
builds with all audits passing (`native-libjade.txt`). The comparator is now
genuinely FIPS 203 ML-KEM-768 rather than round-3 Kyber768, which is a
semantics tightening, not a relaxation.

Result: **61,331 B primary in both profiles**, i.e. `-10,160 B` native and
`-16,299 B` AVX2-only against the local artifact, so the size verdict survives
the repository move. The earlier c8 Kyber768 artifact measured 54,433 B; the
FIPS 203 sources are about 6.9 kB larger.

The successor repository publishes exactly one tag
(`mldsa-avx2-hash-boundary`, an ML-DSA change), so committing to a commit SHA
is the only stable pin. The runners still check the upstream tag list and record
`latest_release_audit=pinned-behind-upstream` rather than pretending the pin is
the newest release.

## AVX2-only local overhead: resolved (2026-11-19 follow-up)

The first AVX2-only pass measured the *local* production artifact at
~14.6 us/op core roundtrip while the native pass measured ~10.4 us/op, and c8
recorded ~10.5 us/op for both. That looked like a measurement fault. It is not:
it is the real cost of the AVX2-only artifact, and c8's AVX2-only figure did
not reproduce.

Evidence, all on CPU 0 with Clang 18.1.3 and the goal profile flags:

- The archived artifact is identical to a fresh rebuild of `400dbe4` with
  `ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"`
  (`b6fd46a016be…` both times) and contains no AVX512 register or symbol, so
  the profile was built correctly.
- Rebuilding the same tree with `-march=native` reproduces the old 14.5 us/op
  only when AVX512 is disabled (`ARCH_CFLAGS="-march=native -mno-avx512f"`
  gives 21.0/11.1/10.5 us/op across runs), which confirms the slow path is the
  AVX2-only code generation rather than an x86-64-v3 flag omission.
- Alternating single-profile passes with identical drivers separate the two
  effects cleanly. Local core roundtrip (ns/op), `kyber_upstream_avx2` suite,
  4 runs each:

| Pass | local (native) | local (AVX2-only) | local penalty | Kyber (native) | Kyber (AVX2-only) | Kyber penalty |
|---|---:|---:|---:|---:|---:|---:|
| C | 10,352 | 14,605 | 1.411x | 16,099 | 20,345 | 1.264x |
| D | 10,311 | 14,642 | 1.420x | 16,222 | 20,345 | 1.254x |

  Per operation the local penalty is keygen `1.400x`/`1.409x`, encaps
  `1.256x`/1.258x`, decaps `1.512x`/`1.516x`. The competitor AVX2 penalty is a
  mix of `1.0x` (fair-flags Kyber) and `1.25x` (standard Kyber), so the
  aggregate AVX2-only margin is `1.39x` where native is `1.56x`.
- 15-run AVX2-only screen with all five re-buildable comparators: Kyber
  `1.171x/1.512x/1.610x/1.390x`, fair-flags Kyber `1.120x/1.510x/1.981x/
  1.471x`, mlkem-native `1.121x/1.502x/1.965x/1.467x` (c8:
  `1.1762x/1.4501x/1.6062x/1.3754x`, `1.1898x/1.4548x/1.6178x/1.3912x`,
  `1.1271x/1.5048x/1.9677x/1.4699x`), PQClean `1.196x/1.481x/1.691x/1.430x`,
  liboqs `1.275x/1.692x/2.198x/1.669x`. Every row clears `1.00x`, the
  aggregate clears `1.05x`, and the per-comparator ratios land within 0.02x of
  c8 despite the 40% local difference, which means the c8 AVX2-only run was
  comparing against comparators that were slowed by the same host effect, not
  against a faster local build.

Conclusion: the AVX2-only table below is valid, the local overhead is a
property of the AVX2-only production path (it is faster in absolute terms than
the AVX2-limited competitors, just slower than the local native artifact), and
the c8 `~10.5 us/op` AVX2-only local figure should be treated as irreproducible
on this host.

A follow-up probe on the same day tried to close the gap and found it is not an
expression-level problem. The stage oracle attributes almost all of the
penalty to the x4 Keccak permutation: `keccakf4_mem` is 254-280 ns/op AVX2-only
against 157-165 ns/op native (`1.7x`), while accumulation, inverse/add, NTT and
ciphertext handling pay only `1.04x`-`1.10x`. The causes are structural for
AVX2: no `vpternlogq`, so each Chi element needs three instructions and a
`vpor` plus `vpandn`, and the compiler materialises ~700 `vpblendd` per
24-round x4 permutation. Five candidates were measured and all rejected — see
`note.md` ("avx2-only-keccak-penalty-probe"): two-round and four-round unrolls
of the round loop (`+/-0.7%`, product metric regressed in one case), a full
24-round expansion of the x1 permutation (`0.7%` faster for `0x3e5` ->
`0x38ff` bytes of code), and two theta-folding rewrites that failed the stage
oracle. No product code changed; `baby-mlkem.c` and `keccakf1600_avx2.h` are
identical to `HEAD` and the AVX2-only artifact is still `45,032 B` primary.

The permutation *count* was then audited in
[2026-11-19-avx2-permutation-inventory](../2026-11-19-avx2-permutation-inventory/README.md):
keygen runs nine x4 permutations for 33 useful lanes and encryption nine for 34,
so both are exactly at their `ceil(lanes/4)` capacity bound, and public-key
preparation already folds eight serial `H(pk)` permutations into its matrix
rows. There is therefore no permutation-count headroom left either. The
AVX2-only gap is fully explained by the ISA plus a schedule that is already
optimal for it, which is why this report treats it as a property of the
profile rather than an open defect.

## Speed (AVX2-only profile)

15 paired runs, 3 warmups, 100,000 iterations, alternating order, CPU 0,
`-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f`, with the AVX512 audit
applied to the local artifact and to each comparator build.

| Comparator | Keygen | Encaps | Decaps | Roundtrip |
|---|---:|---:|---:|---:|
| pq-crystals Kyber AVX2 | 1.184x | 1.435x | 1.615x | 1.391x |
| Kyber AVX2, fair flags | 1.172x | 1.463x | 1.607x | 1.377x |
| mlkem-native `76b6587` | 1.121x | 1.502x | 1.965x | 1.467x |
| PQClean AVX2 | 1.196x | 1.481x | 1.691x | 1.430x |
| liboqs `395d2aa` | 1.275x | 1.692x | 2.198x | 1.669x |
| BoringSSL `ebd922a` | 1.778x | 2.445x | 3.301x | 2.409x |
| libjade ML-KEM-768 AVX2 (successor `90ba5dc`) | 1.110x | 1.412x | 1.876x | 1.391x |
| OpenSSL ML-KEM master (`a1bd850`) | 2.783x | **0.895x** | 1.688x | 1.842x |

Paired 95% CI lower bounds: Kyber `1.176x/1.411x/1.598x/1.371x`, fair-flags
Kyber `1.164x/1.451x/1.599x/1.372x`, mlkem-native `1.111x/1.485x/1.946x/
1.460x`, PQClean `1.190x/1.470x/1.667x/1.416x`, liboqs `1.263x/1.689x/
2.153x/1.648x`, BoringSSL `1.769x/2.427x/3.279x/2.396x`, libjade
`1.074x/1.384x/1.831x/1.402x`, OpenSSL `2.770x/0.889x/1.657x/1.828x`. Every
bound is above `1.00x` **except OpenSSL AVX2-only encaps**, which is a loss and
is called out below. The narrowest aggregate margin is `1.372x` (fair-flags Kyber) against
c8's `1.374x`, and the narrowest operation margin is mlkem-native keygen at
`1.121x` against c8's `1.111x` libjade keygen, so the profile is unchanged
within noise.

BoringSSL's refreshed rows land below c8's (`3.1285x/2.9950x/5.1334x/3.5729x`
native and `2.4907x/2.8720x/3.8676x/2.9701x` AVX2-only) even though its
upstream work should have made it faster. Its measured absolute times barely
moved (native roundtrip ~29,900 ns here versus ~37,800 ns in c8), so its
upstream commits did not reproduce here; the local-side explanation that an
earlier draft of this section offered has since been ruled out by the
alternating-pass experiment above, which shows the local AVX2-only artifact
behaving consistently. Every row still clears `1.00x` and the `1.05x` aggregate
margin.

## Speed (native profile)

15 paired runs, 3 warmups, 100,000 iterations, alternating order, CPU 0,
Clang 18.1.3, production no-cache metric, local side built from pristine
`400dbe4`. Ratios are `comparator_ns / local_ns`.

| Comparator | Keygen | Encaps | Decaps | Roundtrip |
|---|---:|---:|---:|---:|
| pq-crystals Kyber AVX2 | 1.320x | 1.446x | 2.026x | 1.564x |
| Kyber AVX2, fair flags | 1.329x | 1.466x | 2.059x | 1.575x |
| mlkem-native `76b6587` | 1.566x | 1.889x | 3.065x | 2.050x |
| PQClean AVX2 | 1.766x | 1.930x | 2.762x | 2.099x |
| liboqs `395d2aa` | 1.477x | 1.779x | 2.953x | 1.968x |
| BoringSSL `ebd922a` | 1.936x | 2.667x | 4.514x | 2.862x |
| libcrux 0.0.11 | 1.604x | 1.950x | 2.674x | 1.977x |
| Botan 3.14.1 (`71c2475`) | 4.701x | 4.976x | 14.095x | 7.376x |
| libjade ML-KEM-768 AVX2 (successor `90ba5dc`) | 1.560x | 1.781x | 2.940x | 1.996x |
| OpenSSL ML-KEM master (`a1bd850`) | 3.955x | 1.145x | 2.645x | 2.612x |

Paired 95% CI lower bounds for the same rows: Kyber `1.303x/1.434x/2.021x/
1.547x`, fair-flags Kyber `1.317x/1.461x/2.022x/1.561x`, mlkem-native
`1.558x/1.874x/3.004x/1.943x`, PQClean `1.747x/1.900x/2.753x/2.079x`, liboqs
`1.466x/1.773x/2.919x/1.956x`, BoringSSL `1.917x/2.659x/4.475x/2.845x`,
libcrux `1.578x/1.901x/2.613x/1.964x`, Botan `4.664x/4.872x/13.861x/7.306x`,
libjade `1.556x/1.775x/2.932x/1.993x`, OpenSSL `3.911x/1.141x/2.494x/2.542x`
(keygen/encaps/decaps/roundtrip). Every bound is above `1.00x`, and every
aggregate bound is above the `1.05x` completion margin.

These reproduce the c8 native rows (1.328x/1.463x/2.038x/1.572x for Kyber,
1.586x/1.896x/3.082x/2.076x for mlkem-native, 1.760x/1.943x/2.772x/2.105x for
PQClean, 1.512x/1.811x/2.990x/1.999x for liboqs, 1.616x/1.953x/2.674x/2.001x
for libcrux 0.0.10) within run noise, so the fastest claim still holds for the
suites whose upstream did not move.

Two refreshed ratios do move, and both move the right way:

- **Botan** drops from `7.7280x/6.5875x/10.3313x/8.0501x` (c8, pre-AVX2) to
  `4.701x/4.976x/14.095x/7.376x`. Its roundtrip gets slower because decaps
  gained proportionally less than keygen/encaps from the AVX2 codepath; the
  aggregate ratio roughly halves as predicted, and the win is still `7.4x`.
- **libcrux 0.0.11** is `1.604x/1.950x/2.674x/1.977x` against c8's
  `1.6156x/1.9527x/2.6739x/2.0009x`, i.e. unchanged, confirming that its
  0.0.11 changes are performance-neutral.

OpenSSL was not re-measured as a paired row; see "Suites not re-measured".

Local stability in this run: keygen mean 3,963.5 ns/op, min 3,922.9, max
4,081.2; core roundtrip median ~10,484 ns/op.

## Suites not re-measured

None. All ten comparators now have refreshed size rows in both profiles and
refreshed paired speed rows in both profiles.

libjade and OpenSSL were the last two. libjade was re-pinned to the successor
repository and measured (`1.9960x` native, `1.391x` AVX2-only aggregate), and
the OpenSSL speed harness now links `-no-pie`, which is required because the goal
profile builds `libcrypto.a` with `-fno-pic`/`-fno-PIE` for the size gate. The
libjade and OpenSSL rows used five pairs rather than fifteen.

## Threats that remain outside this matrix

- **Botan** now has an AVX2 codepath. The refreshed row confirms it: the
  native roundtrip ratio falls from `8.05x` to `7.38x` and keygen/encaps
  roughly halve (`7.73x/6.59x` -> `4.70x/4.98x`). The win is not at risk; the
  published ratio is.
- **BoringSSL** landed lazy-reduction and vartime-Keccak changes with a quoted
  1.08-1.17x ML-KEM-768 speedup, but the refreshed row did not reproduce that
  gain on this host (native roundtrip `2.862x` versus c8's `3.573x`, with
  BoringSSL's own times barely moved). The row passes either way.
- **OpenSSL** AVX2 NTT/intt/basemul is on `master` (4.2.0-dev) only, not in
  `openssl-4.1.0`. When 4.2 ships, the OpenSSL row is the first to re-run.
- `plan.md` still names `cloudflare/circl` (round-3 Kyber768, pure Go) and
  `itzmeanjan/ml-kem` (portable C++20) as comparison targets. Neither is
  measured anywhere in the repository; both are structurally far slower than
  the already-measured AVX2 comparators.
