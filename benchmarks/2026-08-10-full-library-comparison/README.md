# Full Library Benchmark Comparison (2026-08-10)

This report measures the independent `baby-mlkem` ML-KEM-768 core against the
full comparison set used by the optimization goal. The local implementation is
built with `AVX2_BACKEND=core`; no vendored Kyber/PQClean KEM backend or external
cryptographic runtime library is linked into the local product.

The candidate is commit `dab05133e89f0ae5db81b294207430e64cfe4b77`. This is a
snapshot comparison, not a claim that these are the latest upstream revisions.
All comparator revisions and build provenance are recorded in
[`comparator-revisions.tsv`](comparator-revisions.tsv).

## Topline

- AVX2-only roundtrip median: `baby-mlkem` is `1.3672x` to `5.9166x` faster
  across the ten comparison suites by paired geometric-mean speed ratio.
- Native roundtrip median: `1.5649x` to `8.0611x` faster across the same suites.
- AVX2 normalized primary footprint: `47,460 B`; smaller than 9 of 10
  comparator artifacts. OpenSSL is `45,049 B`, so it is the one smaller result.
- Native normalized primary footprint: `69,611 B`; smaller than 6 of 10
  comparator artifacts. Kyber, fair-flags Kyber, PQClean, and mlkem-native are
  smaller in this native footprint comparison.
- The size result is a measurement, not a completed goal gate. The goal still
  requires every comparator and stricter repeated-run thresholds than this
  five-run survey.

## Measurement Conditions

| Item | Value |
|---|---|
| Host | AMD Ryzen Threadripper 7980X 64-Cores |
| OS | Linux 6.8.0-124-generic |
| Compiler | Ubuntu Clang 18.1.3 (1ubuntu1) |
| CPU pinning | CPU 2 |
| Speed iterations | 5,000 per timed sample |
| Speed runs | 5 measured runs plus 1 warmup |
| Speed statistics | Mean timings; paired geometric-mean speed ratios |
| Confidence interval | Paired bootstrap, 5,000 samples; table shows lower 95% bound |
| AVX2 profile | `-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f` |
| Native profile | `-march=native -mavx2 -mbmi2 -mpopcnt` |
| Local backend | `AVX2_BACKEND=core` |
| Randomness | Deterministic benchmark shim; entropy acquisition is not compared |
| Size scope | Normalized relocatable product with three deterministic APIs |
| Stack measurement | 8 guarded runs, 1 MiB usable probe stack |

The timed speed metric is the cache-free local core roundtrip. Each operation
uses fresh deterministic inputs. The local benchmark binary is reused across
suites, while each comparator is rebuilt from its pinned checkout with
`UPDATE_REPOS=0`.

A speedup of `1.0x` means equal speed; values above `1.0x` favor `baby-mlkem`.
For operation tables, each cell is `geomean (95% CI lower bound)`.
Roundtrip latency is the per-comparator median in ns/op from the same run set.

## Roundtrip Speed

### AVX2-only

| Comparator | baby-mlkem ns/op | Comparator ns/op | Speedup | 95% CI low |
|---|---:|---:|---:|---:|
| Kyber upstream AVX2 | 14853.29 | 20385.70 | 1.3672x | 1.3468x |
| Kyber fair-flags | 14857.05 | 20533.31 | 1.3885x | 1.3751x |
| mlkem-native | 14773.79 | 21651.88 | 1.4551x | 1.4417x |
| PQClean AVX2 | 14997.63 | 20851.91 | 1.3793x | 1.3409x |
| liboqs | 14798.82 | 24539.16 | 1.6515x | 1.6446x |
| BoringSSL | 14932.90 | 43921.31 | 2.9795x | 2.9338x |
| libcrux Rust | 14785.84 | 25408.72 | 1.6969x | 1.6609x |
| libjade Kyber768 AVX2 | 14827.48 | 21183.38 | 1.4230x | 1.4084x |
| Botan ML-KEM-768 | 14891.83 | 88023.60 | 5.9166x | 5.9056x |
| OpenSSL ML-KEM-768 | 14908.13 | 52421.77 | 3.5118x | 3.4987x |

### Native

| Comparator | baby-mlkem ns/op | Comparator ns/op | Speedup | 95% CI low |
|---|---:|---:|---:|---:|
| Kyber upstream AVX2 | 10416.89 | 16336.42 | 1.5738x | 1.5520x |
| Kyber fair-flags | 10416.70 | 16274.04 | 1.5649x | 1.5628x |
| mlkem-native | 10474.17 | 21522.10 | 2.0612x | 2.0544x |
| PQClean AVX2 | 10461.65 | 22092.12 | 2.1114x | 2.0981x |
| liboqs | 10425.05 | 20830.59 | 2.0016x | 1.9920x |
| BoringSSL | 10408.17 | 37630.42 | 3.6246x | 3.6120x |
| libcrux Rust | 10410.01 | 20792.58 | 1.9883x | 1.9622x |
| libjade Kyber768 AVX2 | 10430.21 | 21224.68 | 2.0334x | 2.0213x |
| Botan ML-KEM-768 | 10411.16 | 84136.99 | 8.0611x | 7.9995x |
| OpenSSL ML-KEM-768 | 10467.01 | 48418.47 | 4.8330x | 4.6118x |

## Operation Speed Ratios

These tables include every timed operation. They report paired geometric-mean
speedup and the lower bound of the paired 95% bootstrap interval, rather than
only the aggregate roundtrip number.

### AVX2-only

| Comparator | Keygen | Encaps | Decaps | Roundtrip |
|---|---:|---:|---:|---:|
| Kyber upstream AVX2 | 1.1657x (1.1556x) | 1.4788x (1.4243x) | 1.5917x (1.5341x) | 1.3672x (1.3468x) |
| Kyber fair-flags | 1.1561x (1.1290x) | 1.5148x (1.4612x) | 1.6073x (1.5966x) | 1.3885x (1.3751x) |
| mlkem-native | 1.1135x (1.0898x) | 1.4895x (1.4541x) | 1.9348x (1.8822x) | 1.4551x (1.4417x) |
| PQClean AVX2 | 1.1811x (1.1704x) | 1.4824x (1.4635x) | 1.6331x (1.5801x) | 1.3793x (1.3409x) |
| liboqs | 1.2678x (1.2305x) | 1.7095x (1.6843x) | 2.1612x (2.1553x) | 1.6515x (1.6446x) |
| BoringSSL | 2.3914x (2.3276x) | 2.8567x (2.8442x) | 3.8480x (3.8386x) | 2.9795x (2.9338x) |
| libcrux Rust | 1.3860x (1.3421x) | 1.8741x (1.8556x) | 2.0243x (2.0058x) | 1.6969x (1.6609x) |
| libjade Kyber768 AVX2 | 1.1006x (1.0633x) | 1.8714x (1.8342x) | 1.4795x (1.4712x) | 1.4230x (1.4084x) |
| Botan ML-KEM-768 | 5.4082x (5.2541x) | 5.3649x (5.1539x) | 6.9614x (6.8826x) | 5.9166x (5.9056x) |
| OpenSSL ML-KEM-768 | 3.5549x (3.4891x) | 2.8476x (2.8349x) | 4.2656x (4.2086x) | 3.5118x (3.4987x) |

### Native

| Comparator | Keygen | Encaps | Decaps | Roundtrip |
|---|---:|---:|---:|---:|
| Kyber upstream AVX2 | 1.3134x (1.2729x) | 1.4412x (1.4328x) | 2.0398x (1.9810x) | 1.5738x (1.5520x) |
| Kyber fair-flags | 1.3093x (1.2614x) | 1.4501x (1.4472x) | 2.0691x (2.0606x) | 1.5649x (1.5628x) |
| mlkem-native | 1.5091x (1.4461x) | 1.8657x (1.8537x) | 3.1029x (3.0791x) | 2.0612x (2.0544x) |
| PQClean AVX2 | 1.7674x (1.7256x) | 1.9613x (1.9076x) | 2.8377x (2.8101x) | 2.1114x (2.0981x) |
| liboqs | 1.4866x (1.4355x) | 1.7885x (1.7726x) | 3.0012x (2.9498x) | 2.0016x (1.9920x) |
| BoringSSL | 3.0307x (2.9282x) | 2.9714x (2.9479x) | 5.1764x (5.0630x) | 3.6246x (3.6120x) |
| libcrux Rust | 1.5537x (1.4694x) | 1.8970x (1.8542x) | 2.6485x (2.6174x) | 1.9883x (1.9622x) |
| libjade Kyber768 AVX2 | 1.5144x (1.4640x) | 2.3247x (2.3131x) | 2.3513x (2.3252x) | 2.0334x (2.0213x) |
| Botan ML-KEM-768 | 7.3764x (7.1252x) | 6.4881x (6.4439x) | 10.5328x (10.4305x) | 8.0611x (7.9995x) |
| OpenSSL ML-KEM-768 | 5.3963x (4.7680x) | 3.0628x (2.9575x) | 6.2090x (6.1158x) | 4.8330x (4.6118x) |

## Size Comparison

The normalized `primary` footprint is allocatable executable plus read-only
sections, including required constants and runtime metadata. Writable storage
and measured maximum stack are shown separately. Each paired cell is
`baby-mlkem / comparator`, in bytes. `PASS` only means the local primary
footprint is no larger than that comparator; it is not the overall completion
gate.

### AVX2-only

| Comparator | Primary B/O | Code B/O | RO data B/O | Writable B/O | Stack B/O | Gate |
|---|---:|---:|---:|---:|---:|---:|
| Kyber upstream AVX2 | 47460 / 62970 (0.7537x) | 41539 / 58032 | 5921 / 4938 | 26593 / 0 | 4512 / 18032 | PASS |
| Kyber fair-flags | 47460 / 64269 (0.7385x) | 41539 / 59331 | 5921 / 4938 | 26593 / 0 | 4512 / 18032 | PASS |
| PQClean AVX2 | 47460 / 61827 (0.7676x) | 41539 / 58937 | 5921 / 2890 | 26593 / 0 | 4512 / 17840 | PASS |
| mlkem-native | 47460 / 51279 (0.9255x) | 41539 / 44260 | 5921 / 7019 | 26593 / 0 | 4512 / 21120 | PASS |
| liboqs | 47460 / 81316 (0.5836x) | 41539 / 71844 | 5921 / 9472 | 26593 / 448 | 4512 / 20592 | PASS |
| BoringSSL | 47460 / 134942 (0.3517x) | 41539 / 120040 | 5921 / 14902 | 26593 / 92 | 4512 / 18368 | PASS |
| libcrux Rust | 47460 / 142302 (0.3335x) | 41539 / 128786 | 5921 / 13516 | 26593 / 0 | 4512 / 32072 | PASS |
| libjade Kyber768 AVX2 | 47460 / 109633 (0.4329x) | 41539 / 102434 | 5921 / 7199 | 26593 / 0 | 4512 / 19552 | PASS |
| Botan ML-KEM-768 | 47460 / 146600 (0.3237x) | 41539 / 113469 | 5921 / 33131 | 26593 / 12 | 4512 / 4952 | PASS |
| OpenSSL ML-KEM-768 | 47460 / 45049 (1.0535x) | 41539 / 41088 | 5921 / 3961 | 26593 / 4 | 4512 / 9112 | FAIL |

### Native

| Comparator | Primary B/O | Code B/O | RO data B/O | Writable B/O | Stack B/O | Gate |
|---|---:|---:|---:|---:|---:|---:|
| Kyber upstream AVX2 | 69611 / 61032 (1.1406x) | 53285 / 55904 | 16326 / 5128 | 18001 / 0 | 8056 / 17360 | FAIL |
| Kyber fair-flags | 69611 / 62075 (1.1214x) | 53285 / 56947 | 16326 / 5128 | 18001 / 0 | 8056 / 17360 | FAIL |
| PQClean AVX2 | 69611 / 60950 (1.1421x) | 53285 / 58060 | 16326 / 2890 | 18001 / 0 | 8056 / 17840 | FAIL |
| mlkem-native | 69611 / 51200 (1.3596x) | 53285 / 43728 | 16326 / 7472 | 18001 / 0 | 8056 / 20448 | FAIL |
| liboqs | 69611 / 70206 (0.9915x) | 53285 / 60058 | 16326 / 10148 | 18001 / 448 | 8056 / 19320 | PASS |
| BoringSSL | 69611 / 208709 (0.3335x) | 53285 / 160323 | 16326 / 48386 | 18001 / 92 | 8056 / 21856 | PASS |
| libcrux Rust | 69611 / 137086 (0.5078x) | 53285 / 122210 | 16326 / 14876 | 18001 / 0 | 8056 / 31368 | PASS |
| libjade Kyber768 AVX2 | 69611 / 109633 (0.6349x) | 53285 / 102434 | 16326 / 7199 | 18001 / 0 | 8056 / 19552 | PASS |
| Botan ML-KEM-768 | 69611 / 183712 (0.3789x) | 53285 / 140755 | 16326 / 42957 | 18001 / 12 | 8056 / 4952 | PASS |
| OpenSSL ML-KEM-768 | 69611 / 103552 (0.6722x) | 53285 / 95871 | 16326 / 7681 | 18001 / 4 | 8056 / 9624 | PASS |

## Library And Dependency Scope

`baby-mlkem` has no external cryptographic library dependency in this
measurement. The local product is the repository's independent core and uses
repository-local assembly/intrinsics where selected. The comparator libraries
below are built separately only to establish the comparison points; their
presence in this report does not make them runtime dependencies of
`baby-mlkem`.

| Library | Role in this report | Revision/source | Important scope note |
|---|---|---|---|
| baby-mlkem | Candidate | `dab05133` | Core-only local product; no external crypto runtime |
| Kyber | Reference AVX2 | `3edd5af` | Original Kyber source; not a FIPS 203 implementation claim |
| PQClean | C AVX2 comparator | `0586a82` | Kyber768 AVX2 implementation |
| mlkem-native | Native C comparator | `0457037` | Host-aware optimized C implementation |
| liboqs | Library comparator | `4e1183a` | Algorithm-specific three-API product path |
| BoringSSL | Library comparator | `a204be2` | Internal ML-KEM objects selected by normalized harness |
| libcrux | Rust comparator | `libcrux-ml-kem 0.0.10` | SIMD256 enabled; Cargo lock hash recorded |
| libjade | AVX2 comparator | `release/2023.05-2` | Pre-FIPS Kyber768 semantics, retained as historical comparator |
| Botan | C++ library comparator | `3.13.0` unreleased, `7ffae68` | Internal-core-direct adapter; no per-call cache reuse |
| OpenSSL | Library comparator | `1a3455e` | Three internal core objects; provider registry excluded |

The OpenSSL and Botan measurements intentionally use normalized internal-core
adapters so that the timed call does not reuse prepared keys or matrices. This
makes the comparison more conservative for the local no-cache core, but it is
not a claim about the default high-level API cost of either library. Similarly,
liboqs, BoringSSL, libcrux, and libjade include the adapter and wire-format
handling required by their normalized three-API harnesses.

## Interpretation

The closest AVX2 speed baselines are Kyber, fair-flags Kyber, mlkem-native,
PQClean, and libjade. The local core leads those comparisons by roughly
`1.10x` to `1.46x` in roundtrip, while the normalized local product is smaller
than each of them in AVX2 primary footprint. Native size is different because
`-march=native` enables a larger local AVX512-capable code path and read-only
constant set; the native speed profile should therefore not be read as a
portable size result.

Large speed ratios against Botan, OpenSSL, and BoringSSL should not be
interpreted as a single primitive being intrinsically slower. Their normalized
measurements include library adapter, key/wire parsing, operation rebuild, or
selected-object boundaries that are required by the no-cache comparison
contract. The benchmark isolates the measured product path, not every internal
optimization opportunity in those projects.

## Reproduction And Artifacts

The exact raw speed outputs are:

- [`speed-avx2-allstats.txt`](speed-avx2-allstats.txt)
- [`speed-native-allstats.txt`](speed-native-allstats.txt)
- [`speed-summary.tsv`](speed-summary.tsv)

The exact size outputs are in [`sizes/`](sizes/), with the machine-readable
aggregate in [`size-summary.tsv`](size-summary.tsv). The size run status is in
[`size-status.tsv`](size-status.tsv). Environment and revision details are in
[`environment.txt`](environment.txt) and
[`comparator-revisions.tsv`](comparator-revisions.tsv). File hashes are in
[`checksums.sha256`](checksums.sha256).

The benchmark was run from an isolated temporary tree so the pre-existing root
`bench_core_stagesc` artifact was not overwritten.
