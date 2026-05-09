# ML-KEM Research Plan

## Objective

Build the fastest and smallest ML-KEM implementation in this repository while
maintaining correctness, FIPS 203 compatibility, and security-conscious coding
practice.

## Comparison Targets (as of 2026-05-09)

- Most-starred repository tagged `ml-kem`:
  `cloudflare/circl` (1659 stars)
- Most-starred repository with `ml-kem` in the repository name:
  `itzmeanjan/ml-kem` (133 stars)

Re-check commands:

```bash
curl -s 'https://api.github.com/search/repositories?q=topic:ml-kem&sort=stars&order=desc&per_page=10' | jq -r '.items[] | "\(.full_name)\t\(.stargazers_count)\t\(.html_url)"'
curl -s 'https://api.github.com/search/repositories?q=ml-kem+in:name&sort=stars&order=desc&per_page=10' | jq -r '.items[] | "\(.full_name)\t\(.stargazers_count)\t\(.html_url)"'
```

## Dependency Order

1. Baseline and measurement harness:
   - deterministic correctness command (`make test`)
   - deterministic speed command (`make bench-run BENCH_ITERS=<N>`)
   - size command (`size testc benchc`, `wc -c baby-mlkem.c`)
2. Cryptographic primitive correctness:
   - SHA3/Shake vectors and FIPS202 integration
3. Arithmetic core:
   - modular arithmetic, NTT roots, forward/inverse NTT, polynomial ops
4. Serialization and sampling:
   - `byte_encode` / `byte_decode`, `sample_ntt`, CBD
5. K-PKE:
   - keygen/encrypt/decrypt correctness and negative-path checks
6. ML-KEM:
   - keygen/encaps/decaps correctness and deterministic known-answer checks
7. Optimization loop:
   - branch per hypothesis
   - run correctness, speed, size
   - keep only measured wins; log neutral/failures in `note.md`

## Gating Rules Per Experiment

1. `make clean && make test`
2. `make bench-run BENCH_ITERS=200` (increase iterations if noisy)
3. `size testc benchc`
4. `wc -c baby-mlkem.c`
5. Record baseline, result, and interpretation in `note.md`
