# AGENTS

## Mission

Implement ML-KEM from `plan.md` with the explicit research goal of making it the fastest and smallest ML-KEM implementation possible, while preserving correctness, FIPS 203 compatibility, and security-sensitive coding discipline.

This project should be developed in the spirit of Andrej Karpathy's auto-research idea: keep a tight experimental loop, let measurements drive decisions, record the reasoning trail, and continuously generate the next implementation hypothesis from the previous result.

## Primary Source

- Treat `plan.md` as the implementation plan and dependency order.
- Build bottom-up from the smallest validated components.
- Do not skip correctness checks for speed or size wins.
- Keep the code small, dependency-free, and easy to benchmark.

## Research Loop

For every optimization or implementation idea:

1. Create a dedicated experiment branch.
2. Establish or update the baseline benchmark before changing code.
3. Implement the smallest coherent version of the idea.
4. Run correctness tests, performance benchmarks, and size measurements.
5. Compare against the current best branch.
6. If the result is faster or smaller without breaking correctness, commit it with the benchmark and size numbers in the commit message.
7. If the result does not improve the implementation, record the failed approach in `note.md`, explain why it failed, and change the implementation strategy before trying again.

## Branch And Commit Discipline

- Use short experiment branch names such as `exp/ntt-barrett`, `exp/keccak-unroll`, or `exp/size-encode`.
- Keep each branch focused on one hypothesis.
- Commit only measured improvements or documentation of accepted project state.
- Do not mix unrelated refactors with performance experiments.
- Preserve failed-attempt evidence in `note.md` instead of relying on memory.

## Measurement Discipline

Each experiment should record:

- Commit or branch used as the baseline.
- Compiler, flags, CPU, and OS when relevant.
- Correctness command and result.
- Benchmark command and result.
- Binary/object size command and result.
- Interpretation of why the result improved, regressed, or stayed neutral.

Prefer simple, repeatable commands that can be run locally without network access. If a benchmark is noisy, rerun it enough times to distinguish a real improvement from measurement variance.

## `note.md`

Use `note.md` as the research log for trial and error. Record failed or neutral attempts in enough detail that the same idea is not repeated blindly.

Suggested entry format:

```md
## YYYY-MM-DD: short experiment name

- Branch: `exp/name`
- Hypothesis:
- Change:
- Baseline:
- Result:
- Why it failed or was not accepted:
- Next idea:
```

## Priorities

1. Correct ML-KEM behavior and tests.
2. Constant-time, security-conscious implementation choices.
3. Performance.
4. Code size and binary size.
5. Simplicity and maintainability.

When priorities conflict, document the tradeoff and let measurements decide where possible.
