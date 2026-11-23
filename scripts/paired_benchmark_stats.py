#!/usr/bin/env python3

import argparse
import math
import random
import re
import statistics
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Report paired benchmark speedup statistics."
    )
    parser.add_argument("--metric", required=True)
    parser.add_argument("--local", required=True, type=Path)
    parser.add_argument("--competitor", required=True, type=Path)
    parser.add_argument("--expected-runs", required=True, type=int)
    parser.add_argument("--bootstrap-samples", type=int, default=20000)
    return parser.parse_args()


def read_values(path: Path) -> list[float]:
    values = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for line_number, line in enumerate(lines, 1):
        text = line.strip()
        if not text:
            continue
        try:
            value = float(text)
        except ValueError as error:
            raise ValueError(f"{path}:{line_number}: invalid number: {text}") from error
        if not math.isfinite(value) or value <= 0.0:
            raise ValueError(f"{path}:{line_number}: expected a positive finite value")
        values.append(value)
    return values


def geometric_mean(values: list[float]) -> float:
    return math.exp(statistics.fmean(math.log(value) for value in values))


def bootstrap_interval(
    values: list[float], samples: int, seed: int
) -> tuple[float, float]:
    rng = random.Random(seed)
    count = len(values)
    estimates = []
    for _ in range(samples):
        resample = [values[rng.randrange(count)] for _ in range(count)]
        estimates.append(geometric_mean(resample))
    estimates.sort()
    low_index = int(0.025 * (samples - 1))
    high_index = int(0.975 * (samples - 1))
    return estimates[low_index], estimates[high_index]


def main() -> int:
    args = parse_args()
    if not re.fullmatch(r"[a-z][a-z0-9_]*", args.metric):
        raise ValueError("metric must match [a-z][a-z0-9_]*")
    if args.expected_runs <= 0:
        raise ValueError("expected-runs must be positive")
    if args.bootstrap_samples <= 0:
        raise ValueError("bootstrap-samples must be positive")

    local = read_values(args.local)
    competitor = read_values(args.competitor)
    if len(local) != args.expected_runs or len(competitor) != args.expected_runs:
        raise ValueError(
            f"expected {args.expected_runs} pairs, got local={len(local)} "
            f"competitor={len(competitor)}"
        )

    ratios = [
        competitor_time / local_time
        for local_time, competitor_time in zip(local, competitor)
    ]
    seed = 0x4D4C4B454D + sum(args.metric.encode("ascii"))
    ci_low, ci_high = bootstrap_interval(ratios, args.bootstrap_samples, seed)
    prefix = args.metric

    print(f"{prefix}_runs={len(ratios)}")
    print(f"{prefix}_local_mean_ns={statistics.fmean(local):.2f}")
    print(f"{prefix}_local_median_ns={statistics.median(local):.2f}")
    print(f"{prefix}_competitor_mean_ns={statistics.fmean(competitor):.2f}")
    print(f"{prefix}_competitor_median_ns={statistics.median(competitor):.2f}")
    print(
        f"{prefix}_speedup_ratio_of_medians="
        f"{statistics.median(competitor) / statistics.median(local):.4f}x"
    )
    print(f"{prefix}_speedup_gmean={geometric_mean(ratios):.4f}x")
    print(f"{prefix}_speedup_ci95_low={ci_low:.4f}x")
    print(f"{prefix}_speedup_ci95_high={ci_high:.4f}x")
    print(f"{prefix}_speedup_median={statistics.median(ratios):.4f}x")
    print(f"{prefix}_wins={sum(ratio > 1.0 for ratio in ratios)}/{len(ratios)}")
    local_first_median = statistics.median(ratios[0::2])
    print(f"{prefix}_local_first_median={local_first_median:.4f}x")
    if len(ratios) > 1:
        competitor_first_median = statistics.median(ratios[1::2])
        print(f"{prefix}_competitor_first_median={competitor_first_median:.4f}x")
    else:
        print(f"{prefix}_competitor_first_median=n/a")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"paired_benchmark_stats: {error}", file=sys.stderr)
        sys.exit(1)
