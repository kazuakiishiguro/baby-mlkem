#!/usr/bin/env python3

import argparse
import math
import re
import sys
from pathlib import Path

OPERATIONS = ("keygen", "encaps", "decaps", "roundtrip")
BLOCK_PATTERN = re.compile(r"^\[([a-z0-9_]+)\]$")
RUN_PATTERN = re.compile(
    r"^\[([a-z0-9_]+)\] run=(\d+)/(\d+) "
    r"order=(local-first|competitor-first)$"
)
WARMUP_PATTERN = re.compile(
    r"^\[([a-z0-9_]+)\] warmup=(\d+)/(\d+) "
    r"order=(local-first|competitor-first)$"
)
HEADER_PATTERN = re.compile(r"^iters=(\d+) runs=(\d+)$")
RATIO_PATTERN = re.compile(r"^([0-9]+(?:\.[0-9]+)?)x$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify a baby-mlkem external speed report against the goal gate."
    )
    parser.add_argument("report", type=Path)
    parser.add_argument("--expected-suites", required=True)
    parser.add_argument("--expected-profile")
    parser.add_argument("--min-runs", type=int, default=15)
    parser.add_argument("--min-warmups", type=int, default=3)
    parser.add_argument("--min-bootstrap-samples", type=int, default=20000)
    parser.add_argument("--min-aggregate-speedup", type=float, default=1.05)
    parser.add_argument("--min-operation-speedup", type=float, default=1.0)
    parser.add_argument("--require-updated-repos", action="store_true")
    return parser.parse_args()


def expected_order(index: int) -> str:
    return "local-first" if index % 2 == 1 else "competitor-first"


def parse_ratio(value: str, context: str) -> float:
    match = RATIO_PATTERN.fullmatch(value)
    if not match:
        raise ValueError(f"{context}: invalid ratio: {value}")
    number = float(match.group(1))
    if not math.isfinite(number) or number <= 0.0:
        raise ValueError(f"{context}: ratio must be positive and finite")
    return number


def parse_positive_int(value: str, context: str) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        raise ValueError(f"{context}: invalid integer: {value}")
    number = int(value)
    if number <= 0:
        raise ValueError(f"{context}: expected a positive integer")
    return number


def parse_report(path: Path):
    metadata = {}
    blocks = {}
    measured_orders = {}
    warmup_orders = {}
    current_block = None
    header_runs = None

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line:
            continue

        match = HEADER_PATTERN.fullmatch(line)
        if match:
            metadata["iters"] = match.group(1)
            header_runs = int(match.group(2))
            metadata["runs"] = match.group(2)
            continue

        match = RUN_PATTERN.fullmatch(line)
        if match:
            label, index_text, total_text, order = match.groups()
            index = int(index_text)
            total = int(total_text)
            measured_orders.setdefault(label, {})[index] = (total, order)
            continue

        match = WARMUP_PATTERN.fullmatch(line)
        if match:
            label, index_text, total_text, order = match.groups()
            index = int(index_text)
            total = int(total_text)
            warmup_orders.setdefault(label, {})[index] = (total, order)
            continue

        match = BLOCK_PATTERN.fullmatch(line)
        if match:
            current_block = match.group(1)
            if current_block in blocks:
                raise ValueError(f"{path}:{line_number}: duplicate block {current_block}")
            blocks[current_block] = {}
            continue

        if line.startswith("["):
            continue

        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        target = metadata if current_block is None else blocks[current_block]
        if key in target and target[key] != value:
            raise ValueError(f"{path}:{line_number}: conflicting value for {key}")
        target[key] = value

    if header_runs is None:
        raise ValueError(f"{path}: missing iters/runs header")
    return metadata, blocks, measured_orders, warmup_orders


def require_metadata(metadata, key: str) -> str:
    if key not in metadata:
        raise ValueError(f"missing report metadata: {key}")
    return metadata[key]


def validate_orders(
    label: str, orders, expected_count: int, kind: str, failures: list[str]
) -> None:
    observed = orders.get(label, {})
    expected_indices = set(range(1, expected_count + 1))
    if set(observed) != expected_indices:
        failures.append(
            f"{label}: {kind} indices are incomplete: "
            f"expected={sorted(expected_indices)} observed={sorted(observed)}"
        )
        return
    for index in sorted(observed):
        total, order = observed[index]
        if total != expected_count:
            failures.append(
                f"{label}: {kind} {index} reports total={total}, "
                f"expected={expected_count}"
            )
        required_order = expected_order(index)
        if order != required_order:
            failures.append(
                f"{label}: {kind} {index} order={order}, expected={required_order}"
            )


def main() -> int:
    args = parse_args()
    if args.min_runs <= 0 or args.min_warmups <= 0:
        raise ValueError("minimum run and warmup counts must be positive")
    if args.min_bootstrap_samples <= 0:
        raise ValueError("minimum bootstrap sample count must be positive")
    if args.min_aggregate_speedup <= 0.0 or args.min_operation_speedup <= 0.0:
        raise ValueError("speedup thresholds must be positive")

    expected_suites = args.expected_suites.split(",")
    if not expected_suites or any(not suite for suite in expected_suites):
        raise ValueError("expected-suites must be a non-empty comma-separated list")
    if len(set(expected_suites)) != len(expected_suites):
        raise ValueError("expected-suites contains duplicates")

    metadata, blocks, measured_orders, warmup_orders = parse_report(args.report)
    failures = []

    runs = parse_positive_int(require_metadata(metadata, "runs"), "runs")
    warmups = parse_positive_int(
        require_metadata(metadata, "warmup_runs"), "warmup_runs"
    )
    bootstrap_samples = parse_positive_int(
        require_metadata(metadata, "bootstrap_samples"), "bootstrap_samples"
    )
    if runs < args.min_runs:
        failures.append(f"runs={runs} is below required {args.min_runs}")
    if warmups < args.min_warmups:
        failures.append(f"warmup_runs={warmups} is below required {args.min_warmups}")
    if bootstrap_samples < args.min_bootstrap_samples:
        failures.append(
            f"bootstrap_samples={bootstrap_samples} is below required "
            f"{args.min_bootstrap_samples}"
        )

    if require_metadata(metadata, "bench_suites") != args.expected_suites:
        failures.append("bench_suites does not exactly match the required comparator set")
    if require_metadata(metadata, "local_roundtrip_metric") != (
        "mlkem_roundtrip_core_ns_per_op"
    ):
        failures.append("local_roundtrip_metric is not the no-cache core metric")
    if not require_metadata(metadata, "local_bench_bin").endswith("/bench_productc"):
        failures.append("local_bench_bin is not the production-artifact harness")
    if require_metadata(metadata, "stats_mode") != "median":
        failures.append("stats_mode is not median")
    if args.expected_profile is not None and require_metadata(
        metadata, "goal_profile"
    ) != args.expected_profile:
        failures.append("goal_profile does not match the requested profile")
    if args.require_updated_repos and require_metadata(metadata, "UPDATE_REPOS") != "1":
        failures.append("UPDATE_REPOS is not 1")

    if set(blocks) != set(expected_suites):
        failures.append(
            "report blocks do not exactly match expected suites: "
            f"expected={sorted(expected_suites)} observed={sorted(blocks)}"
        )

    print("label operation ratio_of_medians ci95_low status")
    for label in expected_suites:
        validate_orders(label, measured_orders, runs, "run", failures)
        validate_orders(label, warmup_orders, warmups, "warmup", failures)
        values = blocks.get(label)
        if values is None:
            continue

        try:
            block_bootstrap_samples = parse_positive_int(
                values["paired_bootstrap_samples"],
                f"{label}.paired_bootstrap_samples",
            )
            if block_bootstrap_samples != bootstrap_samples:
                failures.append(
                    f"{label}: paired bootstrap samples={block_bootstrap_samples}, "
                    f"expected={bootstrap_samples}"
                )
        except KeyError:
            failures.append(f"{label}: missing statistic paired_bootstrap_samples")

        for operation in OPERATIONS:
            run_key = f"{operation}_runs"
            ratio_key = f"{operation}_speedup_ratio_of_medians"
            ci_key = f"{operation}_speedup_ci95_low"
            try:
                operation_runs = parse_positive_int(values[run_key], f"{label}.{run_key}")
                ratio = parse_ratio(values[ratio_key], f"{label}.{ratio_key}")
                ci_low = parse_ratio(values[ci_key], f"{label}.{ci_key}")
            except KeyError as error:
                failures.append(f"{label}: missing statistic {error.args[0]}")
                print(f"{label} {operation} missing missing FAIL")
                continue

            operation_failures = []
            if operation_runs != runs:
                operation_failures.append(
                    f"runs={operation_runs}, expected report runs={runs}"
                )
            if operation == "roundtrip":
                if ratio < args.min_aggregate_speedup:
                    operation_failures.append(
                        f"ratio={ratio:.4f} < {args.min_aggregate_speedup:.4f}"
                    )
                if ci_low <= 1.0:
                    operation_failures.append(f"CI lower={ci_low:.4f} is not > 1.0")
            else:
                if ratio < args.min_operation_speedup:
                    operation_failures.append(
                        f"ratio={ratio:.4f} < {args.min_operation_speedup:.4f}"
                    )
                if ci_low < 1.0:
                    operation_failures.append(f"CI lower={ci_low:.4f} is below 1.0")

            status = "FAIL" if operation_failures else "PASS"
            print(f"{label} {operation} {ratio:.4f}x {ci_low:.4f}x {status}")
            for detail in operation_failures:
                failures.append(f"{label}.{operation}: {detail}")

    if failures:
        print("goal_speed_gate=FAIL")
        for failure in failures:
            print(f"failure={failure}")
        return 1

    print("goal_speed_gate=PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"verify_goal_speed_report: {error}", file=sys.stderr)
        sys.exit(2)
