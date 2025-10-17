#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generation of unique private keys, aggregation of conditions by topology, 
streaming data recording in CSV, generation of statistics.

CSV format:
condition;private_key;subset_segments 
where 'subset_segments' — list of segments through «;».
"""

import argparse
import csv
import os
import random
import sys
import time
from collections import Counter
from datetime import datetime

try:
    # Add the path to the parent directory
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from ecurve.secp256k1 import Secp256k1, TEST_PARAMS, LEGACY_PARAMS  # type: ignore
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "Failed to import local 'secp256k1.py'. "
        "Make sure the file is in the same directory."
    ) from exc


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d%H%M%S")


def _fmt_subset_row(row) -> str:
    return f"{row[0]}_{row[1]}_{row[2]}_{row[3]}_{row[4]}_{row[5]}"


def _progress(i: int, total: int):
    pct = 100.0 * i / total if total else 100.0
    sys.stdout.write(f"\rProcessed: {i}/{total} ({pct:.1f}%)")
    sys.stdout.flush()


def generate_dataset(
    curve_mode: str,
    total_keys: int,
    range_start: int,
    data_out: str,
    stats_out: str,
    filter_condition: str,
    top_key_count: int,
    seed: int,
    show_progress: bool,
):
    t0 = time.time()

    if seed is not None:
        random.seed(seed)

    if curve_mode == "test":
        secp256k1 = Secp256k1(TEST_PARAMS)
    else:
        secp256k1 = Secp256k1(LEGACY_PARAMS)
    curve_n = int(secp256k1.curve.n)
    range_end = curve_n - 1
    if range_start >= range_end:
        raise ValueError("--range_start >= curve.n")

    unique_priv_keys = secp256k1.generate_unique_keys(total_keys, range_start, range_end)
    double_points = secp256k1.get_double_points()
    cond_counter = Counter()

    if not data_out:
        data_out = f"key_list_data_{_timestamp()}.csv"
    if not stats_out:
        stats_out = f"key_list_stats_{_timestamp()}.txt"

    wrote_any = False
    with open(data_out, mode="w", newline="", encoding="utf-8") as f_data:
        writer = csv.writer(f_data, delimiter=";")
        for i, priv in enumerate(unique_priv_keys, 1):
            _, pub = secp256k1.generate_keypair(priv)
            topology = secp256k1.get_topology_of_key()
            condition = secp256k1.identify_condition(topology, double_points, pub)
            cond_counter[condition] += 1

            if filter_condition is None or condition == filter_condition:
                segments = [
                    _fmt_subset_row(row) for row in topology if len(row) >= 7 and row[6] == "1"
                ]
                row = [condition, priv] + segments
                writer.writerow(row)
                wrote_any = True

            if show_progress and (i % max(1, total_keys // 100) == 0 or i == total_keys):
                _progress(i, total_keys)

    if show_progress:
        sys.stdout.write("\n")

    total_unique_conditions = len(cond_counter)
    sorted_counts = sorted(cond_counter.items(), key=lambda kv: kv[1], reverse=True)
    covered = sum(c for _, c in sorted_counts[: max(1, top_key_count)])
    coverage_ratio = covered / total_keys if total_keys else 1.0

    with open(stats_out, mode="w", encoding="utf-8") as f_stats:
        f_stats.write("Statistics:\nListed the conditions based on the topology of keys:\n")
        for cond, cnt in sorted_counts:
            f_stats.write(f"{cond} {cnt}\n")
        f_stats.write("\n")
        f_stats.write(
            f"Top {top_key_count} conditions cover {(coverage_ratio * 100):.2f}% from all keys!\n"
        )
        f_stats.write(f"Total condition count:   {total_unique_conditions}\n")
        f_stats.write(f"Total key count:         {total_keys}\n")
        f_stats.write(f"Data records written:    {('yes' if wrote_any else 'no')}\n")
        f_stats.write(f"Spent time: {time.time() - t0:.3f} sec.\n")

    sys.stdout.write(
        f"Done. Data: {os.path.abspath(data_out)} | Stats: {os.path.abspath(stats_out)}\n"
    )


def parse_args():
    p = argparse.ArgumentParser(
        description="Synthetic key set generation with CSV output and statistics.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--curve_mode", type=str, default="test")
    p.add_argument("--total_keys", type=int, default=1_000_000)
    p.add_argument("--range_start", type=int, default=10_000_000)
    p.add_argument("--data_out", type=str, default="")
    p.add_argument("--stats_out", type=str, default="")
    p.add_argument("--filter_condition", type=str, default=None)
    p.add_argument("--top_key_count", type=int, default=2000)
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--no_progress", action="store_true")
    return p.parse_args()


def main():
    args = parse_args()
    generate_dataset(
        curve_mode=args.curve_mode,
        total_keys=args.total_keys,
        range_start=args.range_start,
        data_out=args.data_out,
        stats_out=args.stats_out,
        filter_condition=args.filter_condition,
        top_key_count=args.top_key_count,
        seed=args.seed,
        show_progress=not args.no_progress,
    )


if __name__ == "__main__":
    main()
