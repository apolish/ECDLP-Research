#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Topology Counter Script

This script computes the total number of unique topologies defined by
four integer parameters (a, b, c, d) under the following constraints:

    - a, b, c, d ∈ {1, ..., d_max}
    - a < b
    - a + b + c < d
    - No ordering constraint between c and a, b

The algorithm is based on an analytically derived formula that avoids
explicit enumeration of (c, d), resulting in O(d_max^2) time complexity.

Usage:
    python count_topologies.py --d_max 256
"""

import argparse
import os
import sys

try:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from ecurve.secp256k1 import Secp256k1, TEST_PARAMS, LEGACY_PARAMS
except Exception as exc:
    raise ImportError(
        "Failed to import local 'secp256k1.py'. "
        "Make sure the file is in the same directory."
    ) from exc


def count_topologies(d_max: int) -> int:
    """
    Count the total number of unique topologies for a given d_max.

    For each valid pair (a, b) with a < b, the contribution of all valid
    (c, d) combinations is computed analytically.

    Parameters
    ----------
    d_max : int
        Maximum allowed value for parameter d (and upper bound for a, b, c).

    Returns
    -------
    int
        Total number of unique topologies.
    """
    total = 0

    # Iterate over all valid (a, b) pairs
    for a in range(1, d_max - 1):
        for b in range(a + 1, d_max):
            s = a + b

            # Maximum possible value of c such that a + b + c < d_max
            max_c = (d_max - 1) - s
            if max_c <= 0:
                continue

            # Sum over c = 1 .. max_c of (d_max - (a + b + c))
            # This equals the triangular number:
            #   1 + 2 + ... + max_c = max_c * (max_c + 1) / 2
            total += max_c * (max_c + 1) // 2

    return total


def main() -> None:
    """
    Main entry point of the script.
    """
    ap = argparse.ArgumentParser(
        description="Count unique topologies defined by parameters (a, b, c, d)."
    )
    ap.add_argument(
        "--curve_mode",
        choices=["test", "legacy"],
        required=True,
        help="Elliptic curve mode."
    )

    args = ap.parse_args()

    params = TEST_PARAMS if args.curve_mode == "test" else LEGACY_PARAMS
    ec = Secp256k1(params)
    d_max = ec.curve.l + 2
    result = count_topologies(d_max)

    print("Elliptic curve parameters:")
    print(f"name = {ec.curve.name}")
    print(f"mode = {ec.curve.mode}")
    print(f"p = {ec.curve.p}")
    print(f"a = {ec.curve.a}")
    print(f"b = {ec.curve.b}")
    print(f"g = {ec.curve.g}")
    print(f"n = {ec.curve.n}")
    print(f"l = {ec.curve.l}\n")

    print("Topology counting result:")
    print(f"d_max (curve.l + 2) = {d_max} -> total topologies = {result:,}")


if __name__ == "__main__":
    main()
