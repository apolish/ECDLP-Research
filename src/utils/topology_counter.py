#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Topology Counter Script (Extended)

This script computes:
1) The total number of unique topologies under the original constraints
   derived from elliptic curve parameters.
2) The total number of unique topologies under user-defined constraints
   for parameters a, b, c, d.

User-defined ranges are provided via CLI in the form:
    --a min:max --b min:max --c min:max --d min:max

All ranges are strictly validated before computation.
"""

import argparse
import os
import sys
from typing import Tuple

try:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from ecurve.secp256k1 import Secp256k1, TEST_PARAMS, LEGACY_PARAMS
except Exception as exc:
    raise ImportError(
        "Failed to import local 'secp256k1.py'. "
        "Make sure the file is in the correct directory."
    ) from exc


# ---------------------------------------------------------------------
# Utility: range parsing
# ---------------------------------------------------------------------

def parse_range(spec: str, name: str) -> Tuple[int, int]:
    """
    Parse a range specification in the form 'min:max'.

    Parameters
    ----------
    spec : str
        Range specification.
    name : str
        Parameter name (for error messages).

    Returns
    -------
    (int, int)
        Parsed (min, max) tuple.

    Raises
    ------
    ValueError
        If the specification is invalid.
    """
    if ":" not in spec:
        raise ValueError(
            f"Invalid format for --{name}: '{spec}'. Expected <min>:<max>."
        )

    lo, hi = spec.split(":", 1)

    if not lo.isdigit() or not hi.isdigit():
        raise ValueError(
            f"Invalid values for --{name}: '{spec}'. Must be integers."
        )

    lo, hi = int(lo), int(hi)

    if lo > hi:
        raise ValueError(
            f"Invalid range for --{name}: min > max ({lo} > {hi})."
        )

    return lo, hi


# ---------------------------------------------------------------------
# Original counting logic (unchanged)
# ---------------------------------------------------------------------

def count_topologies_original(d_max: int) -> int:
    """
    Count topologies under the original model:
        a < b
        a + b + c < d
        a, b, c, d ∈ {1, ..., d_max}

    Uses the original O(d_max^2) analytical formula.
    """
    total = 0

    for a in range(1, d_max - 1):
        for b in range(a + 1, d_max):
            s = a + b
            max_c = (d_max - 1) - s
            if max_c <= 0:
                continue
            total += max_c * (max_c + 1) // 2

    return total


# ---------------------------------------------------------------------
# Validation for restricted ranges
# ---------------------------------------------------------------------

def validate_ranges(
    a_min, a_max,
    b_min, b_max,
    c_min, c_max,
    d_min, d_max
) -> None:
    """
    Validate logical consistency of parameter ranges.

    Raises
    ------
    ValueError
        If the ranges make the constraints unsatisfiable.
    """
    errors = []

    if a_max >= b_max:
        errors.append("No possible ordering a < b (a_max >= b_max).")

    if b_max >= c_max:
        errors.append("No possible ordering b < c (b_max >= c_max).")

    if c_max >= d_max:
        errors.append("No possible ordering c < d (c_max >= d_max).")

    if a_min + b_min + c_min >= d_max:
        errors.append(
            "Sum constraint impossible: a_min + b_min + c_min >= d_max."
        )

    if errors:
        raise ValueError(
            "Invalid parameter ranges:\n  - " + "\n  - ".join(errors)
        )


# ---------------------------------------------------------------------
# Restricted counting logic
# ---------------------------------------------------------------------

def count_topologies_restricted(
    a_min, a_max,
    b_min, b_max,
    c_min, c_max,
    d_min, d_max
) -> int:
    """
    Count topologies under strict constraints:
        a < b < c < d
        a + b + c < d
        a ∈ [a_min, a_max]
        b ∈ [b_min, b_max]
        c ∈ [c_min, c_max]
        d ∈ [d_min, d_max]
    """
    total = 0

    for a in range(a_min, a_max + 1):
        for b in range(max(b_min, a + 1), b_max + 1):
            for c in range(max(c_min, b + 1), c_max + 1):
                d_start = max(d_min, a + b + c + 1)
                if d_start > d_max:
                    continue
                total += d_max - d_start + 1

    return total


# ---------------------------------------------------------------------
# Main CLI
# ---------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Count unique topologies under original and restricted constraints."
    )

    ap.add_argument(
        "--curve_mode",
        choices=["test", "legacy"],
        required=True,
        help="Elliptic curve mode."
    )

    ap.add_argument("--a", type=str, help="Range for a as min:max")
    ap.add_argument("--b", type=str, help="Range for b as min:max")
    ap.add_argument("--c", type=str, help="Range for c as min:max")
    ap.add_argument("--d", type=str, help="Range for d as min:max")

    args = ap.parse_args()

    params = TEST_PARAMS if args.curve_mode == "test" else LEGACY_PARAMS
    ec = Secp256k1(params)

    # --------------------------------------------------
    # Original topology count
    # --------------------------------------------------

    original_d_max = ec.curve.l + 2
    original_result = count_topologies_original(original_d_max)

    print("Elliptic curve parameters:")
    print(f"name = {ec.curve.name}")
    print(f"mode = {ec.curve.mode}")
    print(f"p = {ec.curve.p}")
    print(f"a = {ec.curve.a}")
    print(f"b = {ec.curve.b}")
    print(f"g = {ec.curve.g}")
    print(f"n = {ec.curve.n}")
    print(f"l = {ec.curve.l}\n")

    print("Original topology counting:")
    print(f"d_max (curve.l + 2) = {original_d_max}")
    print(f"total topologies = {original_result:,}")

    print()

    # --------------------------------------------------
    # Restricted topology count (optional)
    # --------------------------------------------------

    if args.a and args.b and args.c and args.d:
        a_min, a_max = parse_range(args.a, "a")
        b_min, b_max = parse_range(args.b, "b")
        c_min, c_max = parse_range(args.c, "c")
        d_min, d_max = parse_range(args.d, "d")

        validate_ranges(
            a_min, a_max,
            b_min, b_max,
            c_min, c_max,
            d_min, d_max
        )

        restricted_result = count_topologies_restricted(
            a_min, a_max,
            b_min, b_max,
            c_min, c_max,
            d_min, d_max
        )

        print("Restricted topology counting:")
        print(
            f"a ∈ [{a_min}, {a_max}], "
            f"b ∈ [{b_min}, {b_max}], "
            f"c ∈ [{c_min}, {c_max}], "
            f"d ∈ [{d_min}, {d_max}]"
        )
        print(f"total restricted topologies = {restricted_result:,}")

    else:
        print(
            "Restricted topology counting skipped "
            "(not all ranges --a, --b, --c, --d were provided)."
        )


if __name__ == "__main__":
    main()
