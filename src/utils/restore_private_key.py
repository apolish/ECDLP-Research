#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys
from typing import List, Set, Tuple

try:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from ecurve.secp256k1 import Secp256k1, TEST_PARAMS, LEGACY_PARAMS
except Exception as exc:
    raise ImportError(
        "Failed to import local 'secp256k1.py'. "
        "Make sure the file is in the same directory."
    ) from exc


def parse_added_points(spec: str) -> Set[int]:
    """
    Parses ONLY comma-separated positive integers (1-based).
    Example: "1,3,4,5,6,7,9,16,17,18,22,23,26,27,31" for test curve and 1180926333 private key

    Any token containing non-digits is invalid.
    """
    spec = spec.strip().replace(" ", "")
    if not spec:
        raise ValueError("added_points cannot be empty")

    out: Set[int] = set()
    for token in spec.split(","):
        if not token.isdigit():
            raise ValueError(
                f"Invalid token '{token}'. "
                f"Only comma-separated positive integers are allowed."
            )
        v = int(token)
        if v <= 0:
            raise ValueError(f"Index must be positive: {token}")
        out.add(v)

    if not out:
        raise ValueError("added_points parsed to empty set")

    return out


def restore_bits_from_added_points(added_points: Set[int]) -> str:
    """
    added_points: set of 1-based indices of added double-points.
    Bit-length is inferred as max(added_points).
    Returns MSB..LSB bitstring.
    """
    last_addition = max(added_points)
    bits_lsb = [0] * last_addition

    for idx in added_points:
        bits_lsb[idx - 1] = 1

    return "".join(str(b) for b in bits_lsb[::-1])


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Restore private key from elliptic-curve topology (explicit ops only)."
    )
    ap.add_argument(
        "--curve_mode",
        choices=["test", "legacy"],
        required=True,
        help="Elliptic curve mode."
    )
    ap.add_argument(
        "--added_points",
        type=str,
        required=True,
        help="Comma-separated list of 1-based added point indices (NO ranges)."
    )
    ap.add_argument(
        "--verify",
        action="store_true",
        help="Verify by computing Q = d*G."
    )

    args = ap.parse_args()

    params = TEST_PARAMS if args.curve_mode == "test" else LEGACY_PARAMS
    ec = Secp256k1(params)

    added_points = parse_added_points(args.added_points)
    bits = restore_bits_from_added_points(added_points)
    d = int(bits, 2)

    # Generate double points for consistency / bounds check
    double_points: List[Tuple[int, int]] = ec.get_double_points()

    max_needed = max(added_points)
    if max_needed > len(double_points):
        raise SystemExit(
            f"Need double_points up to index {max_needed}, "
            f"but only {len(double_points)} available."
        )

    print(f"Elliptic curve mode:   {params.mode}")
    print(f"Last addition index:   {max_needed}")
    print(f"Added points count:    {len(added_points)}")
    print(f"Bits (MSB..LSB):       {bits}")
    print(f"Private key (int):     {d}")

    if args.verify:
        Q = ec.scalar_multiply(d, params.g)
        print(f"Verification Q = d*G:  {Q}")


if __name__ == "__main__":
    main()
