#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import hashlib
import secrets


try:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from ecurve.secp256k1 import Secp256k1, TEST_PARAMS, LEGACY_PARAMS
except Exception as exc:
    raise ImportError(
        "Failed to import local 'secp256k1.py'. "
        "Make sure the file is in the correct path."
    ) from exc


def int_to_32bytes(x: int) -> bytes:
    """
    Canonical big-endian 32-byte encoding of a positive integer.
    """
    if x <= 0:
        raise ValueError("Integer must be positive")
    return x.to_bytes(32, byteorder="big")


def generate_private_key_from_entropy(
    k1: bytes,
    k2: bytes,
    k3: bytes,
    curve_n: int,
    mode: str,
) -> int:
    """
    Private key generation from three 256-bit entropy sources.

    legacy mode:
        d = SHA256(k1 || k2 || k3 || counter)
        rejection sampling until 1 <= d < n

    test mode:
        d = (SHA256(k1 || k2 || k3) mod (n - 1)) + 1
        guaranteed termination
    """

    if not (len(k1) == len(k2) == len(k3) == 32):
        raise ValueError("All entropy inputs must be exactly 32 bytes")

    entropy = k1 + k2 + k3

    if mode == "legacy":
        counter = 0
        while True:
            h = hashlib.sha256(entropy + counter.to_bytes(4, "big")).digest()
            d = int.from_bytes(h, byteorder="big")

            if 1 <= d < curve_n:
                return d

            counter += 1

    elif mode == "test":
        h = hashlib.sha256(entropy).digest()
        d = (int.from_bytes(h, byteorder="big") % (curve_n - 1)) + 1
        return d

    else:
        raise ValueError(f"Unsupported mode: {mode}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Private key generation from multi-source entropy (mode-aware)."
    )

    ap.add_argument(
        "--curve_mode",
        choices=["test", "legacy"],
        required=True,
        help="Elliptic curve mode."
    )

    args = ap.parse_args()

    # ------------------------------------------------------------------
    # Curve selection
    # ------------------------------------------------------------------
    params = TEST_PARAMS if args.curve_mode == "test" else LEGACY_PARAMS
    ec = Secp256k1(params)

    # ------------------------------------------------------------------
    # Entropy sources
    # ------------------------------------------------------------------
    if ec.curve.mode == "legacy":
        # Deterministic, reproducible (research / audit)
        k1 = hashlib.sha256(b"entropy-source-1").digest()
        k2 = hashlib.sha256(b"entropy-source-2").digest()
        k3 = hashlib.sha256(b"entropy-source-3").digest()

    elif ec.curve.mode == "test":
        # Real curve-valid scalars, converted canonically
        k1_int = secrets.randbelow(ec.curve.n - 1) + 1
        k2_int = secrets.randbelow(ec.curve.n - 1) + 1
        k3_int = secrets.randbelow(ec.curve.n - 1) + 1

        k1 = int_to_32bytes(k1_int)
        k2 = int_to_32bytes(k2_int)
        k3 = int_to_32bytes(k3_int)

    else:
        raise RuntimeError("Unsupported curve mode")

    # ------------------------------------------------------------------
    # Private key generation
    # ------------------------------------------------------------------
    d = generate_private_key_from_entropy(
        k1=k1,
        k2=k2,
        k3=k3,
        curve_n=params.n,
        mode=ec.curve.mode,
    )

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    print(f"Elliptic curve mode:   {params.mode}")
    print(f"Curve order (n):       {params.n}")
    print(f"Private key (int):     {d}")
    print(f"Private key (hex):     {hex(d)[2:]}")


if __name__ == "__main__":
    main()
