#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PEP 8 compliant secp256k1 demo with key generation, signing, verification,
and curve analysis for both test and legacy parameters.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import random
import time
from typing import List, Optional, Tuple

Point = Optional[Tuple[int, int]]


@dataclass(frozen=True)
class CurveParams:
    """Elliptic curve parameters for secp256k1."""

    name: str
    mode: str  # "test" | "legacy"
    p: int
    a: int
    b: int
    g: Tuple[int, int]
    n: int
    l: int  # number of fixed (x2, y2) points


TEST_PARAMS = CurveParams(
    name="secp256k1",
    mode="test",
    p=1_241_690_119,
    a=1,
    b=35,
    g=(311_072_572, 523_565_415),
    n=1_241_630_743,
    l=29,
)

LEGACY_PARAMS = CurveParams(
    name="secp256k1",
    mode="legacy",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    g=(
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    ),
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    l=254,
)


def encode_varint(i: int) -> bytes:
    """Bitcoin varint encoding."""
    if i < 0xfd:
        return i.to_bytes(1, "little")
    if i <= 0xffff:
        return b"\xfd" + i.to_bytes(2, "little")
    if i <= 0xffffffff:
        return b"\xfe" + i.to_bytes(4, "little")
    return b"\xff" + i.to_bytes(8, "little")


def compress_public_key(pub: Tuple[int, int]) -> bytes:
    """Return compressed SEC representation of a public key (33 bytes)."""
    x, y = pub
    prefix = 0x02 | (y & 1)
    return bytes([prefix]) + x.to_bytes(32, "big")


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data)) – Bitcoin HASH160."""
    sha = hashlib.sha256(data).digest()
    ripe = hashlib.new("ripemd160", sha).digest()
    return ripe


def make_bitcoin_legacy_sighash_message(public_key: Tuple[int, int]) -> bytes:
    """
    Build a Bitcoin legacy SIGHASH_ALL preimage for a simple 1-in-1-out P2PKH transaction.
    This is an illustrative canonical example used for signing on the real secp256k1 curve.
    """
    # Version
    version = (1).to_bytes(4, "little")

    # Compressed public key and HASH160
    compressed_pub = compress_public_key(public_key)
    pubkey_hash = hash160(compressed_pub)

    # Standard P2PKH scriptPubKey: OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG
    script_pubkey = (
        b"\x76"          # OP_DUP
        b"\xa9"          # OP_HASH160
        b"\x14"          # PUSH 20
        + pubkey_hash +
        b"\x88"          # OP_EQUALVERIFY
        b"\xac"          # OP_CHECKSIG
    )

    # For legacy SIGHASH_ALL preimage, scriptCode = scriptPubKey of the UTXO being spent
    script_code = script_pubkey

    # One input
    input_count = encode_varint(1)

    prev_txid = b"\x00" * 32          # dummy prev txid (little-endian)
    prev_index = (0).to_bytes(4, "little")

    script_code_len = encode_varint(len(script_code))
    sequence = (0xFFFFFFFF).to_bytes(4, "little")

    tx_in = (
        prev_txid +
        prev_index +
        script_code_len +
        script_code +
        sequence
    )

    # One output
    output_count = encode_varint(1)

    # Example value: 50 BTC in satoshi (arbitrary but realistic)
    value_sats = 50_0000_0000
    value = value_sats.to_bytes(8, "little")

    script_pubkey_len = encode_varint(len(script_pubkey))

    tx_out = (
        value +
        script_pubkey_len +
        script_pubkey
    )

    # Locktime and SIGHASH type
    locktime = (0).to_bytes(4, "little")
    sighash_all = (1).to_bytes(4, "little")  # SIGHASH_ALL = 0x00000001

    # Final preimage
    preimage = (
        version +
        input_count +
        tx_in +
        output_count +
        tx_out +
        locktime +
        sighash_all
    )

    return preimage


class Secp256k1:
    """Elliptic curve cryptography implementation for secp256k1."""

    def __init__(self, params: CurveParams):
        """Initialize curve with given parameters."""
        self._curve = params
        self._topology_of_key: List[List[int | str]] = []
        self._trace_topology: bool = False

    @property
    def curve(self) -> CurveParams:
        """Return elliptic curve parameters."""
        return self._curve

    def get_topology_of_key(self) -> List[List[int | str]]:
        """Return recorded topology of key generation steps."""
        return self._topology_of_key

    def _prepare_topology_of_key(self, q: Tuple[int, int]) -> None:
        """Truncate recorded topology at the final public key."""
        x3, y3 = q
        kept: List[List[int | str]] = []
        for row in self._topology_of_key:
            kept.append(row)
            if row[4] == x3 and row[5] == y3:
                break
        self._topology_of_key = kept

    @staticmethod
    def inverse_mod(k: int, p: int) -> int:
        """Compute modular multiplicative inverse of k mod p."""
        if k == 0:
            raise ZeroDivisionError("division by zero")
        return pow(k, -1, p)

    def is_on_curve(self, point: Point) -> bool:
        """Check whether a given point lies on the elliptic curve."""
        if point is None:
            return True
        x, y = point
        return (y**2 - x**3 - self._curve.a * x - self._curve.b) % self._curve.p == 0

    def point_add(self, p1: Point, p2: Point, op_flag: str | None = None) -> Point:
        """Add two elliptic curve points using group law."""
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        x1, y1 = p1
        x2, y2 = p2

        if x1 == x2 and y1 != y2:
            return None

        if x1 == x2:
            m = (3 * x1**2 + self._curve.a) * self.inverse_mod(2 * y1, self._curve.p)
            m %= self._curve.p
            x3 = (m**2 - 2 * x1) % self._curve.p
        else:
            m = (y2 - y1) * self.inverse_mod((x2 - x1) % self._curve.p, self._curve.p)
            m %= self._curve.p
            x3 = (m**2 - x1 - x2) % self._curve.p
        y3 = (m * (x1 - x3) - y1) % self._curve.p

        if self._trace_topology:
            self._topology_of_key.append([x1, y1, x2, y2, x3, y3, op_flag or ""])

        return x3, y3

    def scalar_multiply(self, k: int, p: Point) -> Point:
        """Perform scalar multiplication of a point by integer k."""
        if k % self._curve.n == 0 or p is None:
            return None

        if self._trace_topology:
            self._topology_of_key.clear()

        q: Point = None
        while k:
            if k & 1:
                q = self.point_add(q, p, op_flag="1")
            p = self.point_add(p, p, op_flag="")
            k >>= 1

        if isinstance(q, tuple) and len(q) == 2:
            if self._trace_topology:
                self._prepare_topology_of_key(q)
            return q
        return (0, 0)

    def generate_keypair(self, private_key: Optional[int] = None) -> Tuple[int, Tuple[int, int]]:
        """Generate private and public key pair."""
        if private_key is None:
            private_key = random.randrange(1, self._curve.n - 1)
        self._trace_topology = True
        public_key = self.scalar_multiply(private_key, self._curve.g)
        self._trace_topology = False
        return private_key, public_key  # type: ignore

    def hash_message(self, message: bytes) -> int:
        """Return integer hash of a message modulo curve order."""
        if self._curve.mode == "test":
            return random.randrange(1, self._curve.n - 1)
        # legacy / real secp256k1: use Bitcoin-style double SHA256
        h = hashlib.sha256(message).digest()
        h = hashlib.sha256(h).digest()
        return int.from_bytes(h, "big") % self._curve.n

    def sign_message(self, private_key: int, message: bytes) -> Tuple[int, int, int]:
        """Create ECDSA signature for a message using private key."""
        z = self.hash_message(message)
        while True:
            k = random.randrange(1, self._curve.n - 1)
            x, _ = self.scalar_multiply(k, self._curve.g)
            r = x % self._curve.n
            if r == 0:
                continue
            k_inv = self.inverse_mod(k, self._curve.n)
            s = ((z + r * private_key) * k_inv) % self._curve.n
            if s != 0:
                return z, r, s

    def verify_signature(self, public_key: Tuple[int, int], signature: Tuple[int, int, int]) -> bool:
        """Verify ECDSA signature against a given public key."""
        z, r, s = signature
        if not (1 <= r < self._curve.n and 1 <= s < self._curve.n):
            return False
        w = self.inverse_mod(s, self._curve.n)
        u1 = (z * w) % self._curve.n
        u2 = (r * w) % self._curve.n
        p1 = self.scalar_multiply(u1, self._curve.g)
        p2 = self.scalar_multiply(u2, public_key)
        if p1 is None or p2 is None:
            return False
        x, _ = self.point_add(p1, p2)
        if x is None:
            return False
        return (x % self._curve.n) == r

    def get_double_points(self) -> List[Tuple[int, int]]:
        """Generate sequence of double points starting from base point."""
        points: List[Tuple[int, int]] = [self._curve.g]
        p = self.point_add(self._curve.g, self._curve.g)
        points.append(p)  # type: ignore
        i = 1
        while i <= self._curve.l:
            p = self.point_add(p, p)  # type: ignore
            points.append(p)  # type: ignore
            i += 1
        return points

    @staticmethod
    def inverse_point(p: Tuple[int, int], mod_p: int) -> Tuple[int, int]:
        """Return additive inverse of a point modulo p."""
        x, y = p
        return x, (-y) % mod_p

    @staticmethod
    def count_subsets(idx_x1y1_first, idx_x2y2_first, total_adds, idx_x2y2_last) -> Tuple[int, int, int]:
        """Compute number of possible point subsets given topology parameters."""
        total_numbers = idx_x2y2_last - idx_x2y2_first - idx_x1y1_first
        combination_size = total_adds - 2
        total_combinations = math.comb(total_numbers, combination_size)
        return total_numbers, combination_size, total_combinations

    def restore_point(self, r: Tuple[int, int], q: Tuple[int, int]) -> Tuple[int, int]:
        """Recover point p1 from r = p1 + q and q."""
        q_inv = self.inverse_point(q, self._curve.p)
        return self.point_add(r, q_inv)  # type: ignore

    def identify_condition(
        self,
        topology_of_key: List[List[int | str]],
        double_points: List[Tuple[int, int]],
        public_key: Tuple[int, int],
    ) -> str:
        """Extract key generation condition identifiers from topology data."""
        idx_x1y1_first = 0
        idx_x2y2_first = 0
        total_adds = 0

        for row in topology_of_key:
            if row[6] == "1":
                total_adds += 1
                if total_adds == 1 and (row[0], row[1]) in double_points and (row[2], row[3]) in double_points:
                    idx_x1y1_first = double_points.index((row[0], row[1])) + 1
                    idx_x2y2_first = double_points.index((row[2], row[3])) + 1

        idx_x2y2_last = 0
        if topology_of_key:
            last = topology_of_key[-1]
            if (last[2], last[3]) in double_points and (last[4], last[5]) == public_key:
                idx_x2y2_last = double_points.index((last[2], last[3])) + 1

        return f"{idx_x1y1_first}_{idx_x2y2_first}_{total_adds}_{idx_x2y2_last}"

    def generate_unique_keys(self, count, range_start, range_end):
        """Generate a list of unique random integers within a specified range."""
        if self._curve.mode == "test":
            return random.sample(range(range_start, range_end), count)
        elif self._curve.mode == "legacy":
            seen = set()
            while len(seen) < count:
                candidate = random.randrange(range_start, range_end)
                if candidate not in seen:
                    seen.add(candidate)
            return list(seen)


def print_curve_run(curve: CurveParams, private_key: Optional[int] = None) -> None:
    """Run full demo sequence: key generation, signing, verification, analysis."""
    ec = Secp256k1(curve)

    print("Elliptic curve parameters:")
    print(f"name = {curve.name}")
    print(f"mode = {curve.mode}")
    print(f"p = {curve.p}")
    print(f"a = {curve.a}")
    print(f"b = {curve.b}")
    print(f"g = {curve.g}")
    print(f"n = {curve.n}\n")

    t0 = time.time()
    if private_key is not None:
        _, public_key = ec.generate_keypair(private_key=private_key)
    else:
        private_key, public_key = ec.generate_keypair()
    print("Private key:")
    print(f"  d: {hex(private_key)[2:]}, {private_key}, ({bin(private_key)[2:]})")
    print("Public key:")
    print(f"  x: {hex(public_key[0])[2:]}, {public_key[0]}")
    print(f"  y: {hex(public_key[1])[2:]}, {public_key[1]}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")

    t0 = time.time()
    print(f"Is the point on curve?: {ec.is_on_curve(public_key)}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")

    t0 = time.time()
    if curve.mode == "legacy":
        # For real secp256k1 use a Bitcoin legacy SIGHASH_ALL preimage (1-in-1-out P2PKH)
        message = make_bitcoin_legacy_sighash_message(public_key)
    else:
        # For test curves we keep an arbitrary message; z is randomized in hash_message
        message = b"Hello, secp256k1!"
    signature = ec.sign_message(private_key, message)
    print("Signature parameters:")
    print(f"  z: {hex(signature[0])[2:]}, {signature[0]}")
    print(f"  r: {hex(signature[1])[2:]}, {signature[1]}")
    print(f"  s: {hex(signature[2])[2:]}, {signature[2]}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")

    t0 = time.time()
    print(f"Signature validation: {ec.verify_signature(public_key, signature)}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")

    t0 = time.time()
    if curve.mode == "test":
        col_w, line_len = 12, 81
    else:
        col_w, line_len = 80, 489
    headers = ["x1", "y1", "x2", "y2", "x3", "y3", "operation"]
    line = "-" * line_len

    topology_of_key = ec.get_topology_of_key()
    if topology_of_key:
        print("Print topology of private key:")
        print(line)
        print("".join(f"{h:<{col_w}}" for h in headers))
        print(line)
        for row in topology_of_key:
            print("".join(f"{str(v):<{col_w}}" for v in row))
        print(line)
        print("".join(f"{h:<{col_w}}" for h in headers))
        print(line)
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")

    t0 = time.time()
    print("Print double points:")
    double_points = ec.get_double_points()
    for point in double_points:
        print(point)
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")

    t0 = time.time()
    print("Identify the conditions (based on the topology of private key):")
    idx_x1y1_first, idx_x2y2_first, total_adds, idx_x2y2_last = map(int, ec.identify_condition(topology_of_key, double_points, public_key).split("_"))
    print(f"Index of (x1, y1) point in first addition: {idx_x1y1_first}")
    print(f"Index of (x2, y2) point in first addition: {idx_x2y2_first}")
    print(f"Total added point count:                   {total_adds}")
    print(f"Index of (x2, y2) point in last addition:  {idx_x2y2_last}")
    print("Subset count:")
    total_numbers, combination_size, total_combinations = ec.count_subsets(idx_x1y1_first, idx_x2y2_first, total_adds, idx_x2y2_last)
    print(f"* Total numbers of unknown (x2, y2) points: {total_numbers}")
    print(f"* Count of added points (operation = 1):    {combination_size}")
    print(f"* Total combination count C({total_numbers}, {combination_size}): {total_combinations:,}")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")

    t0 = time.time()
    print("Inverse the last point:")
    if topology_of_key:
        last = topology_of_key[-1]
        x1, y1, x3, y3 = last[0], last[1], last[4], last[5]
        x2, y2 = double_points[idx_x2y2_last - 1] if idx_x2y2_last > 0 else double_points[0]
        p_restored = ec.restore_point((x3, y3), (x2, y2))
        if (x1, y1) == p_restored:
            print(f"Last known point (x3, y3) = {(x3, y3)}")
            print(f"Last known point (x2, y2) = {(x2, y2)}")
            print(f"Last known point (x1, y1) = {p_restored} [restored]")
            if ec.is_on_curve(p_restored):
                print(f"A point {p_restored} belongs to a curve!")
            else:
                print(f"A point {p_restored} does not belong to a curve!")
        else:
            print("Coudn't find last known point!")
    else:
        print("No topology data.")
    print(f"Spent time: {time.time() - t0:.3f} sec.\n")


def main() -> None:
    """Run demo for both test and legacy curves."""
    print("========== TEST CURVE ==========")
    print_curve_run(TEST_PARAMS, 950441759)

    print("========== LEGACY CURVE ==========")
    print_curve_run(LEGACY_PARAMS)


if __name__ == "__main__":
    main()
