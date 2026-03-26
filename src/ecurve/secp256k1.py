#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PEP 8 compliant secp256k1 demo with key generation, signing, verification,
and curve analysis for both test and legacy parameters.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import math
import os
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


def make_bitcoin_legacy_sighash_message(
    public_key: Tuple[int, int],
    prev_txid: bytes = b"\x00" * 32,
    prev_index: int = 0,
    output_value_sats: int = 49_9999_0000,
) -> bytes:
    """
    Build a Bitcoin legacy SIGHASH_ALL preimage for a simple 1-in-1-out P2PKH transaction.

    Parameters
    ----------
    public_key : Tuple[int, int]
        Uncompressed (x, y) public key of the signer.
    prev_txid : bytes
        32-byte txid of the UTXO being spent (little-endian, per protocol).
    prev_index : int
        Output index within the previous transaction (vout).
    output_value_sats : int
        Value sent to the single output, in satoshi (input minus fee).
        Note: legacy SIGHASH_ALL does NOT commit to input value — only to
        output value.  This is the vulnerability that BIP 143 fixes.
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

    prev_index_bytes = prev_index.to_bytes(4, "little")

    script_code_len = encode_varint(len(script_code))
    sequence = (0xFFFFFFFF).to_bytes(4, "little")

    tx_in = (
        prev_txid +
        prev_index_bytes +
        script_code_len +
        script_code +
        sequence
    )

    # One output
    output_count = encode_varint(1)

    value = output_value_sats.to_bytes(8, "little")

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


def make_bitcoin_segwit_sighash_message(
    public_key: Tuple[int, int],
    prev_txid: bytes = b"\x00" * 32,
    prev_index: int = 0,
    input_value_sats: int = 50_0000_0000,
    output_value_sats: int = 49_9999_0000,
) -> bytes:
    """
    Build a Bitcoin SegWit v0 (BIP 143) SIGHASH_ALL preimage for a simple
    1-in-1-out P2WPKH transaction.
 
    BIP 143 defines a fundamentally different serialization than legacy:
      1.  nVersion              (4 bytes LE)
      2.  hashPrevouts          (32 bytes) - dSHA256 of all input outpoints
      3.  hashSequence          (32 bytes) - dSHA256 of all input sequences
      4.  outpoint              (36 bytes) - txid + vout of the input being signed
      5.  scriptCode            (variable) - for P2WPKH: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
      6.  value                 (8 bytes LE) - satoshi value of the UTXO being spent
      7.  nSequence             (4 bytes LE) - sequence of the input being signed
      8.  hashOutputs           (32 bytes) - dSHA256 of all serialized outputs
      9.  nLockTime             (4 bytes LE)
      10. nHashType             (4 bytes LE)
 
    Parameters
    ----------
    public_key : Tuple[int, int]
        Uncompressed (x, y) public key of the signer.
    prev_txid : bytes
        32-byte txid of the UTXO being spent (little-endian, per protocol).
    prev_index : int
        Output index within the previous transaction (vout).
    input_value_sats : int
        Value of the UTXO being spent, in satoshi.  BIP 143 commits to this
        value — this is the critical anti-fee-manipulation field.
    output_value_sats : int
        Value sent to the single output, in satoshi (input minus fee).

    Reference: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    """
    # --- Transaction metadata ---
    n_version = (2).to_bytes(4, "little")  # version 2 (common for SegWit tx)
    n_locktime = (0).to_bytes(4, "little")
    n_hashtype = (1).to_bytes(4, "little")  # SIGHASH_ALL
 
    # --- Single input: outpoint from the UTXO being spent ---
    prev_vout = prev_index.to_bytes(4, "little")
    outpoint = prev_txid + prev_vout
 
    sequence = (0xFFFFFFFF).to_bytes(4, "little")
 
    # hashPrevouts = dSHA256(outpoint)  (only one input)
    hash_prevouts = hashlib.sha256(hashlib.sha256(outpoint).digest()).digest()
 
    # hashSequence = dSHA256(sequence)  (only one input)
    hash_sequence = hashlib.sha256(hashlib.sha256(sequence).digest()).digest()
 
    # --- scriptCode for P2WPKH ---
    compressed_pub = compress_public_key(public_key)
    pubkey_hash = hash160(compressed_pub)
    script_code = (
        b"\x19"          # length: 25 bytes
        b"\x76"          # OP_DUP
        b"\xa9"          # OP_HASH160
        b"\x14"          # PUSH 20
        + pubkey_hash +
        b"\x88"          # OP_EQUALVERIFY
        b"\xac"          # OP_CHECKSIG
    )
 
    # --- Value of the UTXO being spent (BIP 143 critical field!) ---
    value = input_value_sats.to_bytes(8, "little")
 
    # --- Single output: pay to same pubkey hash ---
    out_script_pubkey = (
        b"\x76\xa9\x14"
        + pubkey_hash
        + b"\x88\xac"
    )
    out_value = output_value_sats.to_bytes(8, "little")
    serialized_output = (
        out_value
        + encode_varint(len(out_script_pubkey))
        + out_script_pubkey
    )
 
    # hashOutputs = dSHA256(serialized outputs)  (only one output)
    hash_outputs = hashlib.sha256(hashlib.sha256(serialized_output).digest()).digest()
 
    # --- BIP 143 preimage assembly ---
    preimage = (
        n_version
        + hash_prevouts
        + hash_sequence
        + outpoint
        + script_code
        + value
        + sequence
        + hash_outputs
        + n_locktime
        + n_hashtype
    )
 
    return preimage


def int_to_bytes(value: int, byteorder: str = 'big') -> bytes:
    """
    Convert an integer to bytes with the minimum required length.
    
    :param value: Integer to convert.
    :param byteorder: 'big' or 'little' endian.
    :return: Bytes representation of the integer.
    """
    if not isinstance(value, int):
        raise TypeError("Value must be an integer.")
    if byteorder not in ('big', 'little'):
        raise ValueError("byteorder must be 'big' or 'little'.")

    # Handle zero explicitly (bit_length() would return 0)
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, byteorder)


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
    
    def _rfc6979_generate_k(self, private_key: int, z: int) -> int:
        """
        RFC 6979 deterministic nonce generation (HMAC-SHA256).
        Used for legacy secp256k1 only.
        """
        n = self._curve.n
        qlen = n.bit_length()
        holen = hashlib.sha256().digest_size
        rolen = (qlen + 7) // 8

        bx = private_key.to_bytes(rolen, "big") + z.to_bytes(rolen, "big")

        v = b"\x01" * holen
        k = b"\x00" * holen

        k = hmac.new(k, v + b"\x00" + bx, hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()
        k = hmac.new(k, v + b"\x01" + bx, hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()

        while True:
            v = hmac.new(k, v, hashlib.sha256).digest()
            candidate = int.from_bytes(v, "big")
            k_candidate = candidate % n
            if 1 <= k_candidate < n:
                return k_candidate

    def _generate_private_key(self) -> int:
        """Generate a random private key within the valid range."""
        length_in_bytes = len(int_to_bytes(self._curve.n, 'big'))
        # Based on real Bitcoin / secp256k1 model! (for legacy and test curves)
        while True:
            private_key = int.from_bytes(os.urandom(length_in_bytes), "big")
            if 1 <= private_key < self._curve.n:
                return private_key

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
            private_key = self._generate_private_key()
        self._trace_topology = True
        public_key = self.scalar_multiply(private_key, self._curve.g)
        self._trace_topology = False
        return private_key, public_key  # type: ignore

    def hash_message(self, message: bytes) -> int:
        """Return integer hash of a message modulo curve order."""
        if self._curve.mode == "test":
            return random.randrange(1, self._curve.n - 1)
        # legacy / real secp256k1: use Bitcoin-style double SHA256
        hash = hashlib.sha256(hashlib.sha256(message).digest()).digest()
        return int.from_bytes(hash, "big") % self._curve.n

    def sign_message(self, private_key: int, message: bytes, min_start_range: int) -> Tuple[int, int, int]:
        """Create ECDSA signature for a message using private key."""
        z = self.hash_message(message)
        while True:
            if self._curve.mode == "legacy":
                k = self._rfc6979_generate_k(private_key, z)
                if k < min_start_range:
                    continue
            else: # "test"
                k = random.randrange(min_start_range, self._curve.n - 1)
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

    def generate_unique_keys(self, count: int, min_start_range: int) -> list[int]:
        """Generate a list of unique random integers within a specified range."""
        seen = set()
        while len(seen) < count:
            candidate = self._generate_private_key()
            if candidate < min_start_range:
                continue
            if candidate not in seen:
                seen.add(candidate)
        return list(seen)


def print_curve_run(curve: CurveParams, private_key: Optional[int] = None, sig_type: str = "p2pkh") -> None:
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
        prev_txid = os.urandom(32)
        if sig_type == "p2wpkh":
            # SegWit v0 (P2WPKH) — BIP 143 SIGHASH_ALL preimage
            message = make_bitcoin_segwit_sighash_message(public_key, prev_txid)
            print("Using BIP 143 SegWit v0 preimage for signing.")
        else:
            # Legacy P2PKH — traditional SIGHASH_ALL preimage
            message = make_bitcoin_legacy_sighash_message(public_key, prev_txid)
            print("Using legacy P2PKH preimage for signing.")
    else:
        # For test curves we keep an arbitrary message; z is randomized in hash_message
        message = b"Hello, secp256k1!"
    signature = ec.sign_message(private_key, message, min_start_range=1)
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
    print("============================================================")
    print("========== DEMO RUNS FOR PREDEFINED 'private_key' ==========")
    print("============================================================")
    print("")
    print("========== TEST CURVE ==========")
    d = 1180926333
    print_curve_run(curve=TEST_PARAMS, private_key=d)

    print("========== LEGACY CURVE ==========")
    d = 64389052532870313044990203562685705333461655978490098671693221677551702405611
    print_curve_run(curve=LEGACY_PARAMS, private_key=d)
    print("========== LEGACY CURVE ==========")
    print_curve_run(curve=LEGACY_PARAMS, private_key=d, sig_type="p2wpkh")

    print("")

    print("============================================================")
    print("============ DEMO RUNS FOR DYNAMIC 'private_key' ===========")
    print("============================================================")
    print("")
    print("========== TEST CURVE ==========")
    print_curve_run(curve=TEST_PARAMS)

    print("========== LEGACY CURVE ==========")
    print_curve_run(curve=LEGACY_PARAMS)
    print("========== LEGACY CURVE ==========")
    print_curve_run(LEGACY_PARAMS, sig_type="p2wpkh")


if __name__ == "__main__":
    main()
