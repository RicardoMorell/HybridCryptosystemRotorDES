"""
des.py - Python implementation of the Data Encryption Standard (DES)

This module implements:
    - DES block encryption/decryption (64-bit blocks, 64-bit key including parity)
    - ECB mode with PKCS#5-style padding for arbitrary-length byte strings

Public functions we will likely use:

    des_encrypt(data: bytes, key: bytes) -> bytes
    des_decrypt(data: bytes, key: bytes) -> bytes

    # For single 8-byte blocks:
    des_encrypt_block(block: bytes, key: bytes) -> bytes
    des_decrypt_block(block: bytes, key: bytes) -> bytes

All the math is done using integers and bit operations, which matches
the Feistel + permutation description from the class slides.
"""

from typing import List

# ============================================================
# DES TABLES (from the standard)
# ============================================================

# Initial Permutation (IP)
IP_TABLE = [
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
]

# Final Permutation (IP^-1)
FP_TABLE = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
]

# Expansion permutation E (32 -> 48 bits)
E_TABLE = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
]

# P-box permutation (32 -> 32 bits)
P_TABLE = [
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25,
]

# S-boxes: 8 boxes, each 4x16
S_BOXES = [
    # S1
    [
        [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
        [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
        [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
        [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
    ],
    # S2
    [
        [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
        [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
        [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
        [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9],
    ],
    # S3
    [
        [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
        [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
        [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
        [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12],
    ],
    # S4
    [
        [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
        [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
        [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
        [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14],
    ],
    # S5
    [
        [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
        [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
        [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
        [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3],
    ],
    # S6
    [
        [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
        [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
        [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
        [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13],
    ],
    # S7
    [
        [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
        [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
        [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
        [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12],
    ],
    # S8
    [
        [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
        [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
        [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
        [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11],
    ],
]

# PC-1 (key permutation, 64 -> 56 bits)
PC1_TABLE = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
]

# PC-2 (key compression, 56 -> 48 bits)
PC2_TABLE = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

# Left shifts per round (16 rounds)
LEFT_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2,
               1, 2, 2, 2, 2, 2, 2, 1]

# ============================================================
# Bit/Permutation helpers
# ============================================================

def bytes_to_int(block: bytes) -> int:
    """Convert a sequence of bytes to an integer (big endian)."""
    value = 0
    for b in block:
        value = (value << 8) | b
    return value


def int_to_bytes(value: int, length: int) -> bytes:
    """Convert an integer to a big-endian byte string of given length."""
    return bytes((value >> (8 * (length - 1 - i))) & 0xFF for i in range(length))


def permute(block: int, table: List[int], input_bits: int) -> int:
    """
    Generic permutation.
    - block: integer containing 'input_bits' bits.
    - table: list of positions (1-based from MSB) to select from the input.
    Returns an integer whose bit length == len(table).
    """
    result = 0
    for position in table:
        # Convert 1-based position from MSB to 0-based from LSB
        # Position 1 -> bit index input_bits-1
        bit_index = input_bits - position
        bit = (block >> bit_index) & 1
        result = (result << 1) | bit
    return result


def left_rotate(value: int, shift: int, bit_len: int) -> int:
    """Circular left shift on a bit_len-bit value."""
    shift %= bit_len
    return ((value << shift) & ((1 << bit_len) - 1)) | (value >> (bit_len - shift))


# ============================================================
# Key schedule
# ============================================================

def generate_round_keys(key64: int) -> List[int]:
    """
    Generate the 16 round keys (each 48 bits) from a 64-bit key (including parity bits).
    Steps:
        - PC-1: 64 -> 56 bits
        - split into C and D (28 bits each)
        - for each round: left-shift C and D, combine, apply PC-2: 56 -> 48 bits
    """
    # Apply PC-1
    key56 = permute(key64, PC1_TABLE, 64)

    # Split into C and D (28 bits each)
    C = (key56 >> 28) & ((1 << 28) - 1)
    D = key56 & ((1 << 28) - 1)

    round_keys: List[int] = []

    for shift in LEFT_SHIFTS:
        C = left_rotate(C, shift, 28)
        D = left_rotate(D, shift, 28)
        combined = (C << 28) | D
        K = permute(combined, PC2_TABLE, 56)  # 48-bit subkey
        round_keys.append(K)

    return round_keys


# ============================================================
# Round function F (Feistel)
# ============================================================

def sbox_substitution(block48: int) -> int:
    """
    Apply the 8 DES S-boxes to a 48-bit value.
    - Input: 48 bits (as int)
    - Output: 32 bits (as int)
    Processing:
        Split into eight 6-bit chunks, each chunk -> one S-box.
        Each S-box output is 4 bits; concat them into 32 bits.
    """
    result = 0
    # Process from left (MSB) to right
    for i in range(8):
        # Take 6 bits: chunk 0 is the leftmost 6 bits
        shift = 6 * (7 - i)
        six_bits = (block48 >> shift) & 0b111111

        # Row = first and last bits (b5 and b0)
        row = ((six_bits & 0b100000) >> 4) | (six_bits & 0b000001)
        # Column = middle 4 bits (b4..b1)
        col = (six_bits >> 1) & 0b1111

        sbox_value = S_BOXES[i][row][col]  # 0..15
        result = (result << 4) | sbox_value

    return result


def feistel_f(R: int, K: int) -> int:
    """
    DES round function F.
    - R: 32-bit right half
    - K: 48-bit subkey for this round
    Steps:
        1. Expansion E: 32 -> 48 bits
        2. XOR with subkey K
        3. S-box substitution: eight 6->4 boxes, yields 32 bits
        4. P permutation on the 32-bit result
    """
    # 1. Expansion
    ER = permute(R, E_TABLE, 32)  # 48 bits

    # 2. Key mixing (XOR)
    x = ER ^ K

    # 3. S-boxes
    s_output = sbox_substitution(x)  # 32 bits

    # 4. P-box permutation
    return permute(s_output, P_TABLE, 32)


# ============================================================
# Block encryption/decryption (single 64-bit block)
# ============================================================

def des_encrypt_block_int(block64: int, key64: int) -> int:
    """
    Encrypt a single 64-bit block (as int) with DES.
    """
    # Initial permutation (IP)
    ip = permute(block64, IP_TABLE, 64)

    # Split into left and right halves
    L = (ip >> 32) & 0xFFFFFFFF
    R = ip & 0xFFFFFFFF

    # Generate 16 round keys
    round_keys = generate_round_keys(key64)

    # 16 Feistel rounds
    for i in range(16):
        new_L = R
        new_R = L ^ feistel_f(R, round_keys[i])
        L, R = new_L, new_R

    # Swap halves
    pre_output = (R << 32) | L

    # Final permutation (FP)
    cipher = permute(pre_output, FP_TABLE, 64)
    return cipher


def des_decrypt_block_int(block64: int, key64: int) -> int:
    """
    Decrypt a single 64-bit block (as int) with DES.
    Same as encryption but round keys are applied in reverse order.
    """
    # Initial permutation (IP)
    ip = permute(block64, IP_TABLE, 64)

    # Split into halves
    L = (ip >> 32) & 0xFFFFFFFF
    R = ip & 0xFFFFFFFF

    # Round keys in reverse for decryption
    round_keys = generate_round_keys(key64)

    for i in range(15, -1, -1):
        new_L = R
        new_R = L ^ feistel_f(R, round_keys[i])
        L, R = new_L, new_R

    pre_output = (R << 32) | L
    plain = permute(pre_output, FP_TABLE, 64)
    return plain


def des_encrypt_block(block: bytes, key: bytes) -> bytes:
    """
    Encrypt a single 8-byte block with DES.
    - block: 8 bytes plaintext
    - key:   8 bytes key (64 bits incl. parity)
    """
    if len(block) != 8:
        raise ValueError("Block must be exactly 8 bytes")
    if len(key) != 8:
        raise ValueError("Key must be exactly 8 bytes")

    block64 = bytes_to_int(block)
    key64 = bytes_to_int(key)
    cipher64 = des_encrypt_block_int(block64, key64)
    return int_to_bytes(cipher64, 8)


def des_decrypt_block(block: bytes, key: bytes) -> bytes:
    """
    Decrypt a single 8-byte block with DES.
    """
    if len(block) != 8:
        raise ValueError("Block must be exactly 8 bytes")
    if len(key) != 8:
        raise ValueError("Key must be exactly 8 bytes")

    block64 = bytes_to_int(block)
    key64 = bytes_to_int(key)
    plain64 = des_decrypt_block_int(block64, key64)
    return int_to_bytes(plain64, 8)


# ============================================================
# Padding + ECB mode for arbitrary-length data
# ============================================================

def _pkcs5_pad(data: bytes) -> bytes:
    """
    PKCS#5-style padding for 8-byte blocks.
    If len(data) is already a multiple of 8, an extra block of 8 bytes (0x08) is added.
    """
    pad_len = 8 - (len(data) % 8)
    if pad_len == 0:
        pad_len = 8
    return data + bytes([pad_len]) * pad_len


def _pkcs5_unpad(data: bytes) -> bytes:
    """
    Remove PKCS#5-style padding.
    """
    if not data:
        raise ValueError("Cannot unpad empty data")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding")
    if pad_len > len(data):
        raise ValueError("Invalid padding length")

    # Optionally, check that all padding bytes are equal to pad_len
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")

    return data[:-pad_len]


def des_encrypt(data: bytes, key: bytes) -> bytes:
    """
    Encrypt arbitrary-length data using DES in ECB mode with PKCS#5 padding.
    """
    if len(key) != 8:
        raise ValueError("Key must be exactly 8 bytes")

    padded = _pkcs5_pad(data)
    result = bytearray()

    for i in range(0, len(padded), 8):
        block = padded[i:i+8]
        result.extend(des_encrypt_block(block, key))

    return bytes(result)


def des_decrypt(data: bytes, key: bytes) -> bytes:
    """
    Decrypt data encrypted with des_encrypt (ECB + PKCS#5).
    """
    if len(key) != 8:
        raise ValueError("Key must be exactly 8 bytes")
    if len(data) % 8 != 0:
        raise ValueError("Ciphertext length must be multiple of 8")

    result = bytearray()

    for i in range(0, len(data), 8):
        block = data[i:i+8]
        result.extend(des_decrypt_block(block, key))

    return _pkcs5_unpad(bytes(result))


# ============================================================
# Simple self-test (run this file directly)
# ============================================================

if __name__ == "__main__":
    # ---------------------------------------------------
    # Test 1: Standard DES test vector (single block)
    # ---------------------------------------------------
    # key = 0x133457799BBCDFF1
    # plaintext = 0x0123456789ABCDEF
    # ciphertext should be 0x85E813540F0AB405
    key = bytes.fromhex("133457799BBCDFF1")
    pt = bytes.fromhex("0123456789ABCDEF")

    ct = des_encrypt_block(pt, key)
    print("Test 1 - Standard vector")
    print("  Ciphertext:", ct.hex().upper())
    recovered = des_decrypt_block(ct, key)
    print("  Recovered :", recovered.hex().upper())
    print("  Test passed:", recovered == pt)
    print()

    # ---------------------------------------------------
    # Test 2: Different key + plaintext (block-level)
    # ---------------------------------------------------
    key2 = b"NEW_KEY!"        # 8-byte key
    pt2  = b"ABCDEFGH"        # 8-byte plaintext block

    ct2 = des_encrypt_block(pt2, key2)
    rec2 = des_decrypt_block(ct2, key2)

    print("Test 2 - Custom block")
    print("  Plaintext :", pt2)
    print("  Ciphertext:", ct2.hex().upper())
    print("  Recovered :", rec2)
    print("  Test passed:", rec2 == pt2)
    print()

    # ---------------------------------------------------
    # Test 3: High-level ECB + padding (multi-block)
    # ---------------------------------------------------
    msg = b"HELLO MY NAME IS IVANIER"   # length not multiple of 8
    ct3 = des_encrypt(msg, key)   # reuse key from Test 1
    rec3 = des_decrypt(ct3, key)

    print("Test 3 - ECB + PKCS#5 padding")
    print("  Plaintext :", msg)
    print("  Ciphertext:", ct3.hex().upper())
    print("  Recovered :", rec3)
    print("  Test passed:", rec3 == msg)


