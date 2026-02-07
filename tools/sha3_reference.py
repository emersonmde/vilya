"""
SHA-3-256 reference implementation with padding helper.

Uses keccak_reference.py for the permutation. Provides:
- SHA-3 padding (pad10*1 with domain suffix 0x06)
- Full SHA-3-256 hash computation
- Pre-padded block generation for hardware interface
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from keccak_reference import keccak_f1600, bytes_to_state, state_to_bytes


RATE_BYTES = 136  # SHA-3-256 rate = 1088 bits = 136 bytes


def sha3_256_pad(message):
    """Apply SHA-3 padding (pad10*1 with domain suffix 0x06).

    Returns list of 136-byte blocks ready for absorption.
    """
    msg = bytearray(message)

    # Append domain suffix and padding
    # SHA-3 uses suffix 0x06, then pad10*1
    msg.append(0x06)

    # Pad to multiple of rate
    while len(msg) % RATE_BYTES != 0:
        msg.append(0x00)

    # Set the last bit of the last byte of the last block
    msg[-1] |= 0x80

    # Split into blocks
    blocks = []
    for i in range(0, len(msg), RATE_BYTES):
        blocks.append(bytes(msg[i:i + RATE_BYTES]))

    return blocks


def sha3_256(message):
    """Compute SHA-3-256 hash of a message.

    Args:
        message: bytes-like input

    Returns:
        32-byte digest as bytes
    """
    blocks = sha3_256_pad(message)

    # Initialize state
    state = [0] * 25

    # Absorb
    for block in blocks:
        # XOR block into state (rate portion only = first 136 bytes)
        block_state = bytes_to_state(block + b'\x00' * 64)  # pad to 200 bytes
        for i in range(17):  # 136 bytes = 17 lanes
            state[i] ^= block_state[i]
        state = keccak_f1600(state)

    # Squeeze (output = first 32 bytes = 4 lanes)
    output = state_to_bytes(state)[:32]
    return output


def format_padded_blocks(message):
    """Return pre-padded blocks as hex, for feeding to hardware."""
    blocks = sha3_256_pad(message)
    result = []
    for i, block in enumerate(blocks):
        result.append(f"Block {i} ({len(block)} bytes): {block.hex()}")
    return result


if __name__ == "__main__":
    # Test vectors
    test_vectors = [
        (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    ]

    for msg, expected_hex in test_vectors:
        digest = sha3_256(msg)
        digest_hex = digest.hex()
        status = "PASS" if digest_hex == expected_hex else "FAIL"
        print(f"[{status}] SHA-3-256({msg!r})")
        print(f"  Expected: {expected_hex}")
        print(f"  Got:      {digest_hex}")

        # Show padded blocks
        blocks = format_padded_blocks(msg)
        for b in blocks:
            print(f"  {b}")
        print()

    # Additional test: message > 136 bytes (multi-block)
    long_msg = b"a" * 200
    digest = sha3_256(long_msg)
    print(f"SHA-3-256('a' * 200) = {digest.hex()}")
    blocks = format_padded_blocks(long_msg)
    for b in blocks:
        print(f"  {b}")

    # Verify against hashlib
    try:
        import hashlib
        for msg, expected_hex in test_vectors:
            h = hashlib.sha3_256(msg).hexdigest()
            assert h == expected_hex, f"hashlib mismatch for {msg!r}"

        h = hashlib.sha3_256(long_msg).hexdigest()
        assert h == digest.hex(), f"hashlib mismatch for long message"
        print("\nAll hashlib cross-checks PASSED!")
    except ImportError:
        print("\nhashlib not available for cross-check")
