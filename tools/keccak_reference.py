"""
Keccak-f[1600] reference implementation in Python.

Produces per-round intermediate states for verification against RTL.
State is represented as a flat list of 25 64-bit lanes, indexed as A[5*y + x].
Byte order within lanes is little-endian (FIPS 202 Section 3.1.2).
"""

# Round constants (from FIPS 202 / keccak.team)
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# Rotation offsets r[x][y]
ROT_OFFSETS = [
    # y=0  y=1  y=2  y=3  y=4
    [  0,  36,   3,  41,  18],  # x=0
    [  1,  44,  10,  45,   2],  # x=1
    [ 62,   6,  43,  15,  61],  # x=2
    [ 28,  55,  25,  21,  56],  # x=3
    [ 27,  20,  39,   8,  14],  # x=4
]

MASK64 = (1 << 64) - 1


def rotl64(val, n):
    """Left rotate a 64-bit value by n positions."""
    n = n % 64
    return ((val << n) | (val >> (64 - n))) & MASK64


def keccak_round(state, round_num):
    """Apply one round of Keccak-f[1600].

    Args:
        state: list of 25 uint64 lanes, indexed as state[5*y + x]
        round_num: round index 0..23

    Returns:
        New list of 25 uint64 lanes after one round.
    """
    # Theta
    C = [0] * 5
    for x in range(5):
        C[x] = state[x] ^ state[5+x] ^ state[10+x] ^ state[15+x] ^ state[20+x]

    D = [0] * 5
    for x in range(5):
        D[x] = C[(x - 1) % 5] ^ rotl64(C[(x + 1) % 5], 1)

    theta_out = [0] * 25
    for y in range(5):
        for x in range(5):
            theta_out[5*y + x] = (state[5*y + x] ^ D[x]) & MASK64

    # Rho
    rho_out = [0] * 25
    for y in range(5):
        for x in range(5):
            rho_out[5*y + x] = rotl64(theta_out[5*y + x], ROT_OFFSETS[x][y])

    # Pi: A'[y, (2x+3y) mod 5] = A[x, y]
    pi_out = [0] * 25
    for y in range(5):
        for x in range(5):
            new_x = y
            new_y = (2 * x + 3 * y) % 5
            pi_out[5 * new_y + new_x] = rho_out[5*y + x]

    # Chi
    chi_out = [0] * 25
    for y in range(5):
        for x in range(5):
            chi_out[5*y + x] = (
                pi_out[5*y + x]
                ^ ((~pi_out[5*y + (x+1) % 5] & MASK64) & pi_out[5*y + (x+2) % 5])
            ) & MASK64

    # Iota
    chi_out[0] ^= RC[round_num]

    return chi_out


def keccak_f1600(state, trace=False):
    """Apply full Keccak-f[1600] permutation (24 rounds).

    Args:
        state: list of 25 uint64 lanes
        trace: if True, return list of intermediate states after each round

    Returns:
        If trace=False: final state (list of 25 uint64)
        If trace=True: list of 25 states (one after each round)
    """
    states = []
    for r in range(24):
        state = keccak_round(state, r)
        if trace:
            states.append(list(state))
    return states if trace else state


def state_to_bytes(state):
    """Convert lane array to 200-byte array (FIPS 202 byte order)."""
    result = bytearray(200)
    for i in range(25):
        for b in range(8):
            result[i * 8 + b] = (state[i] >> (8 * b)) & 0xFF
    return bytes(result)


def bytes_to_state(data):
    """Convert 200-byte array to lane array."""
    state = [0] * 25
    padded = data + b'\x00' * (200 - len(data))
    for i in range(25):
        for b in range(8):
            state[i] |= padded[i * 8 + b] << (8 * b)
    return state


def state_to_hex(state):
    """Format state as hex string of the first 200 bytes."""
    return state_to_bytes(state).hex()


if __name__ == "__main__":
    # Test: Keccak-f[1600] on all-zero state
    zero_state = [0] * 25
    result = keccak_f1600(zero_state)
    print("Keccak-f[1600](zero state):")
    for i, lane in enumerate(result):
        x = i % 5
        y = i // 5
        print(f"  A[{x},{y}] = {lane:016x}")

    # Known output for Keccak-f[1600] on all-zeros:
    # Lane A[0,0] should be 0xF1258F7940E1DDE7
    expected_lane_0_0 = 0xF1258F7940E1DDE7
    assert result[0] == expected_lane_0_0, \
        f"Lane A[0,0]: got {result[0]:016x}, expected {expected_lane_0_0:016x}"
    print("\nAll-zeros test PASSED!")

    # Print per-round trace for first 2 rounds
    print("\nPer-round trace (all-zeros input):")
    traced = keccak_f1600(zero_state, trace=True)
    for r in range(2):
        print(f"  After round {r}: A[0,0] = {traced[r][0]:016x}")
