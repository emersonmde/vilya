# SPDX-FileCopyrightText: (c) 2026 Matthew Emerson
# SPDX-License-Identifier: Apache-2.0

"""
Cocotb tests for the SHA-3-256 hardware accelerator.

Tests the full hash pipeline through the TT wrapper pin interface:
  - ui_in[7:0]  = data input byte
  - uo_out[7:0] = hash output byte
  - uio_in[0]   = start
  - uio_in[1]   = data_valid
  - uio_in[2]   = last_block
  - uio_in[3]   = result_next
  - uio_out[4]  = busy
  - uio_out[5]  = result_ready
  - uio_out[6]  = absorb_ready
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, RisingEdge

from sha3_reference import sha3_256, sha3_256_pad
from keccak_reference import keccak_f1600, state_to_bytes


# ---------------------------------------------------------------------------
# Helper functions for driving the TT pin interface
# ---------------------------------------------------------------------------

async def reset_dut(dut):
    """Apply reset and initialize all inputs."""
    dut.ena.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 10)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 2)


async def start_hash(dut):
    """Pulse the start signal for one clock cycle."""
    dut.uio_in.value = 0x01  # start = bit 0
    await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0x00
    await ClockCycles(dut.clk, 1)


async def absorb_block(dut, block, is_last=False):
    """Feed a 136-byte block into the absorber, one byte per cycle."""
    assert len(block) == 136, f"Block must be 136 bytes, got {len(block)}"

    for i, byte_val in enumerate(block):
        dut.ui_in.value = byte_val
        uio_val = 0x02  # data_valid = bit 1
        if is_last:
            uio_val |= 0x04  # last_block = bit 2
        dut.uio_in.value = uio_val
        await ClockCycles(dut.clk, 1)

    # Deassert data_valid
    dut.uio_in.value = 0x00
    dut.ui_in.value = 0


def get_status(dut):
    """Read status signals from uio_out. Returns (busy, result_ready, absorb_ready)."""
    val = int(dut.uio_out.value)
    return (val >> 4) & 1, (val >> 5) & 1, (val >> 6) & 1


async def wait_permutation(dut, timeout=100):
    """Wait for the Keccak permutation to complete."""
    for _ in range(timeout):
        await ClockCycles(dut.clk, 1)
        busy, _, _ = get_status(dut)
        if not busy:
            return
    raise TimeoutError("Permutation did not complete within timeout")


async def read_hash(dut, num_bytes=32):
    """Read hash output bytes using result_next."""
    result = []

    # First byte is available immediately when result_ready goes high
    await ClockCycles(dut.clk, 1)
    result.append(int(dut.uo_out.value) & 0xFF)

    # Read remaining bytes
    for i in range(num_bytes - 1):
        dut.uio_in.value = 0x08  # result_next = bit 3
        await ClockCycles(dut.clk, 1)
        dut.uio_in.value = 0x00
        await ClockCycles(dut.clk, 1)
        result.append(int(dut.uo_out.value) & 0xFF)

    return bytes(result)


async def compute_hash(dut, message):
    """Full SHA-3-256 hash computation through the pin interface.

    Args:
        dut: cocotb DUT handle
        message: raw message bytes (will be padded)

    Returns:
        32-byte hash digest
    """
    blocks = sha3_256_pad(message)

    await start_hash(dut)

    for i, block in enumerate(blocks):
        is_last = (i == len(blocks) - 1)
        await absorb_block(dut, block, is_last=is_last)
        await wait_permutation(dut)

    return await read_hash(dut)


# ---------------------------------------------------------------------------
# Test: Keccak-f[1600] permutation on all-zeros (Phase 2 gate)
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_keccak_f1600_zeros(dut):
    """Verify Keccak-f[1600] on all-zeros state matches reference."""
    dut._log.info("test_keccak_f1600_zeros: start")

    clock = Clock(dut.clk, 30, unit="ns")  # ~33 MHz
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    # Start a hash, absorb 136 zero bytes (all zeros XOR state = no change),
    # then run permutation. This tests Keccak-f[1600](zero state).
    await start_hash(dut)

    # Absorb 136 zero bytes as last block
    zero_block = bytes(136)
    await absorb_block(dut, zero_block, is_last=True)

    # Wait for permutation
    await wait_permutation(dut)

    # Read first 32 bytes of output
    hw_output = await read_hash(dut)

    # Reference: Keccak-f[1600] on all-zeros, then read first 32 bytes
    ref_state = keccak_f1600([0] * 25)
    ref_bytes = state_to_bytes(ref_state)[:32]

    dut._log.info(f"HW output:  {hw_output.hex()}")
    dut._log.info(f"Reference:  {ref_bytes.hex()}")

    assert hw_output == ref_bytes, \
        f"Mismatch!\n  HW:  {hw_output.hex()}\n  Ref: {ref_bytes.hex()}"

    dut._log.info("test_keccak_f1600_zeros: PASSED")


# ---------------------------------------------------------------------------
# Test: SHA-3-256("") — empty message (Phase 3 gate)
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_sha3_256_empty(dut):
    """SHA-3-256 of empty message must produce known hash."""
    dut._log.info("test_sha3_256_empty: start")

    clock = Clock(dut.clk, 30, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    hw_hash = await compute_hash(dut, b"")
    expected = bytes.fromhex(
        "a7ffc6f8bf1ed76651c14756a061d662"
        "f580ff4de43b49fa82d80a4b80f8434a"
    )

    dut._log.info(f"HW hash:    {hw_hash.hex()}")
    dut._log.info(f"Expected:   {expected.hex()}")

    assert hw_hash == expected, \
        f"SHA-3-256('') mismatch!\n  HW:  {hw_hash.hex()}\n  Exp: {expected.hex()}"

    dut._log.info("test_sha3_256_empty: PASSED")


# ---------------------------------------------------------------------------
# Test: SHA-3-256("abc")
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_sha3_256_abc(dut):
    """SHA-3-256 of 'abc' must produce known hash."""
    dut._log.info("test_sha3_256_abc: start")

    clock = Clock(dut.clk, 30, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    hw_hash = await compute_hash(dut, b"abc")
    expected = bytes.fromhex(
        "3a985da74fe225b2045c172d6bd390bd"
        "855f086e3e9d525b46bfe24511431532"
    )

    dut._log.info(f"HW hash:    {hw_hash.hex()}")
    dut._log.info(f"Expected:   {expected.hex()}")

    assert hw_hash == expected, \
        f"SHA-3-256('abc') mismatch!\n  HW:  {hw_hash.hex()}\n  Exp: {expected.hex()}"

    dut._log.info("test_sha3_256_abc: PASSED")


# ---------------------------------------------------------------------------
# Test: Multi-block message (> 136 bytes before padding)
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_sha3_256_multiblock(dut):
    """SHA-3-256 of a 200-byte message (requires 2 blocks)."""
    dut._log.info("test_sha3_256_multiblock: start")

    clock = Clock(dut.clk, 30, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    msg = b"a" * 200
    hw_hash = await compute_hash(dut, msg)
    expected = sha3_256(msg)

    dut._log.info(f"HW hash:    {hw_hash.hex()}")
    dut._log.info(f"Expected:   {expected.hex()}")

    assert hw_hash == expected, \
        f"SHA-3-256('a'*200) mismatch!\n  HW:  {hw_hash.hex()}\n  Exp: {expected.hex()}"

    dut._log.info("test_sha3_256_multiblock: PASSED")


# ---------------------------------------------------------------------------
# Test: 135-byte message (0x06|0x80 = 0x86 edge case)
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_sha3_256_135bytes(dut):
    """135-byte message: padding byte is 0x86 (0x06 | 0x80), single byte."""
    dut._log.info("test_sha3_256_135bytes: start")

    clock = Clock(dut.clk, 30, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    msg = b"b" * 135
    hw_hash = await compute_hash(dut, msg)
    expected = sha3_256(msg)

    dut._log.info(f"HW hash:    {hw_hash.hex()}")
    dut._log.info(f"Expected:   {expected.hex()}")

    assert hw_hash == expected, \
        f"SHA-3-256('b'*135) mismatch!\n  HW:  {hw_hash.hex()}\n  Exp: {expected.hex()}"

    dut._log.info("test_sha3_256_135bytes: PASSED")


# ---------------------------------------------------------------------------
# Test: Back-to-back hashes
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_sha3_256_back_to_back(dut):
    """Compute two hashes in sequence to verify proper reset between hashes."""
    dut._log.info("test_sha3_256_back_to_back: start")

    clock = Clock(dut.clk, 30, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    # First hash
    hw_hash1 = await compute_hash(dut, b"first")
    expected1 = sha3_256(b"first")
    assert hw_hash1 == expected1, \
        f"First hash mismatch!\n  HW:  {hw_hash1.hex()}\n  Exp: {expected1.hex()}"
    dut._log.info("First hash correct")

    # Second hash
    hw_hash2 = await compute_hash(dut, b"second")
    expected2 = sha3_256(b"second")
    assert hw_hash2 == expected2, \
        f"Second hash mismatch!\n  HW:  {hw_hash2.hex()}\n  Exp: {expected2.hex()}"
    dut._log.info("Second hash correct")

    dut._log.info("test_sha3_256_back_to_back: PASSED")


# ---------------------------------------------------------------------------
# Test: uio_oe direction register
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_uio_oe(dut):
    """Verify uio_oe is correctly set: bits 7:4 outputs, bits 3:0 inputs."""
    dut._log.info("test_uio_oe: start")

    clock = Clock(dut.clk, 30, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    expected_oe = 0b11110000
    actual_oe = int(dut.uio_oe.value)

    assert actual_oe == expected_oe, \
        f"uio_oe mismatch: got 0x{actual_oe:02x}, expected 0x{expected_oe:02x}"

    dut._log.info("test_uio_oe: PASSED")


# ===========================================================================
# Edge-case tests — FSM robustness
# ===========================================================================

# ---------------------------------------------------------------------------
# Test: start during PERMUTE is ignored
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_start_during_permute(dut):
    """Pulsing start while permutation is running must be ignored.

    The permutation should complete normally and produce the correct hash.
    """
    dut._log.info("test_start_during_permute: start")

    clock = Clock(dut.clk, 30, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    # Start hash and absorb the padded empty-message block
    blocks = sha3_256_pad(b"")
    await start_hash(dut)
    await absorb_block(dut, blocks[0], is_last=True)

    # We're now in PERMUTE. Verify busy is asserted.
    await ClockCycles(dut.clk, 1)
    busy, _, _ = get_status(dut)
    assert busy == 1, "Expected busy=1 during permutation"

    # Pulse start mid-permute (should be ignored)
    dut.uio_in.value = 0x01  # start
    await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0x00

    # Wait for permutation to finish
    await wait_permutation(dut)

    # Verify we're in SQUEEZE with correct hash
    _, result_ready, _ = get_status(dut)
    assert result_ready == 1, "Expected result_ready after permutation"

    hw_hash = await read_hash(dut)
    expected = bytes.fromhex(
        "a7ffc6f8bf1ed76651c14756a061d662"
        "f580ff4de43b49fa82d80a4b80f8434a"
    )
    assert hw_hash == expected, \
        f"Hash corrupted by start during permute!\n  HW:  {hw_hash.hex()}\n  Exp: {expected.hex()}"

    dut._log.info("test_start_during_permute: PASSED")


# ---------------------------------------------------------------------------
# Test: start during SQUEEZE restarts cleanly
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_start_during_squeeze(dut):
    """Pulsing start while reading hash output must restart for a new hash."""
    dut._log.info("test_start_during_squeeze: start")

    clock = Clock(dut.clk, 30, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    # Complete a hash of "abc"
    blocks = sha3_256_pad(b"abc")
    await start_hash(dut)
    await absorb_block(dut, blocks[0], is_last=True)
    await wait_permutation(dut)

    # Read only 4 bytes (partial read)
    _, result_ready, _ = get_status(dut)
    assert result_ready == 1, "Expected result_ready"
    await ClockCycles(dut.clk, 1)
    _ = int(dut.uo_out.value)  # byte 0
    for _ in range(3):
        dut.uio_in.value = 0x08
        await ClockCycles(dut.clk, 1)
        dut.uio_in.value = 0x00
        await ClockCycles(dut.clk, 1)

    # Now start a new hash of "" while still in SQUEEZE
    hw_hash = await compute_hash(dut, b"")
    expected = bytes.fromhex(
        "a7ffc6f8bf1ed76651c14756a061d662"
        "f580ff4de43b49fa82d80a4b80f8434a"
    )
    assert hw_hash == expected, \
        f"Hash after squeeze restart mismatch!\n  HW:  {hw_hash.hex()}\n  Exp: {expected.hex()}"

    dut._log.info("test_start_during_squeeze: PASSED")


# ---------------------------------------------------------------------------
# Test: start during ABSORB restarts cleanly
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_start_during_absorb(dut):
    """Pulsing start mid-absorb must discard partial data and restart."""
    dut._log.info("test_start_during_absorb: start")

    clock = Clock(dut.clk, 30, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    # Start a hash, send 50 bytes of garbage
    await start_hash(dut)
    for i in range(50):
        dut.ui_in.value = 0xFF
        dut.uio_in.value = 0x02  # data_valid
        await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0x00
    dut.ui_in.value = 0

    # Verify we're still in ABSORB
    _, _, absorb_ready = get_status(dut)
    assert absorb_ready == 1, "Expected absorb_ready mid-block"

    # Now restart with start and do a proper hash of ""
    hw_hash = await compute_hash(dut, b"")
    expected = bytes.fromhex(
        "a7ffc6f8bf1ed76651c14756a061d662"
        "f580ff4de43b49fa82d80a4b80f8434a"
    )
    assert hw_hash == expected, \
        f"Hash after absorb restart mismatch!\n  HW:  {hw_hash.hex()}\n  Exp: {expected.hex()}"

    dut._log.info("test_start_during_absorb: PASSED")


# ---------------------------------------------------------------------------
# Test: spurious data_valid in IDLE is ignored
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_data_valid_during_idle(dut):
    """data_valid while in IDLE must not corrupt state for subsequent hash."""
    dut._log.info("test_data_valid_during_idle: start")

    clock = Clock(dut.clk, 30, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    # Assert data_valid with non-zero data while in IDLE
    dut.ui_in.value = 0xAB
    dut.uio_in.value = 0x02  # data_valid
    await ClockCycles(dut.clk, 5)
    dut.uio_in.value = 0x00
    dut.ui_in.value = 0

    # Now do a normal hash — should not be affected
    hw_hash = await compute_hash(dut, b"abc")
    expected = bytes.fromhex(
        "3a985da74fe225b2045c172d6bd390bd"
        "855f086e3e9d525b46bfe24511431532"
    )
    assert hw_hash == expected, \
        f"Hash corrupted by data_valid in IDLE!\n  HW:  {hw_hash.hex()}\n  Exp: {expected.hex()}"

    dut._log.info("test_data_valid_during_idle: PASSED")


# ---------------------------------------------------------------------------
# Test: spurious data_valid during PERMUTE is ignored
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_data_valid_during_permute(dut):
    """data_valid while permuting must not corrupt the state."""
    dut._log.info("test_data_valid_during_permute: start")

    clock = Clock(dut.clk, 30, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    blocks = sha3_256_pad(b"abc")
    await start_hash(dut)
    await absorb_block(dut, blocks[0], is_last=True)

    # Spam data_valid with garbage during permutation
    for _ in range(10):
        dut.ui_in.value = 0xFF
        dut.uio_in.value = 0x02  # data_valid
        await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0x00
    dut.ui_in.value = 0

    await wait_permutation(dut)

    hw_hash = await read_hash(dut)
    expected = bytes.fromhex(
        "3a985da74fe225b2045c172d6bd390bd"
        "855f086e3e9d525b46bfe24511431532"
    )
    assert hw_hash == expected, \
        f"Hash corrupted by data_valid during permute!\n  HW:  {hw_hash.hex()}\n  Exp: {expected.hex()}"

    dut._log.info("test_data_valid_during_permute: PASSED")


# ---------------------------------------------------------------------------
# Test: result_next during ABSORB is ignored
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_result_next_during_absorb(dut):
    """result_next while absorbing must not affect the hash computation."""
    dut._log.info("test_result_next_during_absorb: start")

    clock = Clock(dut.clk, 30, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    blocks = sha3_256_pad(b"abc")
    await start_hash(dut)

    # Send first 50 bytes normally
    for i in range(50):
        dut.ui_in.value = blocks[0][i]
        dut.uio_in.value = 0x02  # data_valid
        await ClockCycles(dut.clk, 1)

    # Pulse result_next mid-absorb (should be ignored)
    dut.uio_in.value = 0x08  # result_next
    await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0x00
    await ClockCycles(dut.clk, 1)

    # Send remaining 86 bytes
    for i in range(50, 136):
        dut.ui_in.value = blocks[0][i]
        uio_val = 0x02 | 0x04  # data_valid + last_block
        dut.uio_in.value = uio_val
        await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0x00
    dut.ui_in.value = 0

    await wait_permutation(dut)

    hw_hash = await read_hash(dut)
    expected = bytes.fromhex(
        "3a985da74fe225b2045c172d6bd390bd"
        "855f086e3e9d525b46bfe24511431532"
    )
    assert hw_hash == expected, \
        f"Hash corrupted by result_next during absorb!\n  HW:  {hw_hash.hex()}\n  Exp: {expected.hex()}"

    dut._log.info("test_result_next_during_absorb: PASSED")


# ---------------------------------------------------------------------------
# Test: reset during PERMUTE
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_reset_during_permute(dut):
    """Asserting reset mid-permutation must cleanly reset; next hash must work."""
    dut._log.info("test_reset_during_permute: start")

    clock = Clock(dut.clk, 30, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    blocks = sha3_256_pad(b"abc")
    await start_hash(dut)
    await absorb_block(dut, blocks[0], is_last=True)

    # Verify we're permuting
    await ClockCycles(dut.clk, 1)
    busy, _, _ = get_status(dut)
    assert busy == 1, "Expected busy during permutation"

    # Wait a few rounds, then reset
    await ClockCycles(dut.clk, 10)
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 2)

    # Verify we're back in IDLE (no status flags)
    busy, result_ready, absorb_ready = get_status(dut)
    assert busy == 0, "Expected busy=0 after reset"
    assert result_ready == 0, "Expected result_ready=0 after reset"
    assert absorb_ready == 0, "Expected absorb_ready=0 after reset"

    # Do a fresh hash — must work correctly
    hw_hash = await compute_hash(dut, b"abc")
    expected = bytes.fromhex(
        "3a985da74fe225b2045c172d6bd390bd"
        "855f086e3e9d525b46bfe24511431532"
    )
    assert hw_hash == expected, \
        f"Hash after reset-during-permute mismatch!\n  HW:  {hw_hash.hex()}\n  Exp: {expected.hex()}"

    dut._log.info("test_reset_during_permute: PASSED")


# ---------------------------------------------------------------------------
# Test: reset during SQUEEZE
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_reset_during_squeeze(dut):
    """Asserting reset while reading hash must cleanly reset; next hash must work."""
    dut._log.info("test_reset_during_squeeze: start")

    clock = Clock(dut.clk, 30, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    # Complete a hash
    blocks = sha3_256_pad(b"abc")
    await start_hash(dut)
    await absorb_block(dut, blocks[0], is_last=True)
    await wait_permutation(dut)

    # Read a few bytes
    _, result_ready, _ = get_status(dut)
    assert result_ready == 1, "Expected result_ready"
    await ClockCycles(dut.clk, 1)
    _ = int(dut.uo_out.value)
    dut.uio_in.value = 0x08
    await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0x00

    # Reset mid-squeeze
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 2)

    # Verify IDLE state
    busy, result_ready, absorb_ready = get_status(dut)
    assert busy == 0 and result_ready == 0 and absorb_ready == 0, \
        "Expected IDLE state after reset"

    # Fresh hash must work
    hw_hash = await compute_hash(dut, b"")
    expected = bytes.fromhex(
        "a7ffc6f8bf1ed76651c14756a061d662"
        "f580ff4de43b49fa82d80a4b80f8434a"
    )
    assert hw_hash == expected, \
        f"Hash after reset-during-squeeze mismatch!\n  HW:  {hw_hash.hex()}\n  Exp: {expected.hex()}"

    dut._log.info("test_reset_during_squeeze: PASSED")


# ---------------------------------------------------------------------------
# Test: simultaneous start + data_valid during ABSORB (start wins)
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_simultaneous_start_data_valid(dut):
    """When start and data_valid are both asserted in ABSORB, start must win."""
    dut._log.info("test_simultaneous_start_data_valid: start")

    clock = Clock(dut.clk, 30, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    # Start a hash, send some garbage bytes
    await start_hash(dut)
    for i in range(20):
        dut.ui_in.value = 0xDE
        dut.uio_in.value = 0x02  # data_valid
        await ClockCycles(dut.clk, 1)

    # Assert start + data_valid simultaneously (start should take priority)
    dut.ui_in.value = 0xAD
    dut.uio_in.value = 0x03  # start(0x01) | data_valid(0x02)
    await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0x00
    dut.ui_in.value = 0
    await ClockCycles(dut.clk, 1)

    # State should now be cleared. A fresh hash of "" should be correct.
    # (compute_hash calls start_hash internally, which will re-clear)
    # Instead, manually feed the padded empty block to verify state was cleared.
    blocks = sha3_256_pad(b"")
    await absorb_block(dut, blocks[0], is_last=True)
    await wait_permutation(dut)
    hw_hash = await read_hash(dut)

    expected = bytes.fromhex(
        "a7ffc6f8bf1ed76651c14756a061d662"
        "f580ff4de43b49fa82d80a4b80f8434a"
    )
    assert hw_hash == expected, \
        f"State not cleared when start+data_valid simultaneous!\n  HW:  {hw_hash.hex()}\n  Exp: {expected.hex()}"

    dut._log.info("test_simultaneous_start_data_valid: PASSED")


# ---------------------------------------------------------------------------
# Test: status signals have correct timing throughout FSM
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_status_signal_timing(dut):
    """Verify busy/result_ready/absorb_ready transition at the correct times."""
    dut._log.info("test_status_signal_timing: start")

    clock = Clock(dut.clk, 30, unit="ns")
    cocotb.start_soon(clock.start())
    await reset_dut(dut)

    # IDLE: all status low
    busy, result_ready, absorb_ready = get_status(dut)
    assert (busy, result_ready, absorb_ready) == (0, 0, 0), \
        f"IDLE status wrong: busy={busy} rr={result_ready} ar={absorb_ready}"

    # Start -> ABSORB: absorb_ready should go high
    dut.uio_in.value = 0x01
    await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0x00
    await ClockCycles(dut.clk, 1)
    busy, result_ready, absorb_ready = get_status(dut)
    assert (busy, result_ready, absorb_ready) == (0, 0, 1), \
        f"ABSORB status wrong: busy={busy} rr={result_ready} ar={absorb_ready}"

    # Absorb a full block to trigger PERMUTE
    blocks = sha3_256_pad(b"")
    await absorb_block(dut, blocks[0], is_last=True)

    # Should now be in PERMUTE: busy high
    await ClockCycles(dut.clk, 1)
    busy, result_ready, absorb_ready = get_status(dut)
    assert (busy, result_ready, absorb_ready) == (1, 0, 0), \
        f"PERMUTE status wrong: busy={busy} rr={result_ready} ar={absorb_ready}"

    # Wait for permutation to complete
    await wait_permutation(dut)

    # SQUEEZE: result_ready high
    busy, result_ready, absorb_ready = get_status(dut)
    assert (busy, result_ready, absorb_ready) == (0, 1, 0), \
        f"SQUEEZE status wrong: busy={busy} rr={result_ready} ar={absorb_ready}"

    # Read all 32 bytes — FSM stays in SQUEEZE with byte_counter=31
    # (requires one more result_next or start to leave SQUEEZE)
    _ = await read_hash(dut)
    busy, result_ready, absorb_ready = get_status(dut)
    assert (busy, result_ready, absorb_ready) == (0, 1, 0), \
        f"Post-read SQUEEZE status wrong: busy={busy} rr={result_ready} ar={absorb_ready}"

    # One more result_next pulse transitions to IDLE
    dut.uio_in.value = 0x08  # result_next
    await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0x00
    await ClockCycles(dut.clk, 1)
    busy, result_ready, absorb_ready = get_status(dut)
    assert (busy, result_ready, absorb_ready) == (0, 0, 0), \
        f"Post-SQUEEZE IDLE status wrong: busy={busy} rr={result_ready} ar={absorb_ready}"

    dut._log.info("test_status_signal_timing: PASSED")
