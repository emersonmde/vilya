## How it works

Vilya is a SHA-3-256 hardware accelerator. It implements the full Keccak-f[1600] permutation in combinational logic, completing one round per clock cycle (24 cycles per permutation). The host sends pre-padded 136-byte message blocks over an 8-bit byte interface, and reads back the 32-byte digest.

**Architecture:**

- `sha3_controller` — sponge FSM with 1600-bit state register, byte-level XOR absorption, and output multiplexing
- `keccak_round` — purely combinational single-round Keccak-f[1600] (theta, rho, pi, chi, iota)
- `keccak_rc` — 24-entry round constant lookup table

**State machine:** IDLE → ABSORB (136 bytes) → PERMUTE (24 cycles) → ABSORB/SQUEEZE

The host is responsible for SHA-3 padding (pad10*1 with domain suffix 0x06). Each input byte is XORed directly into the corresponding position of the 1600-bit state register during absorption, eliminating the need for a separate input buffer.

## How to test

### Pin interface

| Pin | Signal | Direction | Description |
|-----|--------|-----------|-------------|
| `ui_in[7:0]` | data_in | IN | Input data byte |
| `uo_out[7:0]` | data_out | OUT | Output hash byte |
| `uio[0]` | start | IN | Begin new hash (clears state) |
| `uio[1]` | data_valid | IN | Latch input byte |
| `uio[2]` | last_block | IN | Current block is the final padded block |
| `uio[3]` | result_next | IN | Advance to next output byte |
| `uio[4]` | busy | OUT | Keccak-f permutation running |
| `uio[5]` | result_ready | OUT | Hash digest available for reading |
| `uio[6]` | absorb_ready | OUT | Ready to accept next input byte |
| `uio[7]` | (reserved) | OUT | Tied low |

### Protocol

1. **Start:** Pulse `start` for one clock cycle. This clears internal state and enters ABSORB mode.
2. **Absorb:** For each byte of the pre-padded block, place the byte on `data_in` and assert `data_valid`. For the final block, also assert `last_block`. Send exactly 136 bytes per block at one byte per cycle.
3. **Wait:** After 136 bytes, the permutation runs for 24 cycles. Poll `busy` or simply wait.
4. **Repeat:** If not the last block, return to step 2 for the next block.
5. **Read:** When `result_ready` is asserted, the first digest byte is on `data_out`. Pulse `result_next` to advance through all 32 bytes.

### SHA-3 padding (host-side)

Append `0x06` to the message, then zero-pad to a multiple of 136 bytes, and set bit 7 of the last byte (`last_byte |= 0x80`). For an empty message, the single padded block is: `0x06, 0x00 * 134, 0x80`.

### Test vector

SHA-3-256("") = `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a`

## External hardware

Any microcontroller or FPGA with 8 GPIO pins for data and 8 GPIO pins for control/status. A serial-to-parallel adapter (e.g., FTDI) can also be used for host communication.
