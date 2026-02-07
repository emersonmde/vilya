# Vilya — SHA-3-256 Hardware Accelerator

## Project Overview

SHA-3-256 hardware accelerator targeting Tiny Tapeout IHP 26a shuttle.
Pre-padded 136-byte message blocks absorbed via 8-bit byte interface,
Keccak-f[1600] computed in 24 clock cycles, 32-byte digest output.

## Architecture

```
tt_um_emersonmde_vilya       (TT wrapper — pin mapping only)
  └── sha3_controller        (sponge FSM, 1600-bit state, byte I/O)
        └── keccak_round     (combinational: one Keccak-f round)
              └── keccak_rc  (combinational: round constant lookup)
```

## Conventions

- **Verilog-2001** — no SystemVerilog constructs
- **`default_nettype none** in all modules
- **FIPS 202 byte order**: lane A[x][y] = state[(5*y+x)*64 +: 64], little-endian bytes within lanes
- State register lives in `sha3_controller`, not `keccak_round`
- `keccak_round` is purely combinational

## Running Tests

```bash
cd test && make
```

Requires: `iverilog`, `cocotb`, `pytest`

## Pin Interface

- `ui_in[7:0]`  — data input byte
- `uo_out[7:0]` — hash output byte
- `uio_in[0]`   — start (begin new hash)
- `uio_in[1]`   — data_valid (latch input byte)
- `uio_in[2]`   — last_block (final padded block)
- `uio_in[3]`   — result_next (advance output byte)
- `uio_out[4]`  — busy (permutation running)
- `uio_out[5]`  — result_ready (hash available)
- `uio_out[6]`  — absorb_ready (ready for next byte)

## Key Test Vectors

- SHA-3-256("") = `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a`
- SHA-3-256("abc") = `3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532`
