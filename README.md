![](../../workflows/gds/badge.svg) ![](../../workflows/docs/badge.svg) ![](../../workflows/test/badge.svg) ![](../../workflows/fpga/badge.svg)

# Vilya: SHA-3-256 Hardware Accelerator

A SHA-3-256 hardware accelerator targeting [Tiny Tapeout](https://tinytapeout.com) IHP 26a (2x2 tiles, IHP SG13G2 130nm). Implements the full Keccak-f[1600] permutation in combinational logic, completing one round per clock cycle (24 cycles per permutation). The host sends pre-padded 136-byte message blocks over an 8-bit byte interface and reads back the 32-byte digest.

See [docs/info.md](docs/info.md) for the full pin interface, protocol, and test vectors.

## Architecture

```
tt_um_emersonmde_vilya       TT wrapper (pin mapping only)
  └── sha3_controller        Sponge FSM, 1600-bit state register, byte I/O
        └── keccak_round     Combinational: theta, rho, pi, chi, iota
              └── keccak_rc  24-entry round constant lookup
```

**State machine:** IDLE → ABSORB (136 bytes) → PERMUTE (24 cycles) → ABSORB or SQUEEZE

## Running Tests

```sh
cd test && make
```

Requires: [Icarus Verilog](https://github.com/steveicarus/iverilog), [cocotb](https://docs.cocotb.org/en/stable/), pytest

17 tests cover functional correctness (empty message, "abc", multi-block, 135-byte edge case, back-to-back hashes) and edge cases (start/reset/spurious signals in every FSM state).

## Viewing Waveforms

After running tests, open the signal trace:

```sh
surfer test/tb.fst
```

## Resources

- [Tiny Tapeout FAQ](https://tinytapeout.com/faq/)
- [FIPS 202 — SHA-3 Standard](https://csrc.nist.gov/publications/detail/fips/202/final)
- [Build your design locally](https://www.tinytapeout.com/guides/local-hardening/)
