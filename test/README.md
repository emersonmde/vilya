# Vilya Test Suite

17 cocotb tests verify SHA-3-256 correctness and FSM edge-case behavior via Icarus Verilog simulation.

## Running tests

```sh
make
```

Run a single test:

```sh
make TESTCASE=test_sha3_256_abc
```

## Gate-level simulation

After hardening, copy the gate-level netlist to `gate_level_netlist.v`, then:

```sh
make -B GATES=yes
```

## Viewing waveforms

Tests produce `tb.fst` (FST format). Open with:

```sh
surfer tb.fst
```

To generate VCD format instead, edit `tb.v` to use `$dumpfile("tb.vcd");` and run:

```sh
make -B FST=
```
