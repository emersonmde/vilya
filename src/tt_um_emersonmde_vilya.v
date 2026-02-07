/*
 * Copyright (c) 2026 Matthew Emerson
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vilya: SHA-3-256 hardware accelerator
 * Top-level TT wrapper — pin mapping only
 */

`default_nettype none

module tt_um_emersonmde_vilya (
    input  wire [7:0] ui_in,    // Dedicated inputs — data byte
    output wire [7:0] uo_out,   // Dedicated outputs — hash result byte
    input  wire [7:0] uio_in,   // IOs: Input path
    output wire [7:0] uio_out,  // IOs: Output path
    output wire [7:0] uio_oe,   // IOs: Enable path (active high: 0=input, 1=output)
    input  wire       ena,      // always 1 when the design is powered
    input  wire       clk,      // clock
    input  wire       rst_n     // reset_n - low to reset
);

    // uio bit assignments:
    //   [0] start        (input)  — begin new hash
    //   [1] data_valid   (input)  — latch input byte
    //   [2] last_block   (input)  — current block is final padded block
    //   [3] result_next  (input)  — advance to next output byte
    //   [4] busy         (output) — permutation running
    //   [5] result_ready (output) — hash available
    //   [6] absorb_ready (output) — ready for next byte
    //   [7] (reserved)   (output) — tied low

    // Bits 7:4 are outputs, bits 3:0 are inputs
    assign uio_oe = 8'b1111_0000;

    // Control signal extraction
    wire start       = uio_in[0];
    wire data_valid  = uio_in[1];
    wire last_block  = uio_in[2];
    wire result_next = uio_in[3];

    // Status signals from controller
    wire busy;
    wire result_ready;
    wire absorb_ready;

    assign uio_out[4] = busy;
    assign uio_out[5] = result_ready;
    assign uio_out[6] = absorb_ready;
    assign uio_out[7] = 1'b0;
    assign uio_out[3:0] = 4'b0000;

    sha3_controller controller (
        .clk          (clk),
        .rst_n        (rst_n),
        .start        (start),
        .data_valid   (data_valid),
        .last_block   (last_block),
        .result_next  (result_next),
        .data_in      (ui_in),
        .data_out     (uo_out),
        .busy         (busy),
        .result_ready (result_ready),
        .absorb_ready (absorb_ready)
    );

    // Suppress unused input warnings
    wire _unused = &{ena, uio_in[7:4], 1'b0};

endmodule
