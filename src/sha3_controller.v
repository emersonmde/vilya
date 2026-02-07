/*
 * Copyright (c) 2026 Matthew Emerson
 * SPDX-License-Identifier: Apache-2.0
 *
 * SHA-3-256 sponge controller
 * FSM, 1600-bit state register, byte I/O
 */

`default_nettype none

module sha3_controller (
    input  wire       clk,
    input  wire       rst_n,
    input  wire       start,
    input  wire       data_valid,
    input  wire       last_block,
    input  wire       result_next,
    input  wire [7:0] data_in,
    output wire [7:0] data_out,
    output wire       busy,
    output wire       result_ready,
    output wire       absorb_ready
);

    // FSM states
    localparam STATE_IDLE    = 2'd0;
    localparam STATE_ABSORB  = 2'd1;
    localparam STATE_PERMUTE = 2'd2;
    localparam STATE_SQUEEZE = 2'd3;

    reg [1:0] state;

    // 1600-bit Keccak state
    reg [1599:0] keccak_state;

    // Byte counter for absorb (0..135) and squeeze (0..31)
    reg [7:0] byte_counter;

    // Round counter for Keccak-f permutation (0..23)
    reg [4:0] round_counter;

    // Latch for last_block flag
    reg last_block_flag;

    // Keccak round combinational logic
    wire [1599:0] round_state_out;

    keccak_round round_inst (
        .state_in  (keccak_state),
        .round_num (round_counter),
        .state_out (round_state_out)
    );

    // Output mux: read byte from state during squeeze
    // Output bytes 0..31 map to state[N*8 +: 8] (first 4 lanes of row 0)
    reg [7:0] data_out_reg;
    assign data_out = data_out_reg;

    // Status outputs
    assign busy         = (state == STATE_PERMUTE);
    assign result_ready = (state == STATE_SQUEEZE);
    assign absorb_ready = (state == STATE_ABSORB);

    // Output byte mux — select from state based on byte_counter
    // Only used during SQUEEZE, reading bytes 0..31
    always @(*) begin
        case (byte_counter)
             0: data_out_reg = keccak_state[  0 +: 8];
             1: data_out_reg = keccak_state[  8 +: 8];
             2: data_out_reg = keccak_state[ 16 +: 8];
             3: data_out_reg = keccak_state[ 24 +: 8];
             4: data_out_reg = keccak_state[ 32 +: 8];
             5: data_out_reg = keccak_state[ 40 +: 8];
             6: data_out_reg = keccak_state[ 48 +: 8];
             7: data_out_reg = keccak_state[ 56 +: 8];
             8: data_out_reg = keccak_state[ 64 +: 8];
             9: data_out_reg = keccak_state[ 72 +: 8];
            10: data_out_reg = keccak_state[ 80 +: 8];
            11: data_out_reg = keccak_state[ 88 +: 8];
            12: data_out_reg = keccak_state[ 96 +: 8];
            13: data_out_reg = keccak_state[104 +: 8];
            14: data_out_reg = keccak_state[112 +: 8];
            15: data_out_reg = keccak_state[120 +: 8];
            16: data_out_reg = keccak_state[128 +: 8];
            17: data_out_reg = keccak_state[136 +: 8];
            18: data_out_reg = keccak_state[144 +: 8];
            19: data_out_reg = keccak_state[152 +: 8];
            20: data_out_reg = keccak_state[160 +: 8];
            21: data_out_reg = keccak_state[168 +: 8];
            22: data_out_reg = keccak_state[176 +: 8];
            23: data_out_reg = keccak_state[184 +: 8];
            24: data_out_reg = keccak_state[192 +: 8];
            25: data_out_reg = keccak_state[200 +: 8];
            26: data_out_reg = keccak_state[208 +: 8];
            27: data_out_reg = keccak_state[216 +: 8];
            28: data_out_reg = keccak_state[224 +: 8];
            29: data_out_reg = keccak_state[232 +: 8];
            30: data_out_reg = keccak_state[240 +: 8];
            31: data_out_reg = keccak_state[248 +: 8];
            default: data_out_reg = 8'h00;
        endcase
    end

    // FSM and state register
    integer i;
    always @(posedge clk) begin
        if (!rst_n) begin
            state          <= STATE_IDLE;
            keccak_state   <= 1600'b0;
            byte_counter   <= 8'd0;
            round_counter  <= 5'd0;
            last_block_flag <= 1'b0;
        end else begin
            case (state)
                STATE_IDLE: begin
                    if (start) begin
                        keccak_state   <= 1600'b0;
                        byte_counter   <= 8'd0;
                        round_counter  <= 5'd0;
                        last_block_flag <= 1'b0;
                        state          <= STATE_ABSORB;
                    end
                end

                STATE_ABSORB: begin
                    if (start) begin
                        // Restart: clear state and go back to absorb
                        keccak_state   <= 1600'b0;
                        byte_counter   <= 8'd0;
                        round_counter  <= 5'd0;
                        last_block_flag <= 1'b0;
                    end else if (data_valid) begin
                        // XOR incoming byte into the correct position
                        for (i = 0; i < 136; i = i + 1) begin
                            if (byte_counter == i[7:0]) begin
                                keccak_state[i*8 +: 8] <= keccak_state[i*8 +: 8] ^ data_in;
                            end
                        end

                        // Latch last_block when seen
                        if (last_block)
                            last_block_flag <= 1'b1;

                        if (byte_counter == 8'd135) begin
                            // Block complete, start permutation
                            byte_counter  <= 8'd0;
                            round_counter <= 5'd0;
                            state         <= STATE_PERMUTE;
                        end else begin
                            byte_counter <= byte_counter + 8'd1;
                        end
                    end
                end

                STATE_PERMUTE: begin
                    keccak_state <= round_state_out;
                    if (round_counter == 5'd23) begin
                        round_counter <= 5'd0;
                        if (last_block_flag) begin
                            byte_counter <= 8'd0;
                            state        <= STATE_SQUEEZE;
                        end else begin
                            byte_counter <= 8'd0;
                            state        <= STATE_ABSORB;
                        end
                    end else begin
                        round_counter <= round_counter + 5'd1;
                    end
                end

                STATE_SQUEEZE: begin
                    if (start) begin
                        keccak_state   <= 1600'b0;
                        byte_counter   <= 8'd0;
                        round_counter  <= 5'd0;
                        last_block_flag <= 1'b0;
                        state          <= STATE_ABSORB;
                    end else if (result_next) begin
                        if (byte_counter == 8'd31) begin
                            state <= STATE_IDLE;
                        end else begin
                            byte_counter <= byte_counter + 8'd1;
                        end
                    end
                end

                default: state <= STATE_IDLE;
            endcase
        end
    end

endmodule
