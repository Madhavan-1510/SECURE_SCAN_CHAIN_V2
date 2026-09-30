// ============================================================================
// scan_attack_harness.v
//
// Closes Gap 3 from secure1.md: a real scan attack normally needs JTAG/ATE
// equipment a PYNQ-Z2 bring-up doesn't have. tb_scan_attack.v's "attacker"
// is pure testbench logic and cannot be dropped on the board. This module
// is the same attack procedure, ported into synthesizable RTL, so it can be
// triggered from a button and read from LEDs/switches on real hardware --
// this is a standard, legitimate FPGA-security-demo substitute for ATE.
//
// It replaces the CPU entirely (like every scan-related testbench in this
// project does) and drives aes_pcpi's PCPI port directly with a small FSM
// that reproduces, cycle-for-cycle, the same procedure as tb_scan_attack.v:
//
//   LOADKEY x4 (fixed KAT key)  ->  LOADBLOCK x4 (fixed KAT plaintext)
//   ->  issue ENCRYPT, freeze after FREEZE_CYCLES  ->  assert scan_en,
//   capture 1 pre-shift sample + (SCAN_WIDTH-1) post-edge samples
//   ->  hold the 645-bit result for readback
//
// Readback: sel_byte selects which of the 81 bytes (645 bits, top byte
// partial) of the captured stream drives led_out -- exactly the "switches
// pick a byte, LEDs show it" pattern used in FPGA security demos without
// a UART. Board wiring (not simulated here): btn_start/sw_unlock/sel_byte
// to physical buttons/switches, led_out/led_done/led_locked to LEDs.
//
// This module intentionally reuses the exact same fixed NIST KAT key and
// plaintext as the rest of the project's regression suite, so its captured
// output is directly comparable to tb_scan_attack.v / tb_scan_lock.v: with
// sw_unlock=0 (locked, fail-safe default) the captured stream must be all
// zero; with sw_unlock=1 (after a correct unlock) captured[644:517] must
// equal the KAT key -- exactly reproducing the simulated result, now from
// synthesizable hardware.
// ============================================================================
`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"

module scan_attack_harness #(
    parameter integer SCAN_WIDTH    = 645,
    parameter integer FREEZE_CYCLES = 6,
    parameter [31:0]  UNLOCK_CODE   = 32'hDEC0DED1
) (
    input  wire        clk,
    input  wire        resetn,
    input  wire        lock_resetn,

    input  wire        btn_start,     // 1-cycle-debounced pulse: begin attack run
    input  wire        sw_unlock,     // level: 1 = present correct unlock code first

    input  wire [6:0]  sel_byte,      // which byte (0..80) of the 645-bit
                                       // capture to show on led_out
    output wire [7:0]  led_out,
    output wire        led_done,
    output wire        led_locked
);

    // ------------------------------------------------------------------
    // DUT: the coprocessor itself, driven exactly like every scan-attack
    // testbench in this project drives it -- direct PCPI stimulus, no CPU.
    // ------------------------------------------------------------------
    reg         pcpi_valid_r;
    reg  [31:0] pcpi_insn_r, pcpi_rs1_r, pcpi_rs2_r;
    wire        pcpi_wr, pcpi_wait, pcpi_ready;
    wire [31:0] pcpi_rd;

    reg         scan_en_r, scan_in_r;
    wire        scan_out;

    wire        locked;
    reg         unlock_valid_r;
    reg  [31:0] unlock_code_r;
    reg         relock_r;

    assign led_locked = locked;

    scan_lock_controller #(.UNLOCK_CODE(UNLOCK_CODE)) u_lock (
        .clk(clk), .resetn(lock_resetn),
        .unlock_valid(unlock_valid_r), .unlock_code_i(unlock_code_r),
        .relock(relock_r), .locked(locked)
    );

    aes_pcpi u_dut (
        .clk(clk), .resetn(resetn),
        .pcpi_valid(pcpi_valid_r), .pcpi_insn(pcpi_insn_r),
        .pcpi_rs1(pcpi_rs1_r), .pcpi_rs2(pcpi_rs2_r),
        .pcpi_wr(pcpi_wr), .pcpi_rd(pcpi_rd),
        .pcpi_wait(pcpi_wait), .pcpi_ready(pcpi_ready),
        .dbg_key_stage(), .dbg_block_stage(),
        .dbg_core_key_reg(), .dbg_core_round_key_reg(),
        .dbg_core_state_reg(), .dbg_core_round_reg(),
        .scan_en(scan_en_r), .scan_in(scan_in_r), .scan_out(scan_out),
        .locked(locked)
    );

    function [31:0] mk_insn(input [2:0] f3);
        mk_insn = {7'b0, 5'b0, 5'b0, f3, 5'b0, `AES_OPCODE};
    endfunction

    // Fixed NIST AES-128 KAT, same as the rest of the project's suite --
    // this is a demo/attack harness, not a general-purpose loader.
    localparam [127:0] KEY       = 128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] PLAINTEXT = 128'h00112233445566778899AABBCCDDEEFF;

    function [31:0] key_word(input [1:0] idx);
        case (idx)
            2'd0: key_word = KEY[127:96];
            2'd1: key_word = KEY[95:64];
            2'd2: key_word = KEY[63:32];
            default: key_word = KEY[31:0];
        endcase
    endfunction

    function [31:0] pt_word(input [1:0] idx);
        case (idx)
            2'd0: pt_word = PLAINTEXT[127:96];
            2'd1: pt_word = PLAINTEXT[95:64];
            2'd2: pt_word = PLAINTEXT[63:32];
            default: pt_word = PLAINTEXT[31:0];
        endcase
    endfunction

    // ------------------------------------------------------------------
    // Attack FSM -- mirrors tb_scan_attack.v's procedure step for step,
    // but as a real clocked state machine instead of a testbench task.
    // ------------------------------------------------------------------
    localparam S_IDLE       = 4'd0;
    localparam S_UNLOCK     = 4'd1;
    localparam S_LOADKEY    = 4'd2;
    localparam S_LOADBLOCK  = 4'd3;
    localparam S_ENCRYPT    = 4'd4;
    localparam S_FREEZE     = 4'd5;
    localparam S_SCAN_PRE   = 4'd6;
    localparam S_SCAN_SHIFT = 4'd7;
    localparam S_DONE       = 4'd8;

    reg [3:0]  state;
    reg [1:0]  word_idx;
    reg [15:0] freeze_cnt;
    reg [15:0] shift_cnt;

    reg [SCAN_WIDTH-1:0] captured;
    reg                  done_r;

    assign led_done = done_r;

    always @(posedge clk) begin
        pcpi_valid_r   <= 1'b0;
        unlock_valid_r <= 1'b0;
        relock_r       <= 1'b0;

        if (!resetn) begin
            state      <= S_IDLE;
            word_idx   <= 2'd0;
            freeze_cnt <= 16'd0;
            shift_cnt  <= 16'd0;
            scan_en_r  <= 1'b0;
            scan_in_r  <= 1'b0;
            done_r     <= 1'b0;
            captured   <= {SCAN_WIDTH{1'b0}};
        end else begin
            case (state)
                S_IDLE: begin
                    done_r <= 1'b0;
                    if (btn_start) begin
                        word_idx <= 2'd0;
                        if (sw_unlock) begin
                            unlock_code_r  <= UNLOCK_CODE;
                            unlock_valid_r <= 1'b1;
                            state          <= S_UNLOCK;
                        end else begin
                            relock_r <= 1'b1;   // stay/return to fail-safe locked
                            state    <= S_LOADKEY;
                        end
                    end
                end

                S_UNLOCK: begin
                    state <= S_LOADKEY; // unlock_valid pulse already issued
                end

                S_LOADKEY: begin
                    pcpi_valid_r <= 1'b1;
                    pcpi_insn_r  <= mk_insn(`AES_F3_LOADKEY);
                    pcpi_rs1_r   <= {30'b0, word_idx};
                    pcpi_rs2_r   <= key_word(word_idx);
                    if (pcpi_ready) begin
                        if (word_idx == 2'd3) begin
                            word_idx <= 2'd0;
                            state    <= S_LOADBLOCK;
                        end else begin
                            word_idx <= word_idx + 2'd1;
                        end
                    end
                end

                S_LOADBLOCK: begin
                    pcpi_valid_r <= 1'b1;
                    pcpi_insn_r  <= mk_insn(`AES_F3_LOADBLOCK);
                    pcpi_rs1_r   <= {30'b0, word_idx};
                    pcpi_rs2_r   <= pt_word(word_idx);
                    if (pcpi_ready) begin
                        if (word_idx == 2'd3) begin
                            state <= S_ENCRYPT;
                        end else begin
                            word_idx <= word_idx + 2'd1;
                        end
                    end
                end

                S_ENCRYPT: begin
                    // One-cycle ENCRYPT pulse is sufficient to latch
                    // aes_pcpi's ST_IDLE->ST_BUSY transition (see
                    // aes_pcpi.v's start_encrypt condition) -- the attacker
                    // does not wait for completion, exactly like
                    // tb_scan_attack.v.
                    pcpi_valid_r <= 1'b1;
                    pcpi_insn_r  <= mk_insn(`AES_F3_ENCRYPT);
                    pcpi_rs1_r   <= 32'h0;
                    pcpi_rs2_r   <= 32'h0;
                    freeze_cnt   <= 16'd0;
                    state        <= S_FREEZE;
                end

                S_FREEZE: begin
                    // pcpi_valid_r already deasserted (default at top of
                    // block) -- computation runs freely in the background
                    // while we count freeze cycles, same as the testbench.
                    if (freeze_cnt == FREEZE_CYCLES - 1) begin
                        scan_en_r <= 1'b1;
                        scan_in_r <= 1'b0;
                        state     <= S_SCAN_PRE;
                    end else begin
                        freeze_cnt <= freeze_cnt + 16'd1;
                    end
                end

                // Pre-shift sample: scan_out is combinational on the
                // current last cell, visible before the first scan clock
                // edge (authoritative rule, tb_scan_chain.v Check 3 /
                // tb_scan_attack.v Step 7). Captured on the cycle scan_en
                // is first seen high, before any shift has occurred.
                S_SCAN_PRE: begin
                    captured[SCAN_WIDTH-1] <= scan_out;
                    shift_cnt <= 16'd0;
                    state     <= S_SCAN_SHIFT;
                end

                S_SCAN_SHIFT: begin
                    captured[SCAN_WIDTH-2-shift_cnt] <= scan_out;
                    if (shift_cnt == SCAN_WIDTH - 2) begin
                        scan_en_r <= 1'b0;
                        done_r    <= 1'b1;
                        state     <= S_DONE;
                    end else begin
                        shift_cnt <= shift_cnt + 16'd1;
                    end
                end

                S_DONE: begin
                    done_r <= 1'b1;
                    if (btn_start) begin
                        done_r <= 1'b0;
                        word_idx <= 2'd0;
                        if (sw_unlock) begin
                            unlock_code_r  <= UNLOCK_CODE;
                            unlock_valid_r <= 1'b1;
                            state          <= S_UNLOCK;
                        end else begin
                            relock_r <= 1'b1;
                            state    <= S_LOADKEY;
                        end
                    end
                end

                default: state <= S_IDLE;
            endcase
        end
    end

    // ------------------------------------------------------------------
    // Byte-select readback mux: sel_byte in [0,80], byte 80 is a single
    // partial bit (645 = 80*8 + 5), padded with zeros in the top 3 bits.
    // ------------------------------------------------------------------
    reg [7:0] led_out_r;
    always @* begin
        if (sel_byte == 7'd80)
            led_out_r = {3'b0, captured[SCAN_WIDTH-1 -: 5]};
        else
            led_out_r = captured[(SCAN_WIDTH-1 - sel_byte*8) -: 8];
    end
    assign led_out = led_out_r;

endmodule