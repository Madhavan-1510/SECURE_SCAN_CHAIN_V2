// ============================================================================
// aes_pcpi.v  (Phase 6: scan-retrofitted)
//
// Purpose: PicoRV32 PCPI-compliant wrapper around aes_core.v (see original
// header for the full PCPI timing contract -- unchanged in Phase 6).
//
// PHASE 6 CHANGE SUMMARY:
//   key_stage, block_stage, fsm_state are no longer plain `reg`; each is now
//   a `scan_chain` instance. start_i_reg is INTENTIONALLY LEFT PLAIN -- it
//   is a one-cycle pulse control signal, not part of the Phase 6
//   scan-conversion list, and holds no secret.
//
//   This module's 3 scanned registers sit at the FRONT of the coprocessor
//   scan segment (closest to the overall SCAN_IN), then chain directly into
//   the instantiated aes_core's 4-register segment, whose scan_out becomes
//   this module's (and the whole coprocessor's) scan_out. See
//   docs/scan_map.md for the full 645-bit offset table.
//
//   Functional behavior with scan_en=0 is required to be bit-for-bit
//   identical to Phase 2/3/4 -- see tb_aes_pcpi.v regression.
// ============================================================================
`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"

// See aes_core_def.v for the DEFENSE_LEVEL table (1=G1, 2=G2, 3=G3, 4=G4, 5=G2R).
module aes_pcpi_def #(
    parameter integer DEFENSE_LEVEL = 4
) (
    input  wire        clk,
    input  wire        resetn,

    // PicoRV32 PCPI port (connect directly to picorv32's pcpi_* ports)
    input  wire        pcpi_valid,
    input  wire [31:0] pcpi_insn,
    input  wire [31:0] pcpi_rs1,
    input  wire [31:0] pcpi_rs2,
    output wire        pcpi_wr,
    output wire [31:0] pcpi_rd,
    output wire        pcpi_wait,
    output wire        pcpi_ready,

    // Scan-map visibility only (see docs/scan_map.md) -- not part of the
    // PCPI datapath.
    output wire [127:0] dbg_key_stage,
    output wire [127:0] dbg_block_stage,
    output wire [127:0] dbg_core_key_reg,
    output wire [127:0] dbg_core_round_key_reg,
    output wire [127:0] dbg_core_state_reg,
    output wire [3:0]   dbg_core_round_reg,

    // Phase 6: coprocessor scan segment (whole-coprocessor scan_in/scan_out).
    input  wire        scan_en,
    input  wire        scan_in,
    output wire        scan_out,

    // Phase 8: pass-through to aes_core's sensitive-segment lock. This
    // module makes no decisions about locking policy -- see
    // scan_lock_controller.v for the (deliberately simple) unlock gate,
    // kept separate per secure.md Sec.31 ("separate authorization/lock
    // control from scan data protection").
    input  wire        locked
);

    localparam ST_IDLE = 1'b0;
    localparam ST_BUSY = 1'b1;

    // Scanned registers: *_q = current value, *_d = combinational next value
    wire [127:0] key_stage_q, block_stage_q;
    wire         fsm_state_q;

    reg         start_i_reg;    // plain, non-scanned pulse register

    // ---------------------------------------------------------------
    // Bug fix (post-Phase-9 resume investigation, see tb_scan_resume.v /
    // tb_double_encrypt_control.v): aes_core.done_o is a LEVEL, sticky
    // from the previous operation until the next start_i is processed
    // by aes_core's own (one-cycle-delayed) registered FSM. On the very
    // first cycle this module is in ST_BUSY for a NEW operation,
    // aes_core has not yet reacted to the fresh start_i pulse (that
    // happens on aes_core's NEXT posedge), so a stale done_o==1 left
    // over from the PRIOR completed operation is combinationally
    // visible and was being misread as "this operation is already
    // done" -- firing pcpi_ready one cycle too early, before the new
    // computation has even started. This reproduces with scan_en tied
    // permanently low (tb_double_encrypt_control.v), proving it is a
    // pre-existing PCPI/core handshake race, NOT a scan-corruption
    // issue. core_seen_running is cleared the instant a new ENCRYPT is
    // accepted and only set once aes_core.busy_o (fsm_state==RUNNING)
    // has actually been observed for THIS session, so a stale done_o
    // can no longer be mistaken for the new session's completion.
    // ---------------------------------------------------------------
    reg         core_seen_running;

    wire        core_busy, core_done;
    wire [127:0] ciphertext;

    wire is_aes_opcode = (pcpi_insn[6:0] == `AES_OPCODE);
    wire [2:0] funct3  = pcpi_insn[14:12];
    wire [1:0] word_idx = pcpi_rs1[1:0];

    // ---------------------------------------------------------------
    // Combinational decode + PCPI response (reads fsm_state_q)
    // ---------------------------------------------------------------
    reg        pcpi_wr_r;
    reg [31:0] pcpi_rd_r;
    reg        pcpi_wait_r;
    reg        pcpi_ready_r;

    always @* begin
        pcpi_wr_r    = 1'b0;
        pcpi_rd_r    = 32'h0;
        pcpi_wait_r  = 1'b0;
        pcpi_ready_r = 1'b0;

        if (is_aes_opcode) begin
            case (fsm_state_q)
                ST_IDLE: begin
                    if (pcpi_valid) begin
                        case (funct3)
                            `AES_F3_LOADKEY: begin
                                pcpi_ready_r = 1'b1;
                            end
                            `AES_F3_LOADBLOCK: begin
                                pcpi_ready_r = 1'b1;
                            end
                            `AES_F3_ENCRYPT: begin
                                pcpi_wait_r = 1'b1;
                            end
                            `AES_F3_READRESULT: begin
                                pcpi_ready_r = 1'b1;
                                pcpi_wr_r    = 1'b1;
                                case (word_idx)
                                    2'd0: pcpi_rd_r = ciphertext[127:96];
                                    2'd1: pcpi_rd_r = ciphertext[95:64];
                                    2'd2: pcpi_rd_r = ciphertext[63:32];
                                    2'd3: pcpi_rd_r = ciphertext[31:0];
                                endcase
                            end
                            `AES_F3_STATUS: begin
                                pcpi_ready_r = 1'b1;
                                pcpi_wr_r    = 1'b1;
                                pcpi_rd_r    = {31'b0, core_busy};
                            end
                            default: begin
                                // Reserved funct3: not claimed.
                            end
                        endcase
                    end
                end
                ST_BUSY: begin
                    // Gated on core_seen_running -- see declaration comment
                    // above. Without this gate, a stale core_done left
                    // over from a PRIOR operation (aes_core.fsm_state still
                    // ST_DONE, not yet reacted to this session's start_i)
                    // is indistinguishable from genuine completion.
                    pcpi_wait_r  = !(core_done && core_seen_running);
                    pcpi_ready_r =  (core_done && core_seen_running);
                end
            endcase
        end
    end

    assign pcpi_wr    = pcpi_wr_r;
    assign pcpi_rd    = pcpi_rd_r;
    assign pcpi_wait  = pcpi_wait_r;
    assign pcpi_ready = pcpi_ready_r;

    // ---------------------------------------------------------------
    // Next-state (combinational) logic for the 3 scanned registers.
    // Reproduces exactly the original per-word load-on-match / hold-
    // otherwise semantics, and the ST_IDLE<->ST_BUSY FSM transition.
    // ---------------------------------------------------------------
    wire load_key_word   = (fsm_state_q == ST_IDLE) && pcpi_valid && is_aes_opcode && (funct3 == `AES_F3_LOADKEY);
    wire load_block_word = (fsm_state_q == ST_IDLE) && pcpi_valid && is_aes_opcode && (funct3 == `AES_F3_LOADBLOCK);
    wire start_encrypt   = (fsm_state_q == ST_IDLE) && pcpi_valid && is_aes_opcode && (funct3 == `AES_F3_ENCRYPT);

    wire [127:0] key_stage_d;
    assign key_stage_d[127:96] = (load_key_word && word_idx == 2'd0) ? pcpi_rs2 : key_stage_q[127:96];
    assign key_stage_d[95:64]  = (load_key_word && word_idx == 2'd1) ? pcpi_rs2 : key_stage_q[95:64];
    assign key_stage_d[63:32]  = (load_key_word && word_idx == 2'd2) ? pcpi_rs2 : key_stage_q[63:32];
    assign key_stage_d[31:0]   = (load_key_word && word_idx == 2'd3) ? pcpi_rs2 : key_stage_q[31:0];

    wire [127:0] block_stage_d;
    assign block_stage_d[127:96] = (load_block_word && word_idx == 2'd0) ? pcpi_rs2 : block_stage_q[127:96];
    assign block_stage_d[95:64]  = (load_block_word && word_idx == 2'd1) ? pcpi_rs2 : block_stage_q[95:64];
    assign block_stage_d[63:32]  = (load_block_word && word_idx == 2'd2) ? pcpi_rs2 : block_stage_q[63:32];
    assign block_stage_d[31:0]   = (load_block_word && word_idx == 2'd3) ? pcpi_rs2 : block_stage_q[31:0];

    wire fsm_state_d = (fsm_state_q == ST_IDLE) ? (start_encrypt ? ST_BUSY : ST_IDLE) :
                        (fsm_state_q == ST_BUSY) ? (core_done ? ST_IDLE : ST_BUSY) :
                                                    ST_IDLE;

    // ---------------------------------------------------------------
    // Scan segment: scan_in -> key_stage -> block_stage -> fsm_state
    //             -> [aes_core's 4-register segment] -> scan_out
    // ---------------------------------------------------------------
    localparam SENS_GATE = (DEFENSE_LEVEL == 2 || DEFENSE_LEVEL == 4 || DEFENSE_LEVEL == 5);
    localparam TAIL_GATE = (DEFENSE_LEVEL == 4);
    localparam FLUSH_EN  = (DEFENSE_LEVEL == 3);
    localparam GRANULAR  = (DEFENSE_LEVEL == 2 || DEFENSE_LEVEL == 5);
    reg  scan_en_q = 1'b0;
    always @(posedge clk) scan_en_q <= scan_en;
    wire flush = FLUSH_EN & locked & (scan_en ^ scan_en_q);
    wire rst_n = resetn & ~flush;
    wire scan_en_sens = SENS_GATE ? (scan_en & ~locked) : scan_en;
    wire scan_en_tail = TAIL_GATE ? (scan_en & ~locked) : scan_en;
    wire core_scan_out, core_tail_out;

    wire [4:0] seg_tap;
    assign seg_tap[0] = scan_in;
    assign scan_out = GRANULAR ? (locked ? core_tail_out : seg_tap[4]) : seg_tap[4];
    wire tail_in = (DEFENSE_LEVEL == 2) ? scan_in : core_tail_out;
    wire blk_scan_in = (GRANULAR && locked) ? tail_in : seg_tap[1];

    scan_chain #(.WIDTH(128)) u_scan_key_stage (
        .clk(clk), .resetn(rst_n), .scan_en(scan_en_sens),
        .scan_in(seg_tap[0]), .scan_out(seg_tap[1]),
        .d(key_stage_d), .q(key_stage_q)
    );

    scan_chain #(.WIDTH(128)) u_scan_block_stage (
        .clk(clk), .resetn(rst_n), .scan_en(scan_en_tail),
        .scan_in(blk_scan_in), .scan_out(seg_tap[2]),
        .d(block_stage_d), .q(block_stage_q)
    );

    scan_chain #(.WIDTH(1)) u_scan_fsm_state (
        .clk(clk), .resetn(rst_n), .scan_en(scan_en_tail),
        .scan_in(seg_tap[2]), .scan_out(seg_tap[3]),
        .d(fsm_state_d), .q(fsm_state_q)
    );

    aes_core_def #(.DEFENSE_LEVEL(DEFENSE_LEVEL)) u_aes_core (
        .clk         (clk),
        .resetn      (resetn),
        .start_i     (start_i_reg),
        .key_i       (key_stage_q),
        .block_i     (block_stage_q),
        .busy_o      (core_busy),
        .done_o      (core_done),
        .ciphertext_o(ciphertext),
        .dbg_key_reg      (dbg_core_key_reg),
        .dbg_round_key_reg(dbg_core_round_key_reg),
        .dbg_state_reg    (dbg_core_state_reg),
        .dbg_round_reg    (dbg_core_round_reg),
        .scan_en (scan_en),
        .scan_in (seg_tap[3]),
        .scan_out(seg_tap[4]),
        .locked  (locked),
        .scan_out_tail(core_tail_out)
    );

    assign dbg_key_stage   = key_stage_q;
    assign dbg_block_stage = block_stage_q;

    // ---------------------------------------------------------------
    // start_i_reg: plain one-cycle pulse, unchanged in spirit from the
    // original ENCRYPT-branch assignment.
    // ---------------------------------------------------------------
    always @(posedge clk) begin
        start_i_reg <= 1'b0;
        if (rst_n) begin
            if (start_encrypt)
                start_i_reg <= 1'b1;
        end
    end

    // See core_seen_running declaration comment above.
    always @(posedge clk) begin
        if (!rst_n)
            core_seen_running <= 1'b0;
        else if (start_encrypt)
            core_seen_running <= 1'b0;
        else if (core_busy)
            core_seen_running <= 1'b1;
    end

endmodule