// ============================================================================
// aes_core.v  (Phase 6: scan-retrofitted)
//
// Purpose:
//   Iterative (one-round-per-cycle) AES-128 encryption engine.
//
// Byte-ordering convention: unchanged from Phase 3/4 (see original header) --
// all 128-bit vectors are big-endian byte order, FIPS-197 column-major state.
//
// PHASE 6 CHANGE SUMMARY:
//   key_reg, round_key_reg, state_reg, round_reg are no longer plain `reg`.
//   Each is now a `scan_chain` instance so it is scan-observable. fsm_state
//   is INTENTIONALLY LEFT AS A PLAIN REGISTER -- it is not in the Phase 6
//   scan-conversion list (secure.md / project instructions name only
//   key_reg/round_key_reg/state_reg/round_reg for this module) and it holds
//   no secret value (just a 2-bit control code), so there is no security
//   reason to scan it.
//
//   The functional (non-scan) behavior is required to be bit-for-bit
//   identical to Phase 3/4: every register's next-state is now computed as
//   an explicit combinational MUX (the *_d wires below) which reproduces
//   exactly the same case-statement logic that used to live directly inside
//   the always @(posedge clk) block. See docs/scan_map.md for the full
//   segment bit-offset table and chain ordering rationale.
//
// Scan segment contributed by this module (4 registers, LOCAL order):
//   scan_in -> round_reg(4b) -> state_reg(128b) -> round_key_reg(128b)
//           -> key_reg(128b) -> scan_out
//   i.e. round_key_reg and key_reg -- the two registers secure.md's threat
//   model requires isolating -- sit LAST, immediately adjacent to this
//   module's scan_out. Chosen deliberately so a future Phase 8 lock needs
//   only ONE segment boundary (before round_key_reg), not two, since
//   nothing in this module's chain follows key_reg.
// ============================================================================
`timescale 1ns/1ps

// DEFENSE_LEVEL:
//   1 = G1  Paper 1: scan_out masked + round_key_reg scan-in gated (bit-identical to aes_core.v)
//   2 = G2  granular: sensitive regs (state_reg, round_key_reg, key_reg [+key_stage in aes_pcpi_def])
//           frozen while locked; tail (round_reg [+block_stage, fsm_state]) keeps shifting
//   3 = G3  G1 + synchronous flush of EVERY register (incl. plain FSM regs) on any scan_en edge while locked
//   4 = G4  whole chain frozen while locked (write-blocking), scan_out masked
//   5 = G2R like G2 but the tail recirculates while locked (observable, not injectable)
// Every gate depends ONLY on `locked` (+scan_en / a 1-flop scan_en delay for G3).
module aes_core_def #(
    parameter integer DEFENSE_LEVEL = 4
) (
    input  wire         clk,
    input  wire         resetn,

    input  wire         start_i,       // 1-cycle pulse: latch key_i/block_i, begin encryption
    input  wire [127:0] key_i,
    input  wire [127:0] block_i,

    output wire         busy_o,        // high while RUNNING
    output wire         done_o,        // high once ciphertext is valid (sticky until next start_i)
    output wire [127:0] ciphertext_o,

    // Direct read-back of explicit secret-bearing registers, for scan-map
    // wiring / attack demonstration purposes only (Phase 2/3 of the plan).
    // Not part of the normal PCPI datapath.
    output wire [127:0] dbg_key_reg,
    output wire [127:0] dbg_round_key_reg,
    output wire [127:0] dbg_state_reg,
    output wire [3:0]   dbg_round_reg,

    // Phase 6: coprocessor scan segment (this module's 4-register slice).
    input  wire         scan_en,
    input  wire         scan_in,
    output wire         scan_out,

    // Phase 8: sensitive-segment lock (round_key_reg + key_reg). Purely
    // combinational gate on the scan_in/scan_out wiring around those two
    // registers -- see the boundary-mux block below and secure.md Sec.28-30
    // for the full leakage analysis. Does not affect any functional
    // (scan_en=0) path.
    input  wire         locked,

    output wire         scan_out_tail
);

    // ---------------------------------------------------------------
    // fsm_state: plain, non-scanned control register (see header note).
    // ---------------------------------------------------------------
    localparam ST_IDLE    = 2'd0;
    localparam ST_RUNNING = 2'd1;
    localparam ST_DONE    = 2'd2;
    reg [1:0] fsm_state;

    localparam SENS_GATE = (DEFENSE_LEVEL == 2 || DEFENSE_LEVEL == 4 || DEFENSE_LEVEL == 5);
    localparam TAIL_GATE = (DEFENSE_LEVEL == 4);
    localparam FLUSH_EN  = (DEFENSE_LEVEL == 3);
    reg  scan_en_q = 1'b0;
    always @(posedge clk) scan_en_q <= scan_en;
    wire flush = FLUSH_EN & locked & (scan_en ^ scan_en_q);
    wire rst_n = resetn & ~flush;
    wire scan_en_sens = SENS_GATE ? (scan_en & ~locked) : scan_en;
    wire scan_en_tail = TAIL_GATE ? (scan_en & ~locked) : scan_en;

    // ---------------------------------------------------------------
    // Explicit secret-bearing state -- now scan_chain outputs (q) rather
    // than plain regs. *_q is "current value" (read side); *_d is the
    // combinational "next value" fed into each scan_chain's functional d.
    // ---------------------------------------------------------------
    wire [127:0] key_reg_q, round_key_reg_q, state_reg_q;
    wire [3:0]   round_reg_q;

    assign busy_o       = (fsm_state == ST_RUNNING);
    assign done_o       = (fsm_state == ST_DONE);
    assign ciphertext_o = state_reg_q;

    assign dbg_key_reg       = key_reg_q;
    assign dbg_round_key_reg = round_key_reg_q;
    assign dbg_state_reg     = state_reg_q;
    assign dbg_round_reg     = round_reg_q;

    // ---------------------------------------------------------------
    // SubBytes: 16 parallel S-box lookups on the current state
    // ---------------------------------------------------------------
    wire [7:0] sb_in  [0:15];
    wire [7:0] sb_out [0:15];
    genvar gi;
    generate
        for (gi = 0; gi < 16; gi = gi + 1) begin : g_state_sbox
            assign sb_in[gi] = state_reg_q[127-8*gi -: 8];
            aes_sbox u_sbox (
                .in_byte (sb_in[gi]),
                .out_byte(sb_out[gi])
            );
        end
    endgenerate

    wire [127:0] subbytes_state;
    assign subbytes_state = { sb_out[0], sb_out[1], sb_out[2],  sb_out[3],
                               sb_out[4], sb_out[5], sb_out[6],  sb_out[7],
                               sb_out[8], sb_out[9], sb_out[10], sb_out[11],
                               sb_out[12],sb_out[13],sb_out[14], sb_out[15] };

    // ---------------------------------------------------------------
    // ShiftRows (FIPS-197 3.2.2) -- unchanged
    // ---------------------------------------------------------------
    function [127:0] shift_rows;
        input [127:0] s;
        reg [7:0] b [0:15];
        reg [7:0] o [0:15];
        integer r, c;
        begin
            for (r = 0; r < 16; r = r + 1)
                b[r] = s[127-8*r -: 8];
            for (r = 0; r < 4; r = r + 1)
                for (c = 0; c < 4; c = c + 1)
                    o[r + 4*c] = b[r + 4*((c + r) % 4)];
            shift_rows = { o[0], o[1], o[2],  o[3],  o[4],  o[5],  o[6],  o[7],
                           o[8], o[9], o[10], o[11], o[12], o[13], o[14], o[15] };
        end
    endfunction

    // ---------------------------------------------------------------
    // MixColumns (FIPS-197 3.2.3) -- unchanged
    // ---------------------------------------------------------------
    function [7:0] xtime;
        input [7:0] a;
        begin
            xtime = (a << 1) ^ (a[7] ? 8'h1b : 8'h00);
        end
    endfunction

    function [7:0] gmul3;
        input [7:0] a;
        begin
            gmul3 = xtime(a) ^ a;
        end
    endfunction

    function [127:0] mix_columns;
        input [127:0] s;
        reg [7:0] b [0:15];
        reg [7:0] o [0:15];
        integer c;
        reg [7:0] a0, a1, a2, a3;
        begin
            for (c = 0; c < 16; c = c + 1)
                b[c] = s[127-8*c -: 8];
            for (c = 0; c < 4; c = c + 1) begin
                a0 = b[0+4*c]; a1 = b[1+4*c]; a2 = b[2+4*c]; a3 = b[3+4*c];
                o[0+4*c] = xtime(a0) ^ gmul3(a1) ^ a2 ^ a3;
                o[1+4*c] = a0 ^ xtime(a1) ^ gmul3(a2) ^ a3;
                o[2+4*c] = a0 ^ a1 ^ xtime(a2) ^ gmul3(a3);
                o[3+4*c] = gmul3(a0) ^ a1 ^ a2 ^ xtime(a3);
            end
            mix_columns = { o[0], o[1], o[2],  o[3],  o[4],  o[5],  o[6],  o[7],
                             o[8], o[9], o[10], o[11], o[12], o[13], o[14], o[15] };
        end
    endfunction

    // ---------------------------------------------------------------
    // Key schedule -- unchanged except reading round_key_reg_q/round_reg_q
    // ---------------------------------------------------------------
    function [31:0] rot_word;
        input [31:0] w;
        begin
            rot_word = { w[23:0], w[31:24] };
        end
    endfunction

    function [7:0] rcon_byte;
        input [3:0] round;
        begin
            case (round)
                4'd1:  rcon_byte = 8'h01;
                4'd2:  rcon_byte = 8'h02;
                4'd3:  rcon_byte = 8'h04;
                4'd4:  rcon_byte = 8'h08;
                4'd5:  rcon_byte = 8'h10;
                4'd6:  rcon_byte = 8'h20;
                4'd7:  rcon_byte = 8'h40;
                4'd8:  rcon_byte = 8'h80;
                4'd9:  rcon_byte = 8'h1b;
                4'd10: rcon_byte = 8'h36;
                default: rcon_byte = 8'h00;
            endcase
        end
    endfunction

    wire [31:0] rotw3 = rot_word(round_key_reg_q[31:0]);
    wire [7:0]  kb_in  [0:3];
    wire [7:0]  kb_out [0:3];
    assign kb_in[0] = rotw3[31:24];
    assign kb_in[1] = rotw3[23:16];
    assign kb_in[2] = rotw3[15:8];
    assign kb_in[3] = rotw3[7:0];
    generate
        for (gi = 0; gi < 4; gi = gi + 1) begin : g_key_sbox
            aes_sbox u_key_sbox (
                .in_byte (kb_in[gi]),
                .out_byte(kb_out[gi])
            );
        end
    endgenerate
    wire [31:0] subword_rotw3 = { kb_out[0], kb_out[1], kb_out[2], kb_out[3] };

    wire [31:0] w0 = round_key_reg_q[127:96];
    wire [31:0] w1 = round_key_reg_q[95:64];
    wire [31:0] w2 = round_key_reg_q[63:32];
    wire [31:0] w3 = round_key_reg_q[31:0];

    wire [31:0] rcon_word = { rcon_byte(round_reg_q), 8'h00, 8'h00, 8'h00 };
    wire [31:0] w4 = w0 ^ subword_rotw3 ^ rcon_word;
    wire [31:0] w5 = w4 ^ w1;
    wire [31:0] w6 = w5 ^ w2;
    wire [31:0] w7 = w6 ^ w3;
    wire [127:0] next_round_key = { w4, w5, w6, w7 };

    // ---------------------------------------------------------------
    // Per-round combinational pipeline (reads *_q, unchanged math)
    // ---------------------------------------------------------------
    wire [127:0] shiftrows_out = shift_rows(subbytes_state);
    wire [127:0] mixcols_out   = mix_columns(shiftrows_out);
    wire         is_final_round = (round_reg_q == 4'd10);
    wire [127:0] pre_addkey     = is_final_round ? shiftrows_out : mixcols_out;
    wire [127:0] round_output   = pre_addkey ^ next_round_key;

    // ---------------------------------------------------------------
    // Next-state (combinational) MUXes -- these reproduce EXACTLY the
    // same case-statement semantics the original always-block had, just
    // restructured so the storage itself can live inside scan_chain.
    //   load_key covers both (ST_IDLE && start_i) and (ST_DONE && start_i),
    //   which did identical things in the original code.
    // ---------------------------------------------------------------
    wire load_key = (fsm_state == ST_IDLE && start_i) || (fsm_state == ST_DONE && start_i);

    wire [127:0] key_reg_d = load_key ? key_i : key_reg_q;

    wire [127:0] round_key_reg_d =
        load_key                   ? key_i :
        (fsm_state == ST_RUNNING)  ? next_round_key :
                                      round_key_reg_q;

    wire [127:0] state_reg_d =
        load_key                   ? (block_i ^ key_i) :
        (fsm_state == ST_RUNNING)  ? round_output :
                                      state_reg_q;

    wire [3:0] round_reg_d =
        load_key                                     ? 4'h1 :
        (fsm_state == ST_RUNNING && !is_final_round)  ? (round_reg_q + 4'h1) :
                                                         round_reg_q;

    // ---------------------------------------------------------------
    // Scan segment: scan_in -> round_reg -> state_reg -> round_key_reg
    //             -> key_reg -> scan_out
    // seg_tap[0] = external scan_in, seg_tap[4] = external scan_out.
    //
    // PHASE 8: two purely-combinational boundary muxes isolate the
    // sensitive segment (round_key_reg + key_reg, secure.md global bits
    // [644:389]):
    //   - seg_in_muxed  gates what SHIFTS INTO round_key_reg
    //   - seg_out_muxed gates what this module's scan_out actually shows
    // Both are keyed ONLY on `locked` (never on a clocked/registered
    // term), so masking is active before the first pre-shift sample
    // (closes the zero-shift exposure, secure.md Sec.29) and is
    // shift-count-independent (closes Sec.28 Q5-Q7: masked at 0, 128,
    // 256, 645, or any number of shifts beyond that).
    //
    // round_reg/state_reg wiring (seg_tap[0]/[1]/[2]) is completely
    // untouched -- Phase 8 only bounds the sensitive tail of the chain.
    // ---------------------------------------------------------------
    wire [4:0] seg_tap;
    assign seg_tap[0] = scan_in;
    wire seg_in_muxed  = locked ? 1'b0 : seg_tap[2];
    wire seg_out_muxed = locked ? 1'b0 : seg_tap[4];
    assign scan_out      = seg_out_muxed;
    assign scan_out_tail = seg_tap[1];

    scan_chain #(.WIDTH(4)) u_scan_round_reg (
        .clk(clk), .resetn(rst_n), .scan_en(scan_en_tail),
        .scan_in(seg_tap[0]), .scan_out(seg_tap[1]),
        .d(round_reg_d), .q(round_reg_q)
    );

    scan_chain #(.WIDTH(128)) u_scan_state_reg (
        .clk(clk), .resetn(rst_n), .scan_en(scan_en_sens),
        .scan_in(seg_tap[1]), .scan_out(seg_tap[2]),
        .d(state_reg_d), .q(state_reg_q)
    );

    scan_chain #(.WIDTH(128)) u_scan_round_key_reg (
        .clk(clk), .resetn(rst_n), .scan_en(scan_en_sens),
        .scan_in(seg_in_muxed), .scan_out(seg_tap[3]),
        .d(round_key_reg_d), .q(round_key_reg_q)
    );

    scan_chain #(.WIDTH(128)) u_scan_key_reg (
        .clk(clk), .resetn(rst_n), .scan_en(scan_en_sens),
        .scan_in(seg_tap[3]), .scan_out(seg_tap[4]),
        .d(key_reg_d), .q(key_reg_q)
    );

    // ---------------------------------------------------------------
    // fsm_state: plain register, unchanged transition semantics from
    // Phase 3/4 (only the register-value assignments were pulled out
    // into the *_d muxes above; the FSM transitions themselves are
    // bit-for-bit identical).
    // ---------------------------------------------------------------
    always @(posedge clk) begin
        if (!rst_n) begin
            fsm_state <= ST_IDLE;
        end else begin
            case (fsm_state)
                ST_IDLE: begin
                    if (start_i)
                        fsm_state <= ST_RUNNING;
                end
                ST_RUNNING: begin
                    if (is_final_round)
                        fsm_state <= ST_DONE;
                end
                ST_DONE: begin
                    if (start_i)
                        fsm_state <= ST_RUNNING;
                end
                default: fsm_state <= ST_IDLE;
            endcase
        end
    end

endmodule