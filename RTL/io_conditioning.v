// ============================================================================
// io_conditioning.v
//
// FPGA board-I/O front end. Section 24 of the project's continuation
// instructions is explicit: a physical pushbutton/switch is asynchronous to
// `clk` and must NOT be wired directly into a synchronous FSM. The simulated
// harness (scan_attack_harness.v) was correctly built and verified with a
// clean, already-synchronous btn_start/sw_unlock/sel_byte contract (Section
// 24: "the simulation harness can initially use a clean synchronous
// start_i"). This file is the separate hardware front end that turns real,
// bouncy, asynchronous board I/O into that clean contract, so
// scan_attack_harness.v itself is never touched.
//
// Two small reusable pieces:
//
//   btn_debounce_sync  -- for a MOMENTARY pushbutton (btn_start). Produces a
//                          single clean one-cycle PULSE per physical press,
//                          no matter how long the button is held or how much
//                          contact bounce occurs on press/release.
//
//   level_debounce_sync -- for a SLIDE/TOGGLE SWITCH (sw_unlock, sel_byte
//                          bits). Produces a stable debounced LEVEL, not a
//                          pulse -- these signals are meant to be read as a
//                          steady state, not edge-triggered.
//
// Both start with the same 2-flip-flop metastability synchronizer (standard
// practice for any signal crossing from an asynchronous physical pin into a
// clocked domain), then apply a majority-style "must be stable for N
// consecutive cycles before we believe it changed" debounce filter.
//
// DEBOUNCE_CYCLES is deliberately a parameter, not a hardcoded constant:
//   - Real hardware (e.g. PYNQ-Z2 buttons at a ~100 MHz system clock) wants
//     on the order of 1-2 ms of stability, i.e. roughly 100_000-200_000
//     cycles, to reject real mechanical contact bounce.
//   - Simulation wants a tiny value (this file defaults to 20) so testbenches
//     complete in a reasonable number of simulated cycles. Instantiate this
//     module with an explicit #(.DEBOUNCE_CYCLES(...)) override for real
//     synthesis; do not rely on the default outside simulation.
// ============================================================================
`timescale 1ns/1ps

module btn_debounce_sync #(
    parameter integer SYNC_STAGES    = 2,
    parameter integer DEBOUNCE_CYCLES = 20
) (
    input  wire clk,
    input  wire resetn,
    input  wire btn_raw,     // physical, asynchronous, active-high
    output wire pulse_o      // one clock-cycle-wide pulse per debounced press
);

    // ---- Stage 1: metastability synchronizer ----
    reg [SYNC_STAGES-1:0] sync_ff;
    always @(posedge clk) begin
        if (!resetn)
            sync_ff <= {SYNC_STAGES{1'b0}};
        else
            sync_ff <= {sync_ff[SYNC_STAGES-2:0], btn_raw};
    end
    wire btn_sync = sync_ff[SYNC_STAGES-1];

    // ---- Stage 2: debounce filter (require DEBOUNCE_CYCLES of stability
    // at the new value before accepting it as the real, settled level) ----
    localparam integer CNT_W = (DEBOUNCE_CYCLES <= 1) ? 1 : $clog2(DEBOUNCE_CYCLES);
    reg [CNT_W-1:0] stable_cnt;
    reg             btn_debounced;
    reg             btn_debounced_q;   // one-cycle-delayed copy, for edge detect

    always @(posedge clk) begin
        if (!resetn) begin
            stable_cnt      <= {CNT_W{1'b0}};
            btn_debounced   <= 1'b0;
            btn_debounced_q <= 1'b0;
        end else begin
            btn_debounced_q <= btn_debounced;
            if (btn_sync == btn_debounced) begin
                // Matches current accepted level -- no candidate transition
                // in progress, nothing to count.
                stable_cnt <= {CNT_W{1'b0}};
            end else if (stable_cnt >= DEBOUNCE_CYCLES[CNT_W-1:0] - 1'b1) begin
                // Held the new value for the full debounce window: accept it.
                btn_debounced <= btn_sync;
                stable_cnt    <= {CNT_W{1'b0}};
            end else begin
                stable_cnt <= stable_cnt + 1'b1;
            end
        end
    end

    // ---- Stage 3: edge detect on the debounced level -> one-cycle pulse ----
    assign pulse_o = btn_debounced & ~btn_debounced_q;

endmodule


module level_debounce_sync #(
    parameter integer WIDTH          = 1,
    parameter integer SYNC_STAGES    = 2,
    parameter integer DEBOUNCE_CYCLES = 20
) (
    input  wire             clk,
    input  wire             resetn,
    input  wire [WIDTH-1:0] level_raw,
    output wire [WIDTH-1:0] level_o
);

    genvar gi;
    generate
        for (gi = 0; gi < WIDTH; gi = gi + 1) begin : g_bit
            reg [SYNC_STAGES-1:0] sync_ff;
            always @(posedge clk) begin
                if (!resetn)
                    sync_ff <= {SYNC_STAGES{1'b0}};
                else
                    sync_ff <= {sync_ff[SYNC_STAGES-2:0], level_raw[gi]};
            end
            wire bit_sync = sync_ff[SYNC_STAGES-1];

            localparam integer CNT_W = (DEBOUNCE_CYCLES <= 1) ? 1 : $clog2(DEBOUNCE_CYCLES);
            reg [CNT_W-1:0] stable_cnt;
            reg             bit_debounced;

            always @(posedge clk) begin
                if (!resetn) begin
                    stable_cnt    <= {CNT_W{1'b0}};
                    bit_debounced <= 1'b0;
                end else if (bit_sync == bit_debounced) begin
                    stable_cnt <= {CNT_W{1'b0}};
                end else if (stable_cnt >= DEBOUNCE_CYCLES[CNT_W-1:0] - 1'b1) begin
                    bit_debounced <= bit_sync;
                    stable_cnt    <= {CNT_W{1'b0}};
                end else begin
                    stable_cnt <= stable_cnt + 1'b1;
                end
            end

            assign level_o[gi] = bit_debounced;
        end
    endgenerate

endmodule


// ============================================================================
// reset_sync
//
// Standard async-assert / sync-deassert reset synchronizer. A physical board
// reset button is asynchronous just like btn_start is -- but reset needs to
// take effect immediately (async assert) while still releasing cleanly
// aligned to a clock edge (sync deassert), so downstream logic never sees a
// resetn rising edge that violates its own recovery/removal timing.
// Two independent instances are used in fpga_top.v: one for the DUT's
// functional reset (resetn) and one for the lock controller's separate
// reset domain (lock_resetn), matching secure_scan_rv_top_v2.v's existing
// two-reset-domain design intent (a lock/unlock bit should not evaporate
// just because the functional AES datapath is reset).
// ============================================================================
module reset_sync (
    input  wire clk,
    input  wire arstn_raw,   // physical, asynchronous, active-low
    output wire resetn_sync  // synchronized, active-low
);

    reg [1:0] rst_ff;

    always @(posedge clk or negedge arstn_raw) begin
        if (!arstn_raw)
            rst_ff <= 2'b00;
        else
            rst_ff <= {rst_ff[0], 1'b1};
    end

    assign resetn_sync = rst_ff[1];

endmodule