// ============================================================================
// edge_reset_pulse.v
//
// Generates a fixed-length active-low reset pulse on ANY transition of
// btn_raw (press OR release), instead of assuming a particular idle level
// is "not pressed." This makes reset behavior independent of whether a
// given board's button reads active-high or active-low at rest -- a wrong
// polarity assumption elsewhere would otherwise hold the design in
// permanent reset with no way to recover except respinning the bitstream.
// Here, idle (no transitions) never asserts reset in either polarity case,
// and any press/release always produces exactly one clean reset pulse.
//
// Combined with power_on_reset.v (true first-run release from
// configuration alone) via a simple AND in board_top.v, this guarantees:
//   1. The design always runs correctly immediately after programming,
//      with zero button interaction required.
//   2. Any button press, in either wiring convention, reliably produces
//      a clean re-reset instead of either doing nothing or locking up.
// ============================================================================
`timescale 1ns/1ps

module edge_reset_pulse #(
    parameter integer SYNC_STAGES  = 2,
    parameter integer PULSE_CYCLES = 64
) (
    input  wire clk,
    input  wire btn_raw,
    output wire resetn_o   // active-low: 0 during the pulse, 1 otherwise
);

    // Explicit initializers: FPGA flip-flops power up to a defined value
    // from the bitstream (0 here); stating it in RTL (rather than relying
    // on it implicitly) also makes simulation match hardware -- an
    // uninitialized `reg` in Verilog simulation starts as X, which would
    // otherwise poison resetn_o (and everything downstream) with X
    // forever, a pure simulation artifact that does NOT reflect real
    // hardware but must still be avoided so simulation and synthesis agree.
    reg [SYNC_STAGES-1:0] sync_ff = {SYNC_STAGES{1'b0}};
    always @(posedge clk)
        sync_ff <= {sync_ff[SYNC_STAGES-2:0], btn_raw};
    wire btn_sync = sync_ff[SYNC_STAGES-1];

    reg btn_sync_q = 1'b0;
    reg pulsing    = 1'b0;
    reg [$clog2(PULSE_CYCLES+1)-1:0] cnt = 0;

    always @(posedge clk) begin
        btn_sync_q <= btn_sync;
        if (btn_sync != btn_sync_q) begin
            pulsing <= 1'b1;
            cnt     <= {$clog2(PULSE_CYCLES+1){1'b0}};
        end else if (pulsing) begin
            if (cnt == PULSE_CYCLES[$clog2(PULSE_CYCLES+1)-1:0]-1'b1)
                pulsing <= 1'b0;
            else
                cnt <= cnt + 1'b1;
        end
    end

    assign resetn_o = !pulsing;

endmodule