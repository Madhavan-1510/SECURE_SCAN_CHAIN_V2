// ============================================================================
// scan_cell.v
//
// Purpose:
//   The fundamental scan-capable flip-flop. This is the explicit RTL model
//   of an ASIC-style scan cell, built for FPGA simulation/synthesis rather
//   than relying on any vendor DFT insertion flow (Vivado does NOT
//   automatically create production scan chains for FPGA designs -- this
//   module IS the scan chain, modeled by hand, per the project's core
//   engineering principle).
//
// Behavior:
//   resetn == 0        : q <= RESET_VALUE          (synchronous reset)
//   resetn==1, scan_en=1: q <= scan_in              (scan/shift mode)
//   resetn==1, scan_en=0: q <= d                    (functional mode)
//
// Ports:
//   clk, resetn : shared with the functional design (single clock domain,
//                 per project constraint -- no separate scan clock here).
//   scan_en     : mode select. HIGH = scan/shift, LOW = functional.
//   scan_in     : serial data in from the previous cell in the chain (or
//                 the chain's external SCAN_IN on the first cell).
//   d           : functional next-state input (from the surrounding logic).
//   q           : current cell value -- used BOTH as the functional output
//                 feeding the rest of the design AND as this cell's
//                 contribution to scan observability.
//   scan_out    : serial data out to the next cell in the chain (or the
//                 chain's external SCAN_OUT on the last cell). Simply taps
//                 q -- there is no separate scan-only storage element, so
//                 there is exactly one register per bit, not two.
//
// Explicitly NOT modeled here (documented, not silently ignored):
//   - Scan capture/launch clocking edges distinct from functional clocking
//     (real ASIC scan often uses launch-on-shift or separate scan clocks).
//     This prototype uses ONE clock for both, per project scope.
//   - Lockup latches between clock domains (N/A -- single domain).
//   - Any notion of scan compression/MISR -- this is a plain full-length
//     serial shift, matching the project's deterministic-ordering
//     requirement (Phase 6 scan map depends on this being a straight
//     shift-register, not compressed).
// ============================================================================
`timescale 1ns/1ps

module scan_cell #(
    parameter RESET_VALUE = 1'b0
) (
    input  wire clk,
    input  wire resetn,
    input  wire scan_en,
    input  wire scan_in,
    input  wire d,
    output wire q,
    output wire scan_out
);

    reg q_reg;

    always @(posedge clk) begin
        if (!resetn)
            q_reg <= RESET_VALUE;
        else if (scan_en)
            q_reg <= scan_in;
        else
            q_reg <= d;
    end

    assign q        = q_reg;
    assign scan_out = q_reg;

endmodule
