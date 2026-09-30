// ============================================================================
// scan_chain.v
//
// Purpose:
//   A parameterized WIDTH-bit scan-capable register: a drop-in replacement
//   for a plain `reg [WIDTH-1:0] foo;` that additionally supports serial
//   scan shifting. This is the building block used to make aes_core.v's
//   and aes_pcpi.v's secret-bearing registers scan-observable in Phase 6.
//
// Bit-ordering convention (fixed here, used project-wide from this point
// on -- see docs/scan_map.md):
//   bit [0]         is closest to this register's local scan_in
//   bit [WIDTH-1]   is closest to this register's local scan_out
//   i.e. LSB-first shifting. Shifting WIDTH cycles with scan_en=1 moves an
//   external bit pattern in through scan_in, through bit 0 first, ending
//   with bit[WIDTH-1] driving scan_out.
//
// Functional behavior (scan_en=0): q <= d every cycle, exactly like a plain
// register -- this module must be functionally transparent when not in
// scan mode, which is what the Phase 6 regression tests below confirm for
// the modules that get converted to use it.
// ============================================================================
`timescale 1ns/1ps

module scan_chain #(
    parameter WIDTH = 128,
    parameter [WIDTH-1:0] RESET_VALUE = {WIDTH{1'b0}}
) (
    input  wire             clk,
    input  wire             resetn,
    input  wire             scan_en,
    input  wire             scan_in,
    output wire             scan_out,

    input  wire [WIDTH-1:0] d,
    output wire [WIDTH-1:0] q
);

    // chain_taps[0]         = external scan_in
    // chain_taps[i+1]       = bit i's scan_out = bit (i+1)'s scan_in
    // chain_taps[WIDTH]     = external scan_out
    wire [WIDTH:0] chain_taps;
    assign chain_taps[0] = scan_in;
    assign scan_out       = chain_taps[WIDTH];

    genvar i;
    generate
        for (i = 0; i < WIDTH; i = i + 1) begin : g_bit
            scan_cell #(.RESET_VALUE(RESET_VALUE[i])) u_cell (
                .clk     (clk),
                .resetn  (resetn),
                .scan_en (scan_en),
                .scan_in (chain_taps[i]),
                .d       (d[i]),
                .q       (q[i]),
                .scan_out(chain_taps[i+1])
            );
        end
    endgenerate

endmodule
