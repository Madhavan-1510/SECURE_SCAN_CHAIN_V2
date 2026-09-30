// ============================================================================
// power_on_reset.v
//
// Self-releasing reset pulse driven purely from configuration + clk, with NO
// dependence on any external button's idle polarity. FPGA flip-flops come
// out of configuration at their bitstream INIT value (0 here), so por_cnt
// starts at 0 regardless of board wiring, counts up to POR_CYCLES, and
// resetn_o stays low (asserted) until it gets there -- exactly once, right
// after configuration, every time, on every board, regardless of whether a
// given button reads active-high or active-low at idle.
//
// Combine with a button-derived reset via a simple AND (see board_top.v):
// resetn = por_resetn & button_resetn. This guarantees the design always
// comes out of reset correctly on power-up even if the button polarity
// assumption elsewhere turns out to be wrong -- the button then only
// affects manual re-reset behavior, not first-run correctness.
// ============================================================================
`timescale 1ns/1ps

module power_on_reset #(
    parameter integer POR_CYCLES = 64
) (
    input  wire clk,
    output wire resetn_o
);

    reg [$clog2(POR_CYCLES+1)-1:0] por_cnt = 0; // FPGA INIT value = 0, no config dependency
    reg resetn_r = 1'b0;

    always @(posedge clk) begin
        if (por_cnt < POR_CYCLES[$clog2(POR_CYCLES+1)-1:0]) begin
            por_cnt   <= por_cnt + 1'b1;
            resetn_r  <= 1'b0;
        end else begin
            resetn_r <= 1'b1;
        end
    end

    assign resetn_o = resetn_r;

endmodule