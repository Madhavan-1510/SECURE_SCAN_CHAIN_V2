// ============================================================================
// lock_switch_ctrl.v
//
// Translates one debounced board switch (sw_unlock) into the pulse-based
// unlock_valid/relock interface scan_lock_controller.v (already verified,
// unmodified) actually expects. This is a demo-board convenience, not a new
// security mechanism: it presents the fixed UNLOCK_CODE the instant the
// switch goes high, and issues relock the instant it goes low. The security
// property under test is the masking behavior in aes_core.v when locked=1
// (secure1.md Sec.5) -- this controller only exercises that gate, exactly
// as tb_scan_lock.v's Part B/C already do with @(negedge clk) pulses.
// ============================================================================
`timescale 1ns/1ps

module lock_switch_ctrl #(
    parameter [31:0] UNLOCK_CODE = 32'hDEC0DED1
) (
    input  wire        clk,
    input  wire        resetn,
    input  wire        sw_unlock,      // debounced level
    output reg         unlock_valid_o,
    output wire [31:0] unlock_code_o,
    output reg         relock_o
);

    assign unlock_code_o = UNLOCK_CODE;

    reg sw_unlock_q;

    always @(posedge clk) begin
        unlock_valid_o <= 1'b0;
        relock_o       <= 1'b0;
        if (!resetn) begin
            sw_unlock_q <= 1'b0;
        end else begin
            sw_unlock_q <= sw_unlock;
            if (sw_unlock && !sw_unlock_q)
                unlock_valid_o <= 1'b1;
            else if (!sw_unlock && sw_unlock_q)
                relock_o <= 1'b1;
        end
    end

endmodule