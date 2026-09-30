// ============================================================================
// scan_lock_controller.v
//
// Phase 8 - Access-control gate for the sensitive scan segment.
//
// Deliberately simple, per secure.md Sec.5/31: this module's job is
// access control (grant/deny), NOT the security guarantee itself. The
// actual security property -- "locked => scan_in/scan_out of the
// sensitive segment are forced to a fixed value, regardless of shift
// count" -- lives in aes_core.v's boundary muxes and needs no
// cryptographic assumption to hold. This controller only decides WHEN
// that gate is open or closed.
//
// Explicitly NOT an LFSR-based challenge/response lock -- see secure.md
// Sec.5 on the GF-Flush algebraic break of LFSR-based dynamic scan
// obfuscation. A plain fixed-code compare is fine here precisely because
// this gate carries no security weight of its own.
//
// Reset behavior is fail-safe: `locked` defaults to 1 (segment isolated)
// out of reset, and stays 1 until an explicit, correct unlock is
// presented. `relock` (or reset) always re-arms the lock.
// ============================================================================
`timescale 1ns/1ps

module scan_lock_controller #(
    parameter [31:0] UNLOCK_CODE = 32'hDEC0DED1
) (
    input  wire        clk,
    input  wire        resetn,

    // Single-cycle pulse: attempt to unlock using unlock_code_i this cycle.
    input  wire        unlock_valid,
    input  wire [31:0] unlock_code_i,

    // Single-cycle pulse: force back to the locked state.
    input  wire        relock,

    output wire        locked
);

    reg locked_q;
    assign locked = locked_q;

    always @(posedge clk) begin
        if (!resetn) begin
            locked_q <= 1'b1;          // fail-safe: locked out of reset
        end else if (relock) begin
            locked_q <= 1'b1;
        end else if (unlock_valid && (unlock_code_i == UNLOCK_CODE)) begin
            locked_q <= 1'b0;
        end
    end

endmodule