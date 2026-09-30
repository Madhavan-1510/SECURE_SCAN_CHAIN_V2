// ============================================================================
// scan_lock_controller_v2.v  --  Paper 2, L1 lock hardening
//
// Same job as scan_lock_controller.v (v1): grant/deny access, output `locked`.
// The security property still lives in aes_core.v's combinational gates; this
// module only decides WHEN they are open. It stays a plain gate: one 32-bit
// equality compare + counters. No LFSR, no challenge/response (GF-Flush).
//
// Changes vs v1 (each one closes a specific A4 finding, F7):
//   1. NO public default code. v1 hard-codes UNLOCK_CODE=32'hDEC0DED1 as a
//      parameter default. v2 has no code parameter at all: the reference code
//      comes in on `secret_i`, qualified by `secret_valid_i`. If the secret
//      is not provisioned (`secret_valid_i`=0) nothing can unlock.
//      Where secret_i comes from (per-device provisioning) is OUT OF SCOPE
//      here; a constant baked into the bitstream is only as secret as the
//      bitstream.
//   2. Attempt counter + lockout. MAX_FAILS consecutive wrong codes start a
//      LOCKOUT of LOCKOUT_CYCLES clocks during which unlock attempts are
//      ignored (not evaluated, not counted). HARD_LOCKOUT=1 makes it
//      permanent until `resetn`.
//   3. Boot delay. The counter lives in this module's reset domain, so a
//      reset would otherwise clear it. After reset, attempts are ignored for
//      BOOT_DELAY_CYCLES clocks, which bounds attempts-per-reset. Keep
//      BOOT_DELAY_CYCLES >= LOCKOUT_CYCLES so that resetting is never cheaper
//      than waiting out a lockout.
//
// Unchanged from v1: fail-safe locked=1 out of reset; `relock` has priority
// and forces locked=1; a correct code clears `locked`.
//
// Cycle semantics (exact, checked by tb_lock_v2.v): with resetn=1, the first
// BOOT_DELAY_CYCLES clock edges ignore unlock_valid, the next one evaluates
// it. After the failing edge that triggers a lockout, the next
// LOCKOUT_CYCLES edges ignore unlock_valid.
//
// Known trade-off: an attacker can burn MAX_FAILS attempts to block a
// legitimate unlock for LOCKOUT_CYCLES (or until reset with HARD_LOCKOUT).
// This affects unlocking only, never functional AES.
// ============================================================================
`timescale 1ns/1ps

module scan_lock_controller_v2 #(
    parameter integer MAX_FAILS         = 3,
    parameter integer LOCKOUT_CYCLES    = 100_000_000,
    parameter integer BOOT_DELAY_CYCLES = 100_000_000,
    parameter [0:0]   HARD_LOCKOUT      = 1'b0
) (
    input  wire        clk,
    input  wire        resetn,

    input  wire        unlock_valid,     // 1-cycle attempt strobe
    input  wire [31:0] unlock_code_i,    // presented code
    input  wire [31:0] secret_i,         // provisioned reference code
    input  wire        secret_valid_i,   // 0 = not provisioned: never unlock

    input  wire        relock,           // force back to locked

    output wire        locked,
    output wire        lockout_o         // attempts currently being ignored
);

    localparam integer FAIL_W = $clog2(MAX_FAILS + 1);

    reg              locked_q;
    reg [FAIL_W-1:0] fails;
    reg [31:0]       cool;
    reg              dead;

    assign locked    = locked_q;
    assign lockout_o = (cool != 32'd0) || dead;

    wire attempt = unlock_valid && locked_q && !lockout_o;
    wire match   = secret_valid_i && (unlock_code_i == secret_i);

    always @(posedge clk) begin
        if (!resetn) begin
            locked_q <= 1'b1;                 // fail-safe
            fails    <= {FAIL_W{1'b0}};
            cool     <= BOOT_DELAY_CYCLES;
            dead     <= 1'b0;
        end else begin
            if (cool != 32'd0) cool <= cool - 32'd1;

            if (relock) begin
                locked_q <= 1'b1;
            end else if (attempt) begin
                if (match) begin
                    locked_q <= 1'b0;
                    fails    <= {FAIL_W{1'b0}};
                end else if (fails == MAX_FAILS-1) begin
                    fails <= {FAIL_W{1'b0}};
                    if (HARD_LOCKOUT) dead <= 1'b1;
                    else              cool <= LOCKOUT_CYCLES;
                end else begin
                    fails <= fails + 1'b1;
                end
            end
        end
    end

endmodule