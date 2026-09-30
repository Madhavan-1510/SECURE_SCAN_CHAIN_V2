// ============================================================================
// tb_keystage_lock_scope.v
//
// Phase 9 hardening review - key_stage residue scope check (NEW).
//
// secure1.md's "known limitation" section claims key_stage remains exposed
// under the current defense because the protected scope is documented as
// strictly global bits [644:389] (round_key_reg + key_reg only). This test
// checks that claim directly against the actual RTL rather than the
// documentation.
//
// Finding this test is designed to confirm: aes_core's boundary mux
//     seg_out_muxed = locked ? 1'b0 : seg_tap[4];
// forces the WHOLE coprocessor's external scan_out to a constant 0
// whenever locked=1 -- not only while round_key_reg/key_reg bits would be
// shifting past that point. Because key_stage/block_stage/fsm_state/
// round_reg/state_reg all sit UPSTREAM of this single output mux in the
// local chain (key_stage -> block_stage -> fsm_state -> round_reg ->
// state_reg -> [muxed] round_key_reg -> key_reg -> scan_out), their real
// values never reach the external scan_out either, for as long as
// locked=1. So key_stage does NOT leak while locked -- but as a side
// effect of blanket-gating the entire segment's output, not because
// key_stage was deliberately folded into the protected region. This
// also means round_reg/state_reg (the "AES datapath", which secure.md
// Sec.4's diagram depicts as a SEPARATE, still-testable segment from the
// "LOCKED KEY SEGMENT") are UNOBSERVABLE while locked too -- broader than
// the documented segmentation model. This test reports both facts
// side by side so the tradeoff is visible, rather than silently treating
// "key_stage doesn't leak" as a clean win.
// ============================================================================
`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"

module tb_keystage_lock_scope;

    reg clk = 0;
    reg resetn = 0;
    reg lock_resetn = 0;

    reg         pcpi_valid = 0;
    reg  [31:0] pcpi_insn  = 0;
    reg  [31:0] pcpi_rs1   = 0;
    reg  [31:0] pcpi_rs2   = 0;
    wire        pcpi_wr;
    wire [31:0] pcpi_rd;
    wire        pcpi_wait;
    wire        pcpi_ready;

    reg         scan_en = 0;
    reg         scan_in = 0;
    wire        scan_out;

    wire        locked;
    reg         unlock_valid = 0;
    reg  [31:0] unlock_code_i = 0;
    reg         relock = 0;
    localparam [31:0] UNLOCK_CODE = 32'hDEC0DED1;

    scan_lock_controller #(.UNLOCK_CODE(UNLOCK_CODE)) u_lock (
        .clk(clk), .resetn(lock_resetn),
        .unlock_valid(unlock_valid), .unlock_code_i(unlock_code_i),
        .relock(relock), .locked(locked)
    );

    aes_pcpi dut (
        .clk(clk), .resetn(resetn),
        .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn),
        .pcpi_rs1(pcpi_rs1), .pcpi_rs2(pcpi_rs2),
        .pcpi_wr(pcpi_wr), .pcpi_rd(pcpi_rd),
        .pcpi_wait(pcpi_wait), .pcpi_ready(pcpi_ready),
        .dbg_key_stage(), .dbg_block_stage(),
        .dbg_core_key_reg(), .dbg_core_round_key_reg(),
        .dbg_core_state_reg(), .dbg_core_round_reg(),
        .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out),
        .locked(locked)
    );

    always #5 clk = ~clk;

    localparam [127:0] KEY       = 128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] PLAINTEXT = 128'h00112233445566778899AABBCCDDEEFF;
    localparam integer SCAN_WIDTH = 645;

    integer errors = 0;
    integer wait_cycles;

    function [31:0] mk_insn(input [2:0] f3);
        mk_insn = {7'b0, 5'b0, 5'b0, f3, 5'b0, `AES_OPCODE};
    endfunction

    task do_pcpi(input [2:0] f3, input [31:0] rs1v, input [31:0] rs2v,
                 output [31:0] rdv, output wrv);
        begin
            @(negedge clk);
            pcpi_valid = 1'b1; pcpi_insn = mk_insn(f3); pcpi_rs1 = rs1v; pcpi_rs2 = rs2v;
            @(posedge clk);
            wait_cycles = 0;
            while (!pcpi_ready) begin
                @(posedge clk);
                wait_cycles = wait_cycles + 1;
                if (wait_cycles > 100) begin
                    $display("ERROR: pcpi_ready timeout f3=%0d", f3);
                    errors = errors + 1;
                    disable do_pcpi;
                end
            end
            #1; rdv = pcpi_rd; wrv = pcpi_wr;
            @(negedge clk); pcpi_valid = 1'b0;
        end
    endtask

    reg [31:0] rd_val; reg wr_val;
    reg [SCAN_WIDTH-1:0] cap;
    integer k;

    task run_case(input lock_val, output [SCAN_WIDTH-1:0] captured);
        begin
            relock = 1; unlock_valid = 0;
            resetn = 0; lock_resetn = 0;
            repeat (3) @(posedge clk);
            #1 resetn = 1; lock_resetn = 1;
            @(posedge clk);
            #1 relock = 0;

            if (!lock_val) begin
                @(negedge clk);
                unlock_code_i = UNLOCK_CODE; unlock_valid = 1'b1;
                @(posedge clk); #1; unlock_valid = 1'b0;
            end

            do_pcpi(`AES_F3_LOADKEY, 32'd0, KEY[127:96], rd_val, wr_val);
            do_pcpi(`AES_F3_LOADKEY, 32'd1, KEY[95:64],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADKEY, 32'd2, KEY[63:32],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADKEY, 32'd3, KEY[31:0],   rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd0, PLAINTEXT[127:96], rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd1, PLAINTEXT[95:64],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd2, PLAINTEXT[63:32],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd3, PLAINTEXT[31:0],   rd_val, wr_val);

            @(negedge clk);
            pcpi_valid = 1'b1; pcpi_insn = mk_insn(`AES_F3_ENCRYPT); pcpi_rs1=0; pcpi_rs2=0;
            @(posedge clk);
            repeat (6) @(posedge clk);
            #1; pcpi_valid = 1'b0;

            scan_en = 1'b1; scan_in = 1'b0;
            captured[SCAN_WIDTH-1] = scan_out;
            for (k = 0; k < SCAN_WIDTH-1; k = k + 1) begin
                @(posedge clk); #1;
                captured[SCAN_WIDTH-2-k] = scan_out;
            end
            scan_en = 1'b0;
        end
    endtask

    initial begin
        $display("============================================================");
        $display("KEY_STAGE / SEGMENT-SCOPE CHECK");
        $display("============================================================");

        // ---- Case 1: UNLOCKED (documented baseline exposure) ----
        run_case(1'b0, cap);
        $display("UNLOCKED: captured[644:517] (key_reg)   = %032h", cap[644:517]);
        $display("UNLOCKED: captured[127:0]   (key_stage) = %032h", cap[127:0]);
        if (cap[127:0] === KEY)
            $display("CONFIRMED: key_stage residue IS present while UNLOCKED (matches Phase 7 baseline finding)");
        else begin
            $display("UNEXPECTED: key_stage residue NOT found while unlocked");
            errors = errors + 1;
        end
        if (cap[644:517] === KEY)
            $display("CONFIRMED: primary key window also recoverable while UNLOCKED (expected -- no protection active)");

        // ---- Case 2: LOCKED (the actual defended configuration) ----
        run_case(1'b1, cap);
        $display("------------------------------------------------------------");
        $display("LOCKED:   captured[644:517] (key_reg)   = %032h", cap[644:517]);
        $display("LOCKED:   captured[127:0]   (key_stage) = %032h", cap[127:0]);
        $display("LOCKED:   full 645-bit capture all-zero? %s", (cap === {SCAN_WIDTH{1'b0}}) ? "YES" : "NO");
        if (cap[127:0] === KEY) begin
            $display("FINDING: key_stage DOES leak while locked -- documented limitation confirmed as-is");
        end else begin
            $display("FINDING: key_stage does NOT leak while locked.");
            $display("         Mechanism: aes_core's seg_out_muxed forces the ENTIRE coprocessor");
            $display("         scan_out to 0 whenever locked=1, not only the round_key_reg/key_reg");
            $display("         window. This masks key_stage as a side effect, but ALSO masks");
            $display("         round_reg/state_reg (the 'AES datapath' segment secure.md Sec.4");
            $display("         depicts as separate from the locked key segment and expected to");
            $display("         remain normally testable). Scope is broader than documented in");
            $display("         both directions: MORE secure for key_stage than claimed, LESS");
            $display("         faithful to the 'only the sensitive segment is masked, rest of");
            $display("         chain stays testable' design intent than claimed.");
        end

        $display("============================================================");
        if (errors == 0) $display("TESTBENCH: ALL CHECKS PASSED (informational findings above, not pass/fail gated)");
        else $display("TESTBENCH: %0d CHECK(S) FAILED", errors);
        $display("============================================================");
        $finish;
    end

    initial begin #400000; $display("TIMEOUT"); $finish; end

endmodule