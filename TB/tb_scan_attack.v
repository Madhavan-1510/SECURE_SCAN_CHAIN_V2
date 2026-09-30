// ============================================================================
// tb_scan_attack.v
//
// Phase 7 - Baseline Automated Scan Attack
//
// Demonstrates that the AES-128 master key, while resident in aes_core's
// key_reg during active encryption, can be recovered purely from the
// coprocessor's external scan interface (scan_en/scan_in/scan_out) -- no
// hierarchical access to key_reg is used for the recovery itself.
//
// Reuses, unchanged:
//   - the PCPI stimulus idiom from tb_aes_pcpi.v (mk_insn / do_pcpi)
//   - the authoritative scan capture rule from tb_scan_chain.v Check 3
//     (1 pre-shift sample + (WIDTH-1) post-edge samples)
//   - the authoritative 645-bit global scan map from secure.md Section 14:
//       key_stage      [127:0]
//       block_stage    [255:128]
//       fsm_state      [256]
//       round_reg      [260:257]
//       state_reg      [388:261]
//       round_key_reg  [516:389]   SENSITIVE
//       key_reg        [644:517]   SENSITIVE
// ============================================================================
`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"

module tb_scan_attack;

    reg clk = 0;
    reg resetn = 0;

    reg         pcpi_valid = 0;
    reg  [31:0] pcpi_insn  = 32'h0;
    reg  [31:0] pcpi_rs1   = 32'h0;
    reg  [31:0] pcpi_rs2   = 32'h0;
    wire        pcpi_wr;
    wire [31:0] pcpi_rd;
    wire        pcpi_wait;
    wire        pcpi_ready;

    reg         scan_en = 0;
    reg         scan_in = 0;
    wire        scan_out;

    aes_pcpi dut (
        .clk(clk), .resetn(resetn),
        .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn),
        .pcpi_rs1(pcpi_rs1), .pcpi_rs2(pcpi_rs2),
        .pcpi_wr(pcpi_wr), .pcpi_rd(pcpi_rd),
        .pcpi_wait(pcpi_wait), .pcpi_ready(pcpi_ready),
        // Debug taps intentionally left unconnected: the attack does NOT
        // rely on hierarchical/debug access for recovery.
        .dbg_key_stage(), .dbg_block_stage(),
        .dbg_core_key_reg(), .dbg_core_round_key_reg(),
        .dbg_core_state_reg(), .dbg_core_round_reg(),
        .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out),
        // Phase 8 added a `locked` port to aes_pcpi/aes_core after this
        // Phase 7 testbench was written. Tying it to 0 (unlocked) is the
        // correct representation of "no defense present yet" -- this is
        // the pre-Phase-8 baseline this testbench is meant to capture,
        // and with locked=0 the scan wiring is bit-for-bit identical to
        // the original Phase 6 chain (see aes_core.v Phase 8 comments).
        .locked(1'b0)
    );

    always #5 clk = ~clk;

    localparam [127:0] KEY       = 128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] PLAINTEXT = 128'h00112233445566778899AABBCCDDEEFF;

    localparam integer SCAN_WIDTH = 645;
    // Authoritative global offsets, secure.md Section 14 -- do not change
    // without a full Phase 6 re-verification.
    localparam integer KEY_REG_HI = 644;
    localparam integer KEY_REG_LO = 517;

    integer errors = 0;
    integer wait_cycles;

    function [31:0] mk_insn(input [2:0] f3);
        mk_insn = {7'b0, 5'b0, 5'b0, f3, 5'b0, `AES_OPCODE};
    endfunction

    // Identical PCPI-driving idiom to tb_aes_pcpi.v -- unchanged.
    task do_pcpi(input [2:0] f3, input [31:0] rs1v, input [31:0] rs2v,
                 output [31:0] rdv, output wrv);
        begin
            @(negedge clk);
            pcpi_valid = 1'b1;
            pcpi_insn  = mk_insn(f3);
            pcpi_rs1   = rs1v;
            pcpi_rs2   = rs2v;
            @(posedge clk);
            wait_cycles = 0;
            while (!pcpi_ready) begin
                @(posedge clk);
                wait_cycles = wait_cycles + 1;
                if (wait_cycles > 100) begin
                    $display("ERROR: pcpi_ready never asserted (timeout) for f3=%0d", f3);
                    errors = errors + 1;
                    disable do_pcpi;
                end
            end
            #1;
            rdv = pcpi_rd;
            wrv = pcpi_wr;
            @(negedge clk);
            pcpi_valid = 1'b0;
        end
    endtask

    reg [31:0] rd_val;
    reg        wr_val;

    reg [SCAN_WIDTH-1:0] captured;
    reg [127:0]          recovered_key;
    integer i;

    initial begin
        resetn = 0;
        repeat (3) @(posedge clk);
        #1 resetn = 1;
        @(posedge clk);

        // ---- Step 2: functional key load (normal PCPI, unchanged) ----
        do_pcpi(`AES_F3_LOADKEY, 32'd0, KEY[127:96], rd_val, wr_val);
        do_pcpi(`AES_F3_LOADKEY, 32'd1, KEY[95:64],  rd_val, wr_val);
        do_pcpi(`AES_F3_LOADKEY, 32'd2, KEY[63:32],  rd_val, wr_val);
        do_pcpi(`AES_F3_LOADKEY, 32'd3, KEY[31:0],   rd_val, wr_val);
        $display("STEP 2: AES-128 master key loaded via 4x AES_LOADKEY words");

        // ---- Step 3: functional plaintext load ----
        do_pcpi(`AES_F3_LOADBLOCK, 32'd0, PLAINTEXT[127:96], rd_val, wr_val);
        do_pcpi(`AES_F3_LOADBLOCK, 32'd1, PLAINTEXT[95:64],  rd_val, wr_val);
        do_pcpi(`AES_F3_LOADBLOCK, 32'd2, PLAINTEXT[63:32],  rd_val, wr_val);
        do_pcpi(`AES_F3_LOADBLOCK, 32'd3, PLAINTEXT[31:0],   rd_val, wr_val);
        $display("STEP 3: plaintext loaded via 4x AES_LOADBLOCK words");

        // ---- Step 4: start encryption. Do NOT wait for pcpi_ready -- the
        // attacker interrupts mid-computation instead of letting it finish. ----
        @(negedge clk);
        pcpi_valid = 1'b1;
        pcpi_insn  = mk_insn(`AES_F3_ENCRYPT);
        pcpi_rs1   = 32'h0;
        pcpi_rs2   = 32'h0;
        @(posedge clk);
        #1;
        if (pcpi_wait !== 1'b1) begin
            $display("RESULT: FAIL - AES_ENCRYPT did not assert pcpi_wait, cannot proceed with attack");
            errors = errors + 1;
        end
        $display("STEP 4: AES_ENCRYPT issued, core now computing");

        // ---- Step 5: freeze mid-computation. AES-128 takes ~11 cycles total
        // (1 load-key cycle + 10 rounds). Six cycles after issuing ENCRYPT
        // lands well inside RUNNING (round_reg == 6), far from completion.
        // This is a fixed cycle count relative to a self-triggered
        // instruction -- no secret-dependent or hierarchical timing probe
        // is used. ----
        repeat (6) @(posedge clk);
        #1;
        pcpi_valid = 1'b0; // attacker halts further functional interaction
        $display("STEP 5: encryption frozen mid-computation (6 cycles after ENCRYPT issued)");

        // ---- Step 6: enable scan. From this point, every scanned cell's
        // next state comes from scan_in, not from its functional d input --
        // functional progression of the scanned registers stops here. ----
        scan_en = 1'b1;
        scan_in = 1'b0;
        $display("STEP 6: scan_en asserted -- scan cells now shift instead of updating functionally");

        // ---- Steps 7-8: capture + reconstruct the 645-bit segment.
        // Authoritative rule (secure.md Sec.17 / tb_scan_chain.v Check 3):
        // scan_out is a combinational tap on the current LAST cell, visible
        // BEFORE the first scan clock edge. Reconstruction needs exactly
        // 1 pre-shift sample + (SCAN_WIDTH-1) post-edge samples. ----
        captured[SCAN_WIDTH-1] = scan_out; // pre-shift: global bit 644 = key_reg[127]
        for (i = 0; i < SCAN_WIDTH-1; i = i + 1) begin
            @(posedge clk);
            #1;
            captured[SCAN_WIDTH-2-i] = scan_out;
        end
        scan_en = 1'b0;
        $display("STEP 7/8: captured full %0d-bit scan segment (1 pre-shift sample + %0d shifts)",
                  SCAN_WIDTH, SCAN_WIDTH-1);

        // ---- Step 9: extract the key from the known, authoritative offset ----
        recovered_key = captured[KEY_REG_HI:KEY_REG_LO];

        // ---- Step 10: compare ----
        $display("============================================");
        $display("BASELINE SCAN ATTACK");
        $display("Scan width: %0d bits", SCAN_WIDTH);
        $display("AES key location: [%0d:%0d]", KEY_REG_HI, KEY_REG_LO);
        $display("Original key:   %032h", KEY);
        $display("Recovered key:  %032h", recovered_key);

        if (recovered_key === KEY) begin
            $display("RESULT: KEY RECOVERY SUCCESS");
        end else begin
            $display("RESULT: KEY RECOVERY FAILURE");
            errors = errors + 1;
        end
        $display("============================================");

        // ---- Optional Step 25: exhaustive secondary search across every
        // 128-bit window of the captured stream (expected: exactly one
        // match, at [644:517]) ----
        begin : secondary_search
            integer j;
            integer matches;
            reg [127:0] window;
            matches = 0;
            for (j = SCAN_WIDTH-1; j >= 127; j = j - 1) begin
                window = captured[j -: 128];
                if (window === KEY) begin
                    $display("SECONDARY SEARCH: key pattern found at captured[%0d:%0d]", j, j-127);
                    matches = matches + 1;
                end
            end
            $display("SECONDARY SEARCH: %0d matching window(s) found", matches);
        end

        if (errors == 0)
            $display("TESTBENCH: ALL TESTS PASSED");
        else
            $display("TESTBENCH: %0d TEST(S) FAILED", errors);

        $finish;
    end

    initial begin
        #20000;
        $display("RESULT: GLOBAL TIMEOUT");
        $finish;
    end

endmodule