// ============================================================================
// tb_testability_t2.v  (Paper 2, Phase 7 metric T2)
//
// Chain-integrity (flush) test + stuck-at fault detection in simulation, per
// defense variant. Complements T1 (s5i, testability WHILE LOCKED): T2 shows
// the defenses do NOT harm manufacturing testability when UNLOCKED, and that
// a standard flush test still detects scan-chain stuck-at faults.
//
// FLUSH / CHAIN-INTEGRITY TEST (classic): shift a known 645-bit pattern in
// (scan_en=1), then shift it out feeding 0, capturing scan_out. For an intact
// 645-cell shift register the captured stream equals the pattern. Run with a
// pattern that has both 0->1 and 1->0 transitions on every cell (alternating
// + its complement over two passes) so every cell's stuck-at-0 and stuck-at-1
// would corrupt the stream.
//   - UNLOCKED: every variant must recover all 645 bits (chain fully testable).
//   - LOCKED: recovered bits match T1 (0 for G1/G3/G4; the tail for G2).
//
// STUCK-AT DETECTION: force one scan cell's q_reg to a constant (a stuck-at
// fault) and re-run the UNLOCKED flush test; the fault must corrupt the
// recovered stream (detected). Injected at 5 chain positions x {s-a-0, s-a-1}
// on G1. Demonstration of detectability, not full ATPG coverage.
// ============================================================================
`timescale 1ns/1ps

module t2_flush #(parameter integer DL = 4) (
    output reg done, output reg [31:0] rec_unlocked, output reg [31:0] rec_locked
);
    localparam integer CHAIN = 645;
    reg clk = 0, resetn = 0, scan_en = 0, scan_in = 0, locked = 1;
    wire scan_out;
    wire [127:0] ks, bs, krk, kr, sr; wire [3:0] rr;

    generate if (DL == 0) begin : g_orig
        aes_pcpi dut (.clk(clk), .resetn(resetn),
            .pcpi_valid(1'b0), .pcpi_insn(32'h0), .pcpi_rs1(32'h0), .pcpi_rs2(32'h0),
            .pcpi_wr(), .pcpi_rd(), .pcpi_wait(), .pcpi_ready(),
            .dbg_key_stage(ks), .dbg_block_stage(bs), .dbg_core_key_reg(kr),
            .dbg_core_round_key_reg(krk), .dbg_core_state_reg(sr), .dbg_core_round_reg(rr),
            .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out), .locked(locked));
    end else begin : g_def
        aes_pcpi_def #(.DEFENSE_LEVEL(DL)) dut (.clk(clk), .resetn(resetn),
            .pcpi_valid(1'b0), .pcpi_insn(32'h0), .pcpi_rs1(32'h0), .pcpi_rs2(32'h0),
            .pcpi_wr(), .pcpi_rd(), .pcpi_wait(), .pcpi_ready(),
            .dbg_key_stage(ks), .dbg_block_stage(bs), .dbg_core_key_reg(kr),
            .dbg_core_round_key_reg(krk), .dbg_core_state_reg(sr), .dbg_core_round_reg(rr),
            .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out), .locked(locked));
    end endgenerate

    always #5 clk = ~clk;

    reg [CHAIN-1:0] pat, got;
    integer k;

    reg [CHAIN-1:0] gotA, gotB;
    // one flush pass with a given input vector v; captures into `got`.
    task pass(input lk, input [CHAIN-1:0] v);
        integer i;
        begin
            @(negedge clk); resetn = 0; scan_en = 0; locked = lk;
            repeat (3) @(posedge clk); @(negedge clk); resetn = 1;
            @(negedge clk); scan_en = 1;
            for (i = 0; i < CHAIN; i = i + 1) begin scan_in = v[i]; @(negedge clk); end
            scan_in = 0;
            for (i = 0; i < CHAIN; i = i + 1) begin #1; got[i] = scan_out; @(negedge clk); end
            scan_en = 0;
        end
    endtask

    // Truly-recovered = bits that track the input in BOTH the pattern and its
    // complement. A masked/stuck-constant output matches one pass at its
    // constant positions but not the other, so it nets to 0 (removes the
    // coincidental-match artifact of a single alternating pattern).
    task flush_test(input lk, output [31:0] recovered);
        integer i;
        begin
            pass(lk, pat);  gotA = got;
            pass(lk, ~pat); gotB = got;
            recovered = 0;
            for (i = 0; i < CHAIN; i = i + 1)
                if (gotA[i] === pat[i] && gotB[i] === ~pat[i]) recovered = recovered + 1;
        end
    endtask

    initial begin
        done = 0;
        for (k = 0; k < CHAIN; k = k + 1) pat[k] = k[0];
        flush_test(1'b0, rec_unlocked);
        flush_test(1'b1, rec_locked);
        done = 1;
    end
endmodule

// Dedicated G1 instance with accessible cell paths for stuck-at injection.
module t2_stuckat (output reg done, output reg [31:0] detected, output reg [31:0] injected);
    localparam integer CHAIN = 645;
    reg clk = 0, resetn = 0, scan_en = 0, scan_in = 0, locked = 0;
    wire scan_out;

    aes_pcpi_def #(.DEFENSE_LEVEL(1)) dut (.clk(clk), .resetn(resetn),
        .pcpi_valid(1'b0), .pcpi_insn(32'h0), .pcpi_rs1(32'h0), .pcpi_rs2(32'h0),
        .pcpi_wr(), .pcpi_rd(), .pcpi_wait(), .pcpi_ready(),
        .dbg_key_stage(), .dbg_block_stage(), .dbg_core_key_reg(),
        .dbg_core_round_key_reg(), .dbg_core_state_reg(), .dbg_core_round_reg(),
        .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out), .locked(locked));

    always #5 clk = ~clk;

    reg [CHAIN-1:0] pat, got;
    integer i;

    reg [CHAIN-1:0] gA, gB;
    task sa_pass(input [CHAIN-1:0] v);
        begin
            @(negedge clk); resetn = 0; scan_en = 0;
            repeat (3) @(posedge clk); @(negedge clk); resetn = 1;
            @(negedge clk); scan_en = 1;
            for (i = 0; i < CHAIN; i = i + 1) begin scan_in = v[i]; @(negedge clk); end
            scan_in = 0;
            for (i = 0; i < CHAIN; i = i + 1) begin #1; got[i] = scan_out; @(negedge clk); end
            scan_en = 0;
        end
    endtask
    task run_flush(output [31:0] recovered);
        begin
            sa_pass(pat);  gA = got;
            sa_pass(~pat); gB = got;
            recovered = 0;
            for (i = 0; i < CHAIN; i = i + 1)
                if (gA[i] === pat[i] && gB[i] === ~pat[i]) recovered = recovered + 1;
        end
    endtask

    reg [31:0] r;
    task one_fault(input val, input [8*40-1:0] where);
        begin
            injected = injected + 1;
            run_flush(r);
            if (r < CHAIN) begin detected = detected + 1;
                $display("PASS: stuck-at-%0d at %0s detected (flush recovered %0d/645)", val, where, r); end
            else $display("FAIL: stuck-at-%0d at %0s NOT detected", val, where);
        end
    endtask

    initial begin
        done = 0; detected = 0; injected = 0;
        for (i = 0; i < CHAIN; i = i + 1) pat[i] = i[0];
        // baseline: no fault -> full recovery
        run_flush(r);
        if (r === CHAIN) $display("PASS: G1 unlocked flush recovers 645/645 (chain intact, no fault)");
        else             $display("FAIL: G1 unlocked baseline flush recovered %0d/645", r);
        // inject stuck-at at representative cells (front key_stage, block_stage,
        // core state_reg, round_key_reg boundary, back key_reg), both polarities.
        force dut.u_scan_key_stage.g_bit[0].u_cell.q_reg   = 1'b0; one_fault(0, "key_stage[0]");            release dut.u_scan_key_stage.g_bit[0].u_cell.q_reg;
        force dut.u_scan_key_stage.g_bit[0].u_cell.q_reg   = 1'b1; one_fault(1, "key_stage[0]");            release dut.u_scan_key_stage.g_bit[0].u_cell.q_reg;
        force dut.u_scan_block_stage.g_bit[64].u_cell.q_reg= 1'b0; one_fault(0, "block_stage[64]");         release dut.u_scan_block_stage.g_bit[64].u_cell.q_reg;
        force dut.u_scan_block_stage.g_bit[64].u_cell.q_reg= 1'b1; one_fault(1, "block_stage[64]");         release dut.u_scan_block_stage.g_bit[64].u_cell.q_reg;
        force dut.u_aes_core.u_scan_state_reg.g_bit[127].u_cell.q_reg = 1'b0; one_fault(0, "state_reg[127]");   release dut.u_aes_core.u_scan_state_reg.g_bit[127].u_cell.q_reg;
        force dut.u_aes_core.u_scan_state_reg.g_bit[127].u_cell.q_reg = 1'b1; one_fault(1, "state_reg[127]");   release dut.u_aes_core.u_scan_state_reg.g_bit[127].u_cell.q_reg;
        force dut.u_aes_core.u_scan_round_key_reg.g_bit[0].u_cell.q_reg = 1'b0; one_fault(0, "round_key_reg[0]"); release dut.u_aes_core.u_scan_round_key_reg.g_bit[0].u_cell.q_reg;
        force dut.u_aes_core.u_scan_round_key_reg.g_bit[0].u_cell.q_reg = 1'b1; one_fault(1, "round_key_reg[0]"); release dut.u_aes_core.u_scan_round_key_reg.g_bit[0].u_cell.q_reg;
        force dut.u_aes_core.u_scan_key_reg.g_bit[127].u_cell.q_reg = 1'b0; one_fault(0, "key_reg[127]");     release dut.u_aes_core.u_scan_key_reg.g_bit[127].u_cell.q_reg;
        force dut.u_aes_core.u_scan_key_reg.g_bit[127].u_cell.q_reg = 1'b1; one_fault(1, "key_reg[127]");     release dut.u_aes_core.u_scan_key_reg.g_bit[127].u_cell.q_reg;
        done = 1;
    end
endmodule

module tb_testability_t2;
    wire [5:0] fd;
    wire [31:0] ru [0:5], rl [0:5];
    genvar g;
    generate for (g = 0; g <= 5; g = g + 1) begin : gr
        t2_flush #(.DL(g)) r (.done(fd[g]), .rec_unlocked(ru[g]), .rec_locked(rl[g]));
    end endgenerate

    wire sdone; wire [31:0] sdet, sinj;
    t2_stuckat s (.done(sdone), .detected(sdet), .injected(sinj));

    integer errors = 0, g2exp;
    initial begin
        wait ((&fd === 1'b1) && (sdone === 1'b1));
        #1;
        $display("");
        $display("===== T2 CHAIN-INTEGRITY (FLUSH) + STUCK-AT (measured) =====");
        $display("  variant : flush recovered unlocked / locked (of 645)");
        $display("    G0(DL0)=%0d/%0d  G1=%0d/%0d  G2=%0d/%0d  G3=%0d/%0d  G4=%0d/%0d  G2R=%0d/%0d",
                 ru[0],rl[0], ru[1],rl[1], ru[2],rl[2], ru[3],rl[3], ru[4],rl[4], ru[5],rl[5]);
        // Assertion 1: every variant fully testable UNLOCKED.
        for (g2exp = 0; g2exp <= 5; g2exp = g2exp + 1)
            if (ru[g2exp] !== 645) begin $display("FAIL: variant DL=%0d not fully testable unlocked (%0d/645)", g2exp, ru[g2exp]); errors = errors + 1; end
        if (errors == 0) $display("PASS: all variants recover 645/645 UNLOCKED (defenses preserve test mode)");
        // Assertion 2: G4 gives up ALL chain testability while locked (0 recovered).
        if (rl[4] !== 0) begin $display("FAIL: G4 locked recovered %0d (expected 0)", rl[4]); errors = errors + 1; end
        else $display("PASS: G4 locked flush recovers 0/645 (chain frozen; the T1 trade-off)");
        // Assertion 3: G1 locked recovers 0 (scan_out masked).
        if (rl[1] !== 0) begin $display("FAIL: G1 locked recovered %0d (expected 0, masked)", rl[1]); errors = errors + 1; end
        else $display("PASS: G1 locked flush recovers 0/645 (scan_out masked)");
        // Stuck-at
        $display("  stuck-at faults injected=%0d detected=%0d", sinj, sdet);
        if (sdet !== sinj || sinj !== 10) begin $display("FAIL: stuck-at detection %0d/%0d (expected 10/10)", sdet, sinj); errors = errors + 1; end
        else $display("PASS: all 10 injected stuck-at faults detected by the flush test");

        if (errors == 0) $display("TESTBENCH: ALL TESTS PASSED");
        else             $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $finish;
    end
    initial begin #4000000; $display("RESULT: GLOBAL TIMEOUT"); $finish; end
endmodule
