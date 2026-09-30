`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"
// ============================================================================
// tb_defense_equiv.v -- lockstep equivalence, Paper 2 Phase 5.
//
// Claim under test: with locked=0, EVERY defense level (aes_pcpi_def L1..L5) is
// cycle-for-cycle indistinguishable from the original undefended aes_pcpi on all
// observable outputs (pcpi_wr/rd/wait/ready, scan_out, and all 6 dbg_* taps),
// under the same random PCPI + random scan stimulus (scan bursts land while the
// core is idle AND while it is RUNNING). Also: L1 (Paper 1 lock) with locked=1 is
// bit-identical to the original aes_pcpi with locked=1 (the variant file did not
// disturb Paper 1's behaviour).
// Outputs are compared twice per cycle (just before posedge, just after).
// Stimulus is driven on negedge. A stats check proves the stimulus actually
// exercised scan shifting, PCPI completions and >=1 finished encryption.
// ============================================================================
module tb_defense_equiv #(parameter integer NCYC = 900);
    reg clk = 0; always #5 clk = ~clk;
    reg resetn = 0;
    reg pcpi_valid = 0; reg [31:0] pcpi_insn = 0, pcpi_rs1 = 0, pcpi_rs2 = 0;
    reg scan_en = 0, scan_in = 0;

    // outputs bundle: {wr, rd[31:0], wait, ready, scan_out, key_stage, block_stage, key, rk, st, round}
    localparam BW = 1 + 32 + 1 + 1 + 1 + 128*5 + 4;
    wire [BW-1:0] O [0:6];   // 0 = ref(unlocked); 1..5 = L1..L5 (unlocked); 6 = ref(locked)
    wire [BW-1:0] P1;        // L1 locked

    genvar g;
    generate
      for (g = 0; g < 7; g = g + 1) begin : d
        wire wr, wt, rdy, so; wire [31:0] rd;
        wire [127:0] ks, bs, kr, rk, st; wire [3:0] rr;
        if (g == 0 || g == 6) begin : o
          aes_pcpi dut (.clk(clk), .resetn(resetn), .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn),
            .pcpi_rs1(pcpi_rs1), .pcpi_rs2(pcpi_rs2), .pcpi_wr(wr), .pcpi_rd(rd), .pcpi_wait(wt), .pcpi_ready(rdy),
            .dbg_key_stage(ks), .dbg_block_stage(bs), .dbg_core_key_reg(kr), .dbg_core_round_key_reg(rk),
            .dbg_core_state_reg(st), .dbg_core_round_reg(rr),
            .scan_en(scan_en), .scan_in(scan_in), .scan_out(so), .locked(g == 6));
        end else begin : o
          aes_pcpi_def #(.DEFENSE_LEVEL(g)) dut (.clk(clk), .resetn(resetn), .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn),
            .pcpi_rs1(pcpi_rs1), .pcpi_rs2(pcpi_rs2), .pcpi_wr(wr), .pcpi_rd(rd), .pcpi_wait(wt), .pcpi_ready(rdy),
            .dbg_key_stage(ks), .dbg_block_stage(bs), .dbg_core_key_reg(kr), .dbg_core_round_key_reg(rk),
            .dbg_core_state_reg(st), .dbg_core_round_reg(rr),
            .scan_en(scan_en), .scan_in(scan_in), .scan_out(so), .locked(1'b0));
        end
        assign O[g] = {wr, rd, wt, rdy, so, ks, bs, kr, rk, st, rr};
      end
    endgenerate
    // L1 locked
    wire wr1, wt1, rdy1, so1; wire [31:0] rd1; wire [127:0] ks1, bs1, kr1, rk1, st1; wire [3:0] rr1;
    aes_pcpi_def #(.DEFENSE_LEVEL(1)) dl1 (.clk(clk), .resetn(resetn), .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn),
        .pcpi_rs1(pcpi_rs1), .pcpi_rs2(pcpi_rs2), .pcpi_wr(wr1), .pcpi_rd(rd1), .pcpi_wait(wt1), .pcpi_ready(rdy1),
        .dbg_key_stage(ks1), .dbg_block_stage(bs1), .dbg_core_key_reg(kr1), .dbg_core_round_key_reg(rk1),
        .dbg_core_state_reg(st1), .dbg_core_round_reg(rr1),
        .scan_en(scan_en), .scan_in(scan_in), .scan_out(so1), .locked(1'b1));
    assign P1 = {wr1, rd1, wt1, rdy1, so1, ks1, bs1, kr1, rk1, st1, rr1};

    integer mism [0:5];
    integer i;
    integer ci;
    task compare;
        begin
            for (ci = 1; ci <= 5; ci = ci + 1) if (O[ci] !== O[0]) mism[ci-1] = mism[ci-1] + 1;
            if (P1 !== O[6]) mism[5] = mism[5] + 1;
        end
    endtask
    always @(posedge clk) begin #1 compare; end
    always @(negedge clk) begin #4 compare; end

    // stats (from the reference)
    integer scan_cycles = 0, ready_pulses = 0, done_seen = 0, aes_valid = 0, scan_run = 0, scan_idle = 0;
    reg done_seen_q = 0;
    always @(posedge clk) begin
        if (resetn) begin
            if (scan_en) scan_cycles = scan_cycles + 1;
            if (scan_en && d[0].o.dut.core_busy) scan_run = scan_run + 1;
            if (scan_en && !d[0].o.dut.core_busy) scan_idle = scan_idle + 1;
            if (d[0].rdy) ready_pulses = ready_pulses + 1;
            if (d[0].o.dut.core_done && !done_seen_q) done_seen = done_seen + 1;
            if (pcpi_valid && pcpi_insn[6:0] == `AES_OPCODE) aes_valid = aes_valid + 1;
        end
    end
    always @(posedge clk) done_seen_q <= d[0].o.dut.core_done;

    reg [31:0] r; reg [2:0] f3r; integer n, seed;
    integer errors = 0;
    initial begin
        seed = 32'hC0FFEE11;
        for (i = 0; i < 6; i = i + 1) mism[i] = 0;
        resetn = 0; repeat (3) @(negedge clk); resetn = 1;
        for (n = 0; n < NCYC; n = n + 1) begin
            @(negedge clk);
            r = $random(seed);
            pcpi_valid = (r[1:0] != 2'd0);
            f3r = r[18:16] % 6;   // funct3 0..5 (5 = reserved, must be ignored identically)
            pcpi_insn  = {7'b0, r[9:5], r[14:10], f3r, 5'b0, (r[21:19] == 3'd0) ? 7'b0110011 : `AES_OPCODE};
            r = $random(seed);
            pcpi_rs1 = r; pcpi_rs2 = $random(seed);
            // scan_en: sticky, flips with prob 1/24; bias toward ONE burst that starts while core is running
            if (($random(seed) & 32'h1F) == 0) scan_en = ~scan_en;
            scan_in = $random(seed);
            if (n == 3) resetn = 1;
        end
        @(negedge clk); scan_en = 0; pcpi_valid = 0; @(negedge clk);
        $display("stimulus stats: scan_en cycles=%0d  AES-op cycles=%0d  ready pulses=%0d  core completions=%0d", scan_cycles, aes_valid, ready_pulses, done_seen);
        for (i = 0; i < 5; i = i + 1) begin
            if (mism[i] != 0) begin $display("FAIL: level %0d (unlocked) differs from undefended aes_pcpi on %0d sample(s)", i+1, mism[i]); errors = errors + 1; end
            else $display("PASS: level %0d (unlocked) cycle-identical to undefended aes_pcpi over %0d cycles (2 samples/cycle, all outputs)", i+1, NCYC);
        end
        if (mism[5] != 0) begin $display("FAIL: L1 locked differs from original aes_pcpi locked on %0d sample(s)", mism[5]); errors = errors + 1; end
        else $display("PASS: L1 (locked) cycle-identical to original aes_pcpi (locked) over %0d cycles", NCYC);
        if (scan_cycles < 100) begin $display("FAIL: stimulus exercised too little scan (%0d cycles)", scan_cycles); errors = errors + 1; end
        else $display("PASS: stimulus exercised scan shifting (%0d cycles)", scan_cycles);
        $display("scan cycles while ref core RUNNING=%0d, while not running=%0d", scan_run, scan_idle);
        if (scan_run < 5 || scan_idle < 5) begin $display("FAIL: scan bursts did not land both while running and while idle"); errors = errors + 1; end
        else $display("PASS: scan shifting exercised both while the core is running and while idle");
        if (ready_pulses < 20 || done_seen < 1) begin $display("FAIL: stimulus exercised too little PCPI/AES activity"); errors = errors + 1; end
        else $display("PASS: stimulus exercised PCPI completions and >=1 finished encryption");
        if (errors == 0) $display("TESTBENCH: ALL TESTS PASSED"); else $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $finish;
    end
    initial begin #50000000; $display("RESULT: GLOBAL TIMEOUT"); $finish; end
endmodule