`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"
// ============================================================================
// tb_attack_matrix.v -- Paper 2 Phase 4: attack x design matrix, G0 vs G1.
//
// One DUT (unmodified aes_pcpi/aes_core). The design under test is selected by
// driving `locked` directly:  G0 = undefended (locked tied 0, same wiring as
// SECURE_SCAN=0),  G1 = Paper 1 lock engaged (locked=1).  Every attack is
// re-run from reset for each design with the same stimulus, and every cell is
// ASSERTED against the expected outcome (no cell is only printed).
//
//   A1  scan-read      : 644-shift capture, key window / any 128-bit window == KEY ?
//   A2  mode-switch    : 389 shifts of 0 (state_reg forced), then bare READRESULT
//                        returns the forced value (ciphertext spoof)?
//   A3  key+pt inject  : 128 shifts of EVIL_KEY, ENCRYPT with no reload,
//                        ciphertext == golden AES(EVIL_KEY, block_stage)?
//   A6  zeroize        : shifts of 0; is key_reg == 0 after 256? after 645?
//   (A4 brute force targets the lock controller, not the datapath: see
//    tb_attack_bruteforce.v / tb_lock_v2.v.  A5 is an appendix extension.)
//
// Expected (from Paper 2 findings): G1 blocks A1 only. A2/A3 succeed in both.
// A6: G1 zeroizes key_reg in 256 shifts, G0 needs a full 645 (measured here).
// The point of the table: G1 changes the READ column and nothing on WRITE.
// ============================================================================
module tb_attack_matrix;
    reg clk = 0, resetn = 0, lk = 0;
    reg pcpi_valid = 0; reg [31:0] pcpi_insn = 0, pcpi_rs1 = 0, pcpi_rs2 = 0;
    wire pcpi_wr, pcpi_wait, pcpi_ready; wire [31:0] pcpi_rd;
    reg scan_en = 0, scan_in = 0; wire scan_out;
    aes_pcpi dut (.clk(clk), .resetn(resetn), .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn),
        .pcpi_rs1(pcpi_rs1), .pcpi_rs2(pcpi_rs2), .pcpi_wr(pcpi_wr), .pcpi_rd(pcpi_rd),
        .pcpi_wait(pcpi_wait), .pcpi_ready(pcpi_ready),
        .dbg_key_stage(), .dbg_block_stage(), .dbg_core_key_reg(), .dbg_core_round_key_reg(),
        .dbg_core_state_reg(), .dbg_core_round_reg(),
        .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out), .locked(lk));
    always #5 clk = ~clk;

    localparam [127:0] KEY  = 128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] EVIL = 128'h0F1E2D3C4B5A69788796A5B4C3D2E1F0;
    localparam [127:0] PT0  = 128'h00112233445566778899AABBCCDDEEFE; // LSB=0 (fsm lands IDLE)
    localparam [127:0] PTK  = 128'h00112233445566778899AABBCCDDEEFF;
    localparam [127:0] GOLD = 128'h50b58e80ce784e98ad48d63390c5dfd7; // AES(EVIL, 000102..0F), pycryptodome-checked
    localparam integer W = 645;

    integer errors = 0, wait_cycles;
    task check(input cond, input [2047:0] msg);
        begin if (!cond) begin $display("FAIL: %0s", msg); errors = errors + 1; end
              else $display("PASS: %0s", msg); end
    endtask
    function [31:0] mk_insn(input [2:0] f3); mk_insn = {7'b0,5'b0,5'b0,f3,5'b0,`AES_OPCODE}; endfunction
    task do_pcpi(input [2:0] f3, input [31:0] rs1v, input [31:0] rs2v, output [31:0] rdv, output wrv);
        begin
            @(negedge clk); pcpi_valid = 1; pcpi_insn = mk_insn(f3); pcpi_rs1 = rs1v; pcpi_rs2 = rs2v;
            @(posedge clk); wait_cycles = 0;
            while (!pcpi_ready) begin @(posedge clk); wait_cycles = wait_cycles + 1;
                if (wait_cycles > 200) begin $display("ERROR: pcpi timeout"); errors = errors + 1; disable do_pcpi; end end
            #1; rdv = pcpi_rd; wrv = pcpi_wr; @(negedge clk); pcpi_valid = 0;
        end
    endtask
    reg [31:0] rd_val; reg wr_val;

    // reset, load KEY + plaintext, optionally issue ENCRYPT and freeze 6 cycles in
    task setup(input lock_val, input [127:0] pt, input freeze);
        begin
            lk = lock_val; resetn = 0; scan_en = 0; scan_in = 0;
            repeat (3) @(posedge clk); #1 resetn = 1; @(posedge clk);
            do_pcpi(`AES_F3_LOADKEY,32'd0,KEY[127:96],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd1,KEY[95:64],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd2,KEY[63:32],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd3,KEY[31:0],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADBLOCK,32'd0,pt[127:96],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADBLOCK,32'd1,pt[95:64],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADBLOCK,32'd2,pt[63:32],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADBLOCK,32'd3,pt[31:0],rd_val,wr_val);
            if (freeze) begin
                @(negedge clk); pcpi_valid = 1; pcpi_insn = mk_insn(`AES_F3_ENCRYPT); pcpi_rs1 = 0; pcpi_rs2 = 0;
                @(posedge clk); repeat (6) @(posedge clk); #1; pcpi_valid = 0;
            end
        end
    endtask

    task shift_n(input integer n, input [127:0] feed128, input use_feed);
        integer k;
        begin
            @(negedge clk); scan_en = 1;
            for (k = 0; k < n; k = k + 1) begin
                scan_in = use_feed ? feed128[127-k] : 1'b0;
                @(negedge clk);
            end
            scan_en = 0;
        end
    endtask

    task read4(output [127:0] ct);
        begin
            do_pcpi(`AES_F3_READRESULT,32'd0,32'h0,rd_val,wr_val); ct[127:96] = rd_val;
            do_pcpi(`AES_F3_READRESULT,32'd1,32'h0,rd_val,wr_val); ct[95:64]  = rd_val;
            do_pcpi(`AES_F3_READRESULT,32'd2,32'h0,rd_val,wr_val); ct[63:32]  = rd_val;
            do_pcpi(`AES_F3_READRESULT,32'd3,32'h0,rd_val,wr_val); ct[31:0]   = rd_val;
        end
    endtask

    // results[design][attack]
    reg a1 [0:1]; reg a2 [0:1]; reg a3 [0:1]; reg a6_256 [0:1]; reg a6_645 [0:1];
    reg [W-1:0] cap; reg [127:0] ct; integer d, k, j; reg leak;

    initial begin
        for (d = 0; d < 2; d = d + 1) begin
            $display("================ design G%0d (%s) ================", d, d ? "Paper-1 lock engaged" : "undefended");
            // ---- A1 scan-read ----
            setup(d == 1, PTK, 1);
            scan_en = 1; scan_in = 0; cap = 0; cap[W-1] = scan_out;
            for (k = 0; k < W-1; k = k + 1) begin @(posedge clk); #1; cap[W-2-k] = scan_out; end
            scan_en = 0;
            leak = 0; for (j = W-1; j >= 127; j = j - 1) if (cap[j -: 128] === KEY) leak = 1;
            a1[d] = leak;
            check((d == 0) ? (leak === 1'b1 && cap[644:517] === KEY) : (leak === 1'b0 && cap[644:517] === 128'h0),
                  (d == 0) ? "A1 G0: key recovered from scan_out" : "A1 G1: BLOCKED, no key window anywhere in the 645-bit stream");
            // ---- A2 mode-switch / ciphertext spoof (state_reg forced to 0, bare READRESULT) ----
            setup(d == 1, PTK, 1);
            shift_n(389, 128'h0, 0);
            read4(ct);
            a2[d] = (ct === 128'h0);
            check(ct === 128'h0, (d == 0) ? "A2 G0: bare READRESULT returns the scan-forced value (spoof)" : "A2 G1: bare READRESULT returns the scan-forced value (spoof) -- NOT blocked");
            // ---- A3 key + plaintext injection ----
            setup(d == 1, PT0, 0);
            shift_n(128, EVIL, 1);
            do_pcpi(`AES_F3_ENCRYPT,32'd0,32'd0,rd_val,wr_val);
            read4(ct);
            a3[d] = (ct === GOLD);
            check(ct === GOLD, (d == 0) ? "A3 G0: encrypts attacker (key,plaintext) = golden ciphertext" : "A3 G1: encrypts attacker (key,plaintext) = golden ciphertext -- NOT blocked");
            // ---- A6 zeroize ----
            setup(d == 1, PTK, 1);
            shift_n(256, 128'h0, 0);
            a6_256[d] = (dut.u_aes_core.key_reg_q === 128'h0);
            setup(d == 1, PTK, 1);
            shift_n(645, 128'h0, 0);
            a6_645[d] = (dut.u_aes_core.key_reg_q === 128'h0 && dut.u_aes_core.round_key_reg_q === 128'h0);
            check(a6_645[d] === 1'b1, "A6: 645 shifts of 0 zeroize round_key_reg+key_reg in BOTH designs");
            check(a6_256[d] === (d == 1), (d == 1) ? "A6 G1: key_reg already zero at 256 shifts (lock's scan-in gate accelerates zeroize)" : "A6 G0: key_reg NOT yet zero at 256 shifts (needs full chain)");
        end

        $display("");
        $display("==================== ATTACK x DESIGN MATRIX (measured) ====================");
        $display("  attack                          | G0 undefended   | G1 Paper-1 lock");
        $display("  A1 scan-read (key recovery)     | %-15s | %s", a1[0] ? "SUCCEEDS" : "blocked", a1[1] ? "SUCCEEDS" : "BLOCKED");
        $display("  A2 mode-switch / ct spoof       | %-15s | %s", a2[0] ? "SUCCEEDS" : "blocked", a2[1] ? "SUCCEEDS" : "BLOCKED");
        $display("  A3 key+plaintext injection      | %-15s | %s", a3[0] ? "SUCCEEDS" : "blocked", a3[1] ? "SUCCEEDS" : "BLOCKED");
        $display("  A6 zeroize key_reg @256 shifts  | %-15s | %s", a6_256[0] ? "zeroed" : "not zeroed", a6_256[1] ? "zeroed" : "not zeroed");
        $display("  A6 zeroize all keys @645 shifts | %-15s | %s", a6_645[0] ? "zeroed" : "not zeroed", a6_645[1] ? "zeroed" : "not zeroed");
        $display("  A4 brute force: see tb_attack_bruteforce.v (v1) / tb_lock_v2.v (L1)");
        $display("===========================================================================");
        if (errors == 0) $display("TESTBENCH: ALL TESTS PASSED"); else $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $finish;
    end
    initial begin #20000000; $display("RESULT: GLOBAL TIMEOUT"); $finish; end
endmodule