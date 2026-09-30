// ============================================================================
// tb_scan_resume.v
//
// Phase 9 Part C (NEW) - Functional resume after scan mode, WITHOUT reset.
//
// Closes the verification gap identified in secure.md ("Current known
// issue" / project master instructions SS20-21,34): tb_scan_lock.v never
// tested whether the coprocessor can perform a fresh, correct encryption
// immediately after a scan session ends, without an intervening resetn
// pulse. All existing functional checks (tb_aes_pcpi.v, tb_scan_lock.v
// Part D) start from a full reset.
//
// ARCHITECTURAL NOTE (read before interpreting results):
//   Requirement A (this test): after scan_en drops, WITHOUT resetn, can
//   the coprocessor still correctly perform a brand-new LOADKEY/LOADBLOCK/
//   ENCRYPT/READRESULT sequence?
//   Requirement B (NOT tested, NOT architecturally possible): resuming
//   the exact interrupted mid-computation. Scan mode overrides every
//   scan_chain register's functional `d` input with `scan_in` -- the
//   pre-scan computation state is unconditionally destroyed by design.
//   This test only asks whether the system comes back HEALTHY, not
//   whether it remembers what it was doing.
//
// SUSPECTED ROOT CAUSE UNDER TEST (static RTL trace, not yet simulated):
//   aes_core.fsm_state (ST_IDLE/RUNNING/DONE) is a PLAIN register, clocked
//   on every posedge clk regardless of scan_en (aes_core.v's FSM always
//   block has no scan_en gating at all). Its RUNNING->DONE transition
//   depends on `is_final_round = (round_reg_q == 4'd10)`, and round_reg_q
//   IS a scan_chain output -- during scan_en=1 it takes on whatever
//   pattern is shifting through it. If that transient pattern equals
//   4'd10 while aes_core.fsm_state==RUNNING, the unscanned FSM commits a
//   spurious RUNNING->DONE transition with no relation to real progress.
//   Separately, aes_pcpi.fsm_state_q IS scanned (u_scan_fsm_state) and
//   will settle to ST_IDLE after a scan_in=0 session -- so aes_pcpi
//   believes IDLE while aes_core may be stuck RUNNING or DONE. Since
//   aes_core's load_key condition is
//     (fsm_state==ST_IDLE && start_i) || (fsm_state==ST_DONE && start_i)
//   a stuck-RUNNING aes_core will silently DROP the next legitimate
//   start_i pulse, ignore the freshly loaded key/plaintext, and instead
//   keep incrementing round_reg_q (now full of scan garbage) until it
//   wraps mod-16 back through 4'd10 -- producing a WRONG ciphertext for
//   what should have been a correct, fresh, post-scan encryption.
//
//   This testbench does not assume that hypothesis is correct. It checks
//   the only externally-observable consequence that matters: does the
//   NEXT legitimate PCPI-driven encryption after a scan session (no
//   reset) reproduce the correct NIST KAT ciphertext?
//
// SWEEP: reuses the same authoritative shift-count boundary set as
// tb_scan_lock.v (0,1,127,255,256,388,517,644,645,1290) so results are
// directly comparable to the existing attack/defense evidence, crossed
// with both LOCKED and UNLOCKED configurations -- the suspected bug path
// (round_reg) sits BEFORE the Phase 8 lock boundary (which only gates
// round_key_reg's scan_in and the final scan_out), so it is expected to
// reproduce identically regardless of lock state. This test confirms or
// refutes that expectation rather than assuming it.
// ============================================================================
`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"

module tb_scan_resume;

    reg clk = 0;
    reg resetn = 0;
    reg lock_resetn = 0;

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

    wire        locked;
    reg         unlock_valid = 0;
    reg  [31:0] unlock_code_i = 32'h0;
    reg         relock = 0;

    localparam [31:0] UNLOCK_CODE = 32'hDEC0DED1;

    scan_lock_controller #(.UNLOCK_CODE(UNLOCK_CODE)) u_lock (
        .clk(clk), .resetn(lock_resetn),
        .unlock_valid(unlock_valid), .unlock_code_i(unlock_code_i),
        .relock(relock),
        .locked(locked)
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

    localparam [127:0] KEY        = 128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] PLAINTEXT  = 128'h00112233445566778899AABBCCDDEEFF;
    localparam [127:0] EXPECTED_CT= 128'h69C4E0D86A7B0430D8CDB78070B4C55A;

    integer errors = 0;
    integer wait_cycles;

    function [31:0] mk_insn(input [2:0] f3);
        mk_insn = {7'b0, 5'b0, 5'b0, f3, 5'b0, `AES_OPCODE};
    endfunction

    // Identical PCPI-driving idiom used throughout the existing suite --
    // unchanged, reused verbatim so this test observes the DUT through
    // exactly the same interface contract as every other testbench.
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

    // Runs ONE full LOADKEY/LOADBLOCK/ENCRYPT/READRESULT KAT sequence
    // through the normal PCPI interface only (no scan, no hierarchical
    // access) and returns the reconstructed ciphertext.
    task run_kat(output [127:0] ct);
        begin
            do_pcpi(`AES_F3_LOADKEY, 32'd0, KEY[127:96], rd_val, wr_val);
            do_pcpi(`AES_F3_LOADKEY, 32'd1, KEY[95:64],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADKEY, 32'd2, KEY[63:32],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADKEY, 32'd3, KEY[31:0],   rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd0, PLAINTEXT[127:96], rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd1, PLAINTEXT[95:64],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd2, PLAINTEXT[63:32],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd3, PLAINTEXT[31:0],   rd_val, wr_val);
            do_pcpi(`AES_F3_ENCRYPT, 32'd0, 32'd0, rd_val, wr_val);
            do_pcpi(`AES_F3_READRESULT, 32'd0, 32'h0, rd_val, wr_val); ct[127:96] = rd_val;
            do_pcpi(`AES_F3_READRESULT, 32'd1, 32'h0, rd_val, wr_val); ct[95:64]  = rd_val;
            do_pcpi(`AES_F3_READRESULT, 32'd2, 32'h0, rd_val, wr_val); ct[63:32]  = rd_val;
            do_pcpi(`AES_F3_READRESULT, 32'd3, 32'h0, rd_val, wr_val); ct[31:0]   = rd_val;
        end
    endtask

    // Informational only: polls AES_STATUS (funct3=100) to report
    // aes_core.busy_o's value through the normal PCPI surface (no
    // hierarchical access). Included purely as diagnostic evidence for
    // WHY a failure happened, not as the pass/fail criterion itself.
    task poll_status(output busy_bit);
        reg [31:0] rd_v; reg wr_v;
        begin
            do_pcpi(`AES_F3_STATUS, 32'd0, 32'd0, rd_v, wr_v);
            busy_bit = rd_v[0];
        end
    endtask

    reg core_busy_after_scan;

    // The full Requirement-A experiment for one (lock_val, n_shifts) point.
    task run_resume_case(input lock_val, input integer n_shifts);
        integer k;
        reg [127:0] ct_after;
        begin
            // ---- Legitimate power-on / initial setup for this case.
            // This resetn pulse is the ONLY reset in this task. It happens
            // BEFORE the scan session, never between scan exit and the
            // post-scan functional attempt -- that boundary is the one
            // under test.
            relock = 1; unlock_valid = 0;
            resetn = 0; lock_resetn = 0;
            repeat (3) @(posedge clk);
            #1 resetn = 1; lock_resetn = 1;
            @(posedge clk);
            #1 relock = 0;

            if (lock_val) begin
                // default fail-safe state is already locked=1; nothing to do
            end else begin
                @(negedge clk);
                unlock_code_i = UNLOCK_CODE;
                unlock_valid  = 1'b1;
                @(posedge clk); #1;
                unlock_valid = 1'b0;
            end

            // ---- Reach the SAME mid-computation point the Phase 7/8
            // attack testbenches use, for direct comparability:
            // load key+plaintext, issue ENCRYPT, freeze 6 cycles in
            // (aes_core.fsm_state==RUNNING, round_reg_q==6 at freeze).
            do_pcpi(`AES_F3_LOADKEY, 32'd0, KEY[127:96], rd_val, wr_val);
            do_pcpi(`AES_F3_LOADKEY, 32'd1, KEY[95:64],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADKEY, 32'd2, KEY[63:32],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADKEY, 32'd3, KEY[31:0],   rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd0, PLAINTEXT[127:96], rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd1, PLAINTEXT[95:64],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd2, PLAINTEXT[63:32],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd3, PLAINTEXT[31:0],   rd_val, wr_val);

            @(negedge clk);
            pcpi_valid = 1'b1;
            pcpi_insn  = mk_insn(`AES_F3_ENCRYPT);
            pcpi_rs1   = 32'h0;
            pcpi_rs2   = 32'h0;
            @(posedge clk);

            repeat (6) @(posedge clk);
            #1;
            pcpi_valid = 1'b0;

            // ---- Enter scan mode, shift n_shifts cycles, exit. This is
            // the ONLY thing that happens between the interrupted
            // computation and the resume attempt.
            scan_en = 1'b1;
            scan_in = 1'b0;
            for (k = 0; k < n_shifts; k = k + 1) begin
                @(posedge clk);
            end
            #1;
            scan_en = 1'b0;

            // ---- NO RESET HERE. This is the boundary under test. ----

            // Diagnostic only: what does aes_core report itself as?
            poll_status(core_busy_after_scan);

            // ---- The actual Requirement-A check: does the coprocessor
            // still correctly perform a brand-new, fully legitimate
            // encryption through the normal PCPI interface?
            run_kat(ct_after);

            $display("---------------------------------------------------------------");
            $display("CASE: locked=%0d  n_shifts=%0d", lock_val, n_shifts);
            $display("  core_busy immediately after scan exit (informational): %0d", core_busy_after_scan);
            $display("  post-scan KAT ciphertext:  %032h", ct_after);
            $display("  expected KAT ciphertext:   %032h", EXPECTED_CT);
            if (ct_after === EXPECTED_CT) begin
                $display("  RESULT: RESUME OK (locked=%0d, n_shifts=%0d)", lock_val, n_shifts);
            end else begin
                $display("  RESULT: RESUME FAILED (locked=%0d, n_shifts=%0d) -- fresh post-scan encryption produced wrong ciphertext without any reset", lock_val, n_shifts);
                errors = errors + 1;
            end
        end
    endtask

    integer shift_points [0:9];
    integer i, lv;

    initial begin
        shift_points[0] = 0;
        shift_points[1] = 1;
        shift_points[2] = 127;
        shift_points[3] = 255;
        shift_points[4] = 256;
        shift_points[5] = 388;
        shift_points[6] = 517;
        shift_points[7] = 644;
        shift_points[8] = 645;
        shift_points[9] = 1290;

        $display("=================================================================");
        $display("PHASE 9 PART C: functional resume after scan, WITHOUT reset");
        $display("=================================================================");

        for (lv = 0; lv < 2; lv = lv + 1) begin
            for (i = 0; i < 10; i = i + 1) begin
                run_resume_case((lv == 1), shift_points[i]);
            end
        end

        $display("=================================================================");
        if (errors == 0)
            $display("TESTBENCH: ALL TESTS PASSED (%0d cases)", 20);
        else
            $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $display("=================================================================");

        $finish;
    end

    initial begin
        #2000000;
        $display("RESULT: GLOBAL TIMEOUT");
        $finish;
    end

endmodule