`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"
// ============================================================================
// tb_scan_lock_v2.v -- Paper 2 Phase 2. scan_lock_controller_v2 (L1) driving the
// UNMODIFIED aes_pcpi/aes_core through the same `locked` wire as v1.
// Reuses tb_scan_lock.v's Phase-7 read-attack procedure unchanged.
//
//   A  boot delay: correct secret presented inside the boot delay is ignored;
//      Phase-7 attack at 0..1290 shifts recovers nothing (window + full stream)
//   B  v1 public default DEC0DED1 is rejected
//   C  real secret unlocks; attack then recovers the KAT key (== Phase 7)
//   D  MAX_FAILS wrong codes -> lockout; correct code rejected during lockout;
//      attack still all-zero; after expiry the correct code unlocks
//   E  functional KAT bit-exact while locked, in lockout, and unlocked
// Only the lock controller is reset (lock_resetn) to change lock state; run_attack
// resets the AES datapath (resetn) only, exactly like tb_scan_lock.v.
// ============================================================================
module tb_scan_lock_v2;
    reg clk = 0, resetn = 0, lock_resetn = 0;
    reg pcpi_valid = 0; reg [31:0] pcpi_insn = 0, pcpi_rs1 = 0, pcpi_rs2 = 0;
    wire pcpi_wr, pcpi_wait, pcpi_ready; wire [31:0] pcpi_rd;
    reg scan_en = 0, scan_in = 0; wire scan_out;
    wire locked, lockout;
    reg unlock_valid = 0; reg [31:0] unlock_code_i = 0; reg relock = 0;

    localparam [31:0] SECRET = 32'hA5C31F7E;
    localparam integer MF = 3, LO = 5000, BD = 20;

    scan_lock_controller_v2 #(.MAX_FAILS(MF), .LOCKOUT_CYCLES(LO), .BOOT_DELAY_CYCLES(BD), .HARD_LOCKOUT(1'b0)) u_lock (
        .clk(clk), .resetn(lock_resetn), .unlock_valid(unlock_valid), .unlock_code_i(unlock_code_i),
        .secret_i(SECRET), .secret_valid_i(1'b1), .relock(relock), .locked(locked), .lockout_o(lockout));

    aes_pcpi dut (
        .clk(clk), .resetn(resetn), .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn),
        .pcpi_rs1(pcpi_rs1), .pcpi_rs2(pcpi_rs2), .pcpi_wr(pcpi_wr), .pcpi_rd(pcpi_rd),
        .pcpi_wait(pcpi_wait), .pcpi_ready(pcpi_ready),
        .dbg_key_stage(), .dbg_block_stage(), .dbg_core_key_reg(), .dbg_core_round_key_reg(),
        .dbg_core_state_reg(), .dbg_core_round_reg(),
        .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out), .locked(locked));

    always #5 clk = ~clk;

    localparam [127:0] KEY = 128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] PLAINTEXT = 128'h00112233445566778899AABBCCDDEEFF;
    localparam [127:0] EXPECTED_CT = 128'h69C4E0D86A7B0430D8CDB78070B4C55A;
    localparam integer SCAN_WIDTH = 645;

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
            while (!pcpi_ready) begin
                @(posedge clk); wait_cycles = wait_cycles + 1;
                if (wait_cycles > 100) begin $display("ERROR: pcpi timeout f3=%0d", f3); errors = errors + 1; disable do_pcpi; end
            end
            #1; rdv = pcpi_rd; wrv = pcpi_wr; @(negedge clk); pcpi_valid = 0;
        end
    endtask

    reg [31:0] rd_val; reg wr_val;

    task load_kat;
        begin
            do_pcpi(`AES_F3_LOADKEY,32'd0,KEY[127:96],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd1,KEY[95:64],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd2,KEY[63:32],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd3,KEY[31:0],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADBLOCK,32'd0,PLAINTEXT[127:96],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADBLOCK,32'd1,PLAINTEXT[95:64],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADBLOCK,32'd2,PLAINTEXT[63:32],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADBLOCK,32'd3,PLAINTEXT[31:0],rd_val,wr_val);
        end
    endtask

    task run_attack(input integer n_shifts, output [127:0] recovered, output [SCAN_WIDTH-1:0] full_capture);
        integer k; reg [SCAN_WIDTH-1:0] cap;
        begin
            resetn = 0; scan_en = 0; scan_in = 0;
            repeat (3) @(posedge clk); #1 resetn = 1; @(posedge clk);
            load_kat;
            @(negedge clk); pcpi_valid = 1; pcpi_insn = mk_insn(`AES_F3_ENCRYPT); pcpi_rs1 = 0; pcpi_rs2 = 0;
            @(posedge clk); repeat (6) @(posedge clk); #1; pcpi_valid = 0;
            scan_en = 1; scan_in = 0;
            cap = {SCAN_WIDTH{1'b0}}; cap[SCAN_WIDTH-1] = scan_out;
            for (k = 0; k < n_shifts; k = k + 1) begin
                @(posedge clk); #1;
                if (SCAN_WIDTH-2-k >= 0) cap[SCAN_WIDTH-2-k] = scan_out;
            end
            scan_en = 0;
            full_capture = cap; recovered = cap[644:517];
        end
    endtask

    task run_kat(output [127:0] ct);
        begin
            resetn = 0; scan_en = 0; scan_in = 0;
            repeat (3) @(posedge clk); #1 resetn = 1; @(posedge clk);
            load_kat;
            do_pcpi(`AES_F3_ENCRYPT,32'd0,32'd0,rd_val,wr_val);
            do_pcpi(`AES_F3_READRESULT,32'd0,32'h0,rd_val,wr_val); ct[127:96] = rd_val;
            do_pcpi(`AES_F3_READRESULT,32'd1,32'h0,rd_val,wr_val); ct[95:64]  = rd_val;
            do_pcpi(`AES_F3_READRESULT,32'd2,32'h0,rd_val,wr_val); ct[63:32]  = rd_val;
            do_pcpi(`AES_F3_READRESULT,32'd3,32'h0,rd_val,wr_val); ct[31:0]   = rd_val;
        end
    endtask

    // reset the LOCK controller only (fail-safe locked, boot delay re-armed)
    task lock_reset;
        begin @(negedge clk); lock_resetn = 0; unlock_valid = 0; relock = 0; repeat (3) @(negedge clk); lock_resetn = 1; end
    endtask
    task present(input [31:0] c);
        begin unlock_valid = 1; unlock_code_i = c; @(negedge clk); unlock_valid = 0; end
    endtask

    reg [127:0] rec, ct; reg [SCAN_WIDTH-1:0] full_cap; reg any_leak;
    integer sp [0:9]; integer i, j, leaks;

    initial begin
        sp[0]=0; sp[1]=1; sp[2]=127; sp[3]=255; sp[4]=256; sp[5]=388; sp[6]=517; sp[7]=644; sp[8]=645; sp[9]=1290;
        resetn = 0; lock_resetn = 0; repeat (3) @(posedge clk); #1 resetn = 1; @(negedge clk);

        // ---------------- A ----------------
        $display("=== A: locked out of reset + boot delay; Phase-7 attack ===");
        lock_reset;
        check(locked === 1'b1 && lockout === 1'b1, "A locked=1 and boot delay active right after reset release");
        present(SECRET);     // inside the boot delay
        check(locked === 1'b1, "A correct secret presented INSIDE the boot delay is ignored");
        leaks = 0;
        for (i = 0; i < 10; i = i + 1) begin
            run_attack(sp[i], rec, full_cap);
            if (rec === KEY) leaks = leaks + 1;
            for (j = SCAN_WIDTH-1; j >= 127; j = j - 1) if (full_cap[j -: 128] === KEY) leaks = leaks + 1;
            if (sp[i] == 0 && full_cap[SCAN_WIDTH-1] !== 1'b0) leaks = leaks + 1;
        end
        check(leaks === 0, "A locked: key window and every 128-bit window of the full stream clean at 0,1,127,255,256,388,517,644,645,1290 shifts; zero-shift sample masked");
        run_attack(SCAN_WIDTH-1, rec, full_cap);
        check(rec === 128'h0, "A locked: captured[644:517] is all-zero at 644 shifts");
        $display("  captured[644:517] (locked) = %032h", rec);

        // ---------------- B ----------------
        $display("=== B: v1 public default rejected ===");
        lock_reset; repeat (BD + 2) @(negedge clk);
        present(32'hDEC0DED1);
        check(locked === 1'b1, "B DEC0DED1 does not unlock v2");
        run_attack(SCAN_WIDTH-1, rec, full_cap);
        check(rec !== KEY && rec === 128'h0, "B key not recoverable after the DEC0DED1 attempt");

        // ---------------- C ----------------
        $display("=== C: real secret unlocks; attack == Phase 7 ===");
        lock_reset; repeat (BD + 2) @(negedge clk);
        present(SECRET); @(negedge clk);
        check(locked === 1'b0, "C real secret clears locked after the boot delay");
        run_attack(SCAN_WIDTH-1, rec, full_cap);
        $display("  captured[644:517] (unlocked) = %032h", rec);
        check(rec === KEY, "C unlocked: attack recovers the KAT key exactly as Phase 7");

        // ---------------- D ----------------
        $display("=== D: lockout ===");
        lock_reset; repeat (BD + 2) @(negedge clk);
        present(32'h1); present(32'h2); present(32'h3);
        check(lockout === 1'b1 && locked === 1'b1, "D 3 wrong codes -> lockout active, still locked");
        present(SECRET);
        check(locked === 1'b1, "D correct code REJECTED during lockout");
        run_attack(SCAN_WIDTH-1, rec, full_cap);
        check(rec === 128'h0 && lockout === 1'b1, "D attack during lockout: all-zero (lockout still running)");
        // functional KAT while in lockout (E2)
        run_kat(ct);
        $display("  KAT ciphertext in lockout = %032h", ct);
        check(ct === EXPECTED_CT, "E functional KAT bit-exact while LOCKED + IN LOCKOUT");
        wait (lockout === 1'b0); @(negedge clk);
        present(SECRET); @(negedge clk);
        check(locked === 1'b0, "D after lockout expiry the correct code unlocks");
        run_attack(SCAN_WIDTH-1, rec, full_cap);
        check(rec === KEY, "D after expiry+unlock the attack recovers the key (Phase 7 behavior)");
        run_kat(ct);
        check(ct === EXPECTED_CT, "E functional KAT bit-exact while UNLOCKED");

        // ---------------- E (plain locked) ----------------
        lock_reset; repeat (BD + 2) @(negedge clk);
        check(locked === 1'b1 && lockout === 1'b0, "E state: locked, no lockout");
        run_kat(ct);
        check(ct === EXPECTED_CT, "E functional KAT bit-exact while LOCKED (no lockout)");

        $display("================================================================");
        if (errors == 0) $display("TESTBENCH: ALL TESTS PASSED"); else $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $finish;
    end
    initial begin #40000000; $display("RESULT: GLOBAL TIMEOUT"); $finish; end
endmodule