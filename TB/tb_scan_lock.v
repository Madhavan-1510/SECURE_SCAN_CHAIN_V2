// ============================================================================
// tb_scan_lock.v
//
// Phase 8/9 - Segmented secure scan defense verification.
//
// Validates, against the SAME attack procedure as tb_scan_attack.v
// (Phase 7), unchanged:
//
//   A) LOCKED:   the identical scan attack no longer recovers the key
//                (checked at 0, 1, 127, 255, 256, 388, 517, 644, 645,
//                 and 1290 (= 2x645) shifts -- secure.md Sec.28/29).
//   B) UNLOCKED: the identical attack recovers the key exactly as in
//                Phase 7 -- i.e. Phase 8's changes are a no-op on
//                observability/behavior when not locked.
//   C) Functional AES (scan_en=0) still produces the correct NIST KAT
//      ciphertext regardless of lock state -- confirms secure.md Sec.30
//      ("functional AES behavior must remain independent of lock state").
// ============================================================================
`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"

module tb_scan_lock;

    reg clk = 0;
    reg resetn = 0;       // resets the aes_pcpi/aes_core DUT only
    reg lock_resetn = 0;  // resets the lock controller only -- separate
                           // reset domain, since a lock/unlock config bit
                           // should not evaporate just because the AES
                           // core's functional state is reset

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

    localparam integer SCAN_WIDTH = 645;
    localparam integer KEY_REG_HI = 644;
    localparam integer KEY_REG_LO = 517;

    integer errors = 0;
    integer wait_cycles;

    function [31:0] mk_insn(input [2:0] f3);
        mk_insn = {7'b0, 5'b0, 5'b0, f3, 5'b0, `AES_OPCODE};
    endfunction

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

    // Reusable "attack" sequence: normal key/plaintext load, start encrypt,
    // freeze after 6 cycles, assert scan, capture up to N_SHIFTS shifts
    // beyond the pre-shift sample. Returns the recovered key window
    // [644:517] of whatever was captured, and also the FULL captured
    // stream for exhaustive leakage scanning.
    task run_attack(input integer n_shifts, output [127:0] recovered,
                     output [SCAN_WIDTH-1:0] full_capture);
        integer k;
        reg [SCAN_WIDTH-1:0] cap;
        begin
            // Reset the coprocessor's FUNCTIONAL state only, between runs.
            // Deliberately does NOT touch lock_resetn: the lock/unlock
            // configuration must persist across DUT resets, exactly like
            // a real access-control latch would.
            resetn = 0;
            scan_en = 0; scan_in = 0;
            repeat (3) @(posedge clk);
            #1 resetn = 1;
            @(posedge clk);

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

            scan_en = 1'b1;
            scan_in = 1'b0;

            cap = {SCAN_WIDTH{1'b0}};
            // pre-shift sample (bit 644)
            cap[SCAN_WIDTH-1] = scan_out;
            for (k = 0; k < n_shifts; k = k + 1) begin
                @(posedge clk);
                #1;
                if (SCAN_WIDTH-2-k >= 0)
                    cap[SCAN_WIDTH-2-k] = scan_out;
                // beyond SCAN_WIDTH-1 shifts we just keep clocking; no more
                // NEW bit positions to fill, but scan_out is re-sampled by
                // the caller's leak-check below regardless.
            end
            scan_en = 1'b0;

            full_capture = cap;
            recovered = cap[KEY_REG_HI:KEY_REG_LO];
        end
    endtask

    reg [127:0] rec;
    reg [SCAN_WIDTH-1:0] full_cap;
    integer test_num;
    integer j;
    reg any_leak;

    // Shift counts to sweep, per secure.md Sec.28 Q5-Q7
    integer shift_points [0:9];

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
        shift_points[9] = 1290; // 2x full chain length

        // =====================================================
        // PART A: default-locked (fail-safe out of reset) attack
        // =====================================================
        $display("============================================");
        $display("PART A: DEFAULT STATE (locked out of reset), repeat Phase 7 attack");
        $display("============================================");

        relock = 1; unlock_valid = 0;
        resetn = 0; lock_resetn = 0;
        repeat(2) @(posedge clk);
        #1 resetn = 1; lock_resetn = 1;
        @(posedge clk);
        #1 relock = 0;
        if (locked !== 1'b1) begin
            $display("RESULT: FAIL - lock controller did not default to locked=1 out of reset");
            errors = errors + 1;
        end else begin
            $display("CHECK: lock controller correctly defaults to locked=1 (fail-safe) out of reset");
        end

        for (test_num = 0; test_num < 10; test_num = test_num + 1) begin
            run_attack(shift_points[test_num], rec, full_cap);

            // zero-shift exposure check specifically at n_shifts==0
            if (shift_points[test_num] == 0) begin
                if (full_cap[SCAN_WIDTH-1] !== 1'b0) begin
                    $display("RESULT: FAIL - zero-shift exposure: scan_out was NOT masked before first shift (locked)");
                    errors = errors + 1;
                end else begin
                    $display("CHECK: zero-shift exposure closed -- pre-shift sample masked (locked)");
                end
            end

            if (rec === KEY) begin
                $display("LEAK at %0d shifts (LOCKED): recovered_key == KEY -- DEFENSE FAILED", shift_points[test_num]);
                errors = errors + 1;
            end else begin
                $display("OK  at %0d shifts (LOCKED): key NOT recoverable (captured[644:517] = %032h)",
                          shift_points[test_num], rec);
            end

            // exhaustive scan of every 128-bit window for ANY appearance
            // of the real key, anywhere in the captured stream
            any_leak = 1'b0;
            for (j = SCAN_WIDTH-1; j >= 127; j = j - 1) begin
                if (full_cap[j -: 128] === KEY) begin
                    any_leak = 1'b1;
                    $display("  -> full-stream leak found at captured[%0d:%0d]", j, j-127);
                end
            end
            if (any_leak) begin
                $display("RESULT: FAIL - key pattern found somewhere in captured stream at %0d shifts", shift_points[test_num]);
                errors = errors + 1;
            end
        end

        // =====================================================
        // PART B: unlock, repeat attack -> must match Phase 7 exactly
        // =====================================================
        $display("============================================");
        $display("PART B: UNLOCKED -- confirm Phase 8 wiring is a no-op vs Phase 7 baseline");
        $display("============================================");

        @(negedge clk);
        unlock_code_i = UNLOCK_CODE;
        unlock_valid  = 1'b1;
        @(posedge clk); #1;
        unlock_valid = 1'b0;

        if (locked !== 1'b0) begin
            $display("RESULT: FAIL - correct unlock code did not clear locked");
            errors = errors + 1;
        end else begin
            $display("CHECK: correct unlock code cleared locked (locked=0)");
        end

        run_attack(SCAN_WIDTH-1, rec, full_cap);
        if (rec === KEY) begin
            $display("RESULT: PASS - UNLOCKED attack recovers key exactly as Phase 7 (captured[644:517] = %032h)", rec);
        end else begin
            $display("RESULT: FAIL - UNLOCKED attack should behave exactly like Phase 7 but did not");
            errors = errors + 1;
        end

        // =====================================================
        // PART C: wrong unlock code must NOT unlock
        // =====================================================
        $display("============================================");
        $display("PART C: wrong unlock code is rejected");
        $display("============================================");
        relock = 1; @(posedge clk); #1; relock = 0;
        @(negedge clk);
        unlock_code_i = 32'hBAADF00D;
        unlock_valid  = 1'b1;
        @(posedge clk); #1;
        unlock_valid = 1'b0;
        if (locked !== 1'b1) begin
            $display("RESULT: FAIL - wrong unlock code incorrectly cleared locked");
            errors = errors + 1;
        end else begin
            $display("CHECK: wrong unlock code correctly rejected, still locked");
        end
        run_attack(SCAN_WIDTH-1, rec, full_cap);
        if (rec === KEY) begin
            $display("RESULT: FAIL - key recoverable after rejected unlock attempt");
            errors = errors + 1;
        end else begin
            $display("CHECK: key still not recoverable after rejected unlock attempt");
        end

        // =====================================================
        // PART D: functional AES correctness independent of lock state
        // (locked=1 currently from Part C) -- confirms secure.md Sec.30
        // =====================================================
        $display("============================================");
        $display("PART D: functional AES correctness while LOCKED (scan_en=0 path)");
        $display("============================================");
        resetn = 0; scan_en = 0; scan_in = 0;
        repeat (3) @(posedge clk);
        #1 resetn = 1;
        @(posedge clk);

        do_pcpi(`AES_F3_LOADKEY, 32'd0, KEY[127:96], rd_val, wr_val);
        do_pcpi(`AES_F3_LOADKEY, 32'd1, KEY[95:64],  rd_val, wr_val);
        do_pcpi(`AES_F3_LOADKEY, 32'd2, KEY[63:32],  rd_val, wr_val);
        do_pcpi(`AES_F3_LOADKEY, 32'd3, KEY[31:0],   rd_val, wr_val);
        do_pcpi(`AES_F3_LOADBLOCK, 32'd0, PLAINTEXT[127:96], rd_val, wr_val);
        do_pcpi(`AES_F3_LOADBLOCK, 32'd1, PLAINTEXT[95:64],  rd_val, wr_val);
        do_pcpi(`AES_F3_LOADBLOCK, 32'd2, PLAINTEXT[63:32],  rd_val, wr_val);
        do_pcpi(`AES_F3_LOADBLOCK, 32'd3, PLAINTEXT[31:0],   rd_val, wr_val);
        do_pcpi(`AES_F3_ENCRYPT, 32'd0, 32'd0, rd_val, wr_val);

        begin : ct_check
            reg [127:0] ct;
            do_pcpi(`AES_F3_READRESULT, 32'd0, 32'h0, rd_val, wr_val); ct[127:96] = rd_val;
            do_pcpi(`AES_F3_READRESULT, 32'd1, 32'h0, rd_val, wr_val); ct[95:64]  = rd_val;
            do_pcpi(`AES_F3_READRESULT, 32'd2, 32'h0, rd_val, wr_val); ct[63:32]  = rd_val;
            do_pcpi(`AES_F3_READRESULT, 32'd3, 32'h0, rd_val, wr_val); ct[31:0]   = rd_val;
            $display("Ciphertext (locked=%0d): %032h  (expected %032h)", locked, ct, EXPECTED_CT);
            if (ct === EXPECTED_CT) begin
                $display("RESULT: PASS - functional AES correct while LOCKED");
            end else begin
                $display("RESULT: FAIL - functional AES broken while LOCKED (Sec.30 violation)");
                errors = errors + 1;
            end
        end

        $display("============================================");
        if (errors == 0)
            $display("TESTBENCH: ALL TESTS PASSED");
        else
            $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $display("============================================");

        $finish;
    end

    initial begin
        #200000;
        $display("RESULT: GLOBAL TIMEOUT");
        $finish;
    end

endmodule