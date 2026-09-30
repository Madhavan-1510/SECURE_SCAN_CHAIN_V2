`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"

// ============================================================================
// tb_attack_write_inject.v
//
// Paper 2, Phase 1. Promotes tb_attack_probe.v (informational $display only)
// into a regression-grade testbench with real pass/fail assertions.
//
// Adds, vs. the original probe:
//   1. An independent bit-level reference model of the front 389-bit region
//      of the chain (key_stage[128] + block_stage[128] + fsm_state[1] +
//      round_reg[4] + state_reg[128]), built from the documented scan
//      semantics (scan_chain.v header: "bit[0] closest to local scan_in",
//      plain shift register), NOT copied from the RTL under test. Each
//      injection case checks the DUT's key_stage_q/block_stage_q/fsm_state
//      against this model with ===, not just an end-to-end ciphertext.
//   2. F3's zeroize side effect asserted directly (round_key_reg_q===0 at
//      >=128 shifts, key_reg_q===0 at >=256 shifts) alongside the injection,
//      since the same locked-scan session produces both effects together.
//   3. F8 sweep: plaintext LSB=0 (fsm_state lands IDLE post-injection,
//      matching the original probe) AND LSB=1 (fsm_state lands BUSY),
//      with the LSB=1 case's consequence checked explicitly: a subsequent
//      ENCRYPT via PCPI must NOT be accepted (pcpi_ready stays 0), which is
//      a genuine availability hazard distinct from the LSB=0 case.
//   4. Partial shift-count sweep (not just exactly 128): 0, 1, 32, 64, 96,
//      127, 128, 129, 160, 200, 255, 256, 257, 300 -- covering under-,
//      at-, and over- the key_stage width and the round_key_reg/key_reg
//      zeroize boundaries.
//   5. The n_shifts==128, LSB=0, full-injection-then-ENCRYPT case still
//      reproduces the exact ciphertext independently confirmed in
//      PROJECT_README.md sec 5a/15 against pycryptodome
//      (50b58e80ce784e98ad48d63390c5dfd7), asserted with ===, not just
//      printed.
//
// This file does NOT modify aes_pcpi.v/aes_core.v/scan_lock_controller.v --
// same frozen DUT as every other Paper 1/2 testbench.
// ============================================================================

module tb_attack_write_inject;

    reg clk = 0, resetn = 0, lock_resetn = 0;
    reg pcpi_valid = 0; reg [31:0] pcpi_insn = 0, pcpi_rs1 = 0, pcpi_rs2 = 0;
    wire pcpi_wr, pcpi_wait, pcpi_ready; wire [31:0] pcpi_rd;
    reg scan_en = 0, scan_in = 0; wire scan_out;
    wire locked; reg unlock_valid = 0; reg [31:0] unlock_code_i = 0; reg relock = 0;
    localparam [31:0] UNLOCK_CODE = 32'hDEC0DED1;

    scan_lock_controller #(.UNLOCK_CODE(UNLOCK_CODE)) u_lock (
        .clk(clk), .resetn(lock_resetn), .unlock_valid(unlock_valid),
        .unlock_code_i(unlock_code_i), .relock(relock), .locked(locked));

    aes_pcpi dut (
        .clk(clk), .resetn(resetn), .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn),
        .pcpi_rs1(pcpi_rs1), .pcpi_rs2(pcpi_rs2), .pcpi_wr(pcpi_wr), .pcpi_rd(pcpi_rd),
        .pcpi_wait(pcpi_wait), .pcpi_ready(pcpi_ready),
        .dbg_key_stage(), .dbg_block_stage(), .dbg_core_key_reg(), .dbg_core_round_key_reg(),
        .dbg_core_state_reg(), .dbg_core_round_reg(),
        .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out), .locked(locked));

    always #5 clk = ~clk;

    localparam [127:0] REAL_KEY = 128'h000102030405060708090A0B0C0D0E0F;
    // Non-periodic attacker key (avoids accidentally masking a bit-order bug
    // with a periodic pattern) -- same value as tb_attack_probe.v, so results
    // are directly comparable.
    localparam [127:0] EVIL_KEY = 128'h0F1E2D3C4B5A69788796A5B4C3D2E1F0;
    localparam [127:0] PLAINTEXT_LSB0 = 128'h00112233445566778899AABBCCDDEEFE; // ...FE, LSB=0
    localparam [127:0] PLAINTEXT_LSB1 = 128'h00112233445566778899AABBCCDDEEFF; // ...FF, LSB=1

    localparam [127:0] GOLDEN_CT_128_LSB0 = 128'h50b58e80ce784e98ad48d63390c5dfd7; // sec 5a/15

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
                if (wait_cycles > 200) begin
                    $display("ERROR: pcpi_ready never asserted (timeout) for f3=%0d", f3);
                    errors = errors + 1;
                    disable do_pcpi;
                end
            end
            #1; rdv = pcpi_rd; wrv = pcpi_wr;
            @(negedge clk); pcpi_valid = 1'b0;
        end
    endtask

    reg [31:0] rd_val; reg wr_val;

    task check(input cond, input [1023:0] msg);
        begin
            if (!cond) begin $display("FAIL: %0s", msg); errors = errors + 1; end
            else $display("PASS: %0s", msg);
        end
    endtask

    // ------------------------------------------------------------------
    // Independent bit-level reference model of the front 389-bit region
    // (key_stage+block_stage+fsm_state+round_reg+state_reg), built from
    // the documented scan semantics, NOT from reading the RTL under test:
    // a plain LSB-first shift register, bit[0] closest to scan_in, one
    // scan_cell per bit (scan_cell.v: scan_en=1 => q<=scan_in).
    // model_bit(k) = value of region-A bit k (0..388) after n_shifts,
    // given: initial 389-bit vector `init`, and the fed bitstream is
    // EVIL_KEY's 128 bits MSB-first (matching the documented scan_chain.v
    // convention "first-fed bit ends at bit[WIDTH-1]") followed by
    // zero-padding for any additional shifts beyond 128.
    // ------------------------------------------------------------------
    function fed_bit(input integer cycle_idx /* 0-based, 0 = first cycle */);
        begin
            if (cycle_idx < 128)
                fed_bit = EVIL_KEY[127 - cycle_idx];
            else
                fed_bit = 1'b0;
        end
    endfunction

    // Computes region-A bit k after n shifts of the fed bitstream into a
    // 389-bit register whose initial value is init[388:0] (bit0=nearest
    // scan_in). Implemented as an explicit cycle-by-cycle shift, exactly
    // mirroring scan_cell.v's documented behavior, independently written.
    task model_region_a(input [388:0] init, input integer n, output [388:0] result);
        integer c;
        reg [388:0] v;
        begin
            v = init;
            for (c = 0; c < n; c = c + 1) begin
                v = {v[387:0], fed_bit(c)};
            end
            result = v;
        end
    endtask

    // Region B (round_key_reg[128]+key_reg[256 total incl round_key]) is
    // simpler: while locked, round_key_reg's local scan_in is forced to a
    // constant 0 (aes_core.v: seg_in_muxed = locked ? 0 : seg_tap[2]),
    // independent of region A and of shift count. So after >=128 shifts
    // round_key_reg is provably all-zero, and after >=256 shifts key_reg
    // (which is fed by round_key_reg's own scan_out) is also all-zero.
    // This models that documented mechanism, not by reading the RTL.
    task expected_region_b_zero(input integer n, output round_key_zero, output key_reg_zero);
        begin
            round_key_zero = (n >= 128);
            key_reg_zero   = (n >= 256);
        end
    endtask

    reg [388:0] region_a_init, region_a_expected;
    reg exp_rk_zero, exp_kr_zero;

    // Runs one injection case: reset, load REAL_KEY + given plaintext
    // normally (locked=1 fail-safe, never unlocked), capture the true
    // pre-injection region-A state via hierarchical read (for the model's
    // initial condition -- reading state, not altering it), shift
    // n_shifts of the EVIL_KEY-then-zero bitstream, then compare DUT
    // state against the independent model.
    task run_case(input integer n_shifts, input [127:0] plaintext, input [1023:0] label);
        integer k;
        begin
            resetn = 0; lock_resetn = 0; scan_en = 0; scan_in = 0;
            relock = 1; unlock_valid = 0;
            repeat (3) @(posedge clk);
            #1 resetn = 1; lock_resetn = 1;
            @(posedge clk);
            #1 relock = 0;

            check(locked === 1'b1, {"fail-safe locked=1 confirmed before injection (", label, ")"});

            do_pcpi(`AES_F3_LOADKEY, 32'd0, REAL_KEY[127:96], rd_val, wr_val);
            do_pcpi(`AES_F3_LOADKEY, 32'd1, REAL_KEY[95:64],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADKEY, 32'd2, REAL_KEY[63:32],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADKEY, 32'd3, REAL_KEY[31:0],   rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd0, plaintext[127:96], rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd1, plaintext[95:64],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd2, plaintext[63:32],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd3, plaintext[31:0],   rd_val, wr_val);

            // Capture true pre-injection region-A state (hierarchical read
            // used only to seed the independent model's initial condition,
            // exactly as tb_scan_attack.v etc. read dbg taps for setup, not
            // for the attack itself).
            region_a_init[388:261] = dut.u_aes_core.state_reg_q;
            region_a_init[260:257] = dut.u_aes_core.round_reg_q;
            region_a_init[256]     = dut.fsm_state_q;
            region_a_init[255:128] = dut.block_stage_q;
            region_a_init[127:0]   = dut.key_stage_q;

            model_region_a(region_a_init, n_shifts, region_a_expected);
            expected_region_b_zero(n_shifts, exp_rk_zero, exp_kr_zero);

            @(negedge clk); scan_en = 1'b1;
            for (k = 0; k < n_shifts; k = k + 1) begin
                scan_in = fed_bit(k);
                @(negedge clk);
            end
            scan_en = 1'b0;
            @(posedge clk); #1;

            begin : region_a_check
                reg [388:0] dut_region_a;
                dut_region_a[388:261] = dut.u_aes_core.state_reg_q;
                dut_region_a[260:257] = dut.u_aes_core.round_reg_q;
                dut_region_a[256]     = dut.fsm_state_q;
                dut_region_a[255:128] = dut.block_stage_q;
                dut_region_a[127:0]   = dut.key_stage_q;
                check(dut_region_a === region_a_expected,
                      {"region-A (key_stage/block_stage/fsm/round/state) matches independent shift model (", label, ")"});
            end

            if (exp_rk_zero)
                check(dut.u_aes_core.round_key_reg_q === 128'h0, {"round_key_reg zeroed as F3 predicts (", label, ")"});
            if (exp_kr_zero)
                check(dut.u_aes_core.key_reg_q === 128'h0, {"key_reg zeroed as F3 predicts (", label, ")"});
        end
    endtask

    integer shift_points [0:13];
    integer i;
    reg [127:0] ct;

    initial begin
        shift_points[0]=0;   shift_points[1]=1;   shift_points[2]=32;  shift_points[3]=64;
        shift_points[4]=96;  shift_points[5]=127; shift_points[6]=128; shift_points[7]=129;
        shift_points[8]=160; shift_points[9]=200; shift_points[10]=255; shift_points[11]=256;
        shift_points[12]=257; shift_points[13]=300;

        $display("================================================================");
        $display("tb_attack_write_inject: partial-shift-count sweep, region-A model check");
        $display("================================================================");
        for (i = 0; i < 14; i = i + 1) begin
            run_case(shift_points[i], PLAINTEXT_LSB0, "LSB0 sweep");
        end
        for (i = 0; i < 14; i = i + 1) begin
            run_case(shift_points[i], PLAINTEXT_LSB1, "LSB1 sweep");
        end

        // ------------------------------------------------------------
        // F8 case A: PLAINTEXT_LSB0, exactly 128 shifts -> fsm_state must
        // land IDLE(0), and a subsequent ENCRYPT with no fresh load must
        // be accepted and reproduce the independently-confirmed ciphertext.
        // ------------------------------------------------------------
        $display("----------------------------------------------------------------");
        $display("F8 case A: LSB=0, 128 shifts -> expect fsm_state=IDLE, ENCRYPT accepted");
        run_case(128, PLAINTEXT_LSB0, "F8-A full injection");
        check(dut.fsm_state_q === 1'b0, "F8-A: fsm_state lands IDLE after 128-shift injection with plaintext LSB=0");

        do_pcpi(`AES_F3_ENCRYPT, 32'd0, 32'd0, rd_val, wr_val);
        do_pcpi(`AES_F3_READRESULT, 32'd0, 32'h0, rd_val, wr_val); ct[127:96] = rd_val;
        do_pcpi(`AES_F3_READRESULT, 32'd1, 32'h0, rd_val, wr_val); ct[95:64]  = rd_val;
        do_pcpi(`AES_F3_READRESULT, 32'd2, 32'h0, rd_val, wr_val); ct[63:32]  = rd_val;
        do_pcpi(`AES_F3_READRESULT, 32'd3, 32'h0, rd_val, wr_val); ct[31:0]   = rd_val;
        $display("F8-A ciphertext: %032h  (expected %032h, independently confirmed vs pycryptodome, sec 5a/15)", ct, GOLDEN_CT_128_LSB0);
        check(ct === GOLDEN_CT_128_LSB0, "F8-A: post-injection ENCRYPT reproduces the independently-confirmed A3 ciphertext");

        // ------------------------------------------------------------
        // F8 case B: PLAINTEXT_LSB1, exactly 128 shifts -> fsm_state must
        // land BUSY(1), and a subsequent ENCRYPT attempt must NOT be
        // accepted within a bounded window -- a distinct availability
        // hazard from case A, confirmed rather than assumed.
        // ------------------------------------------------------------
        $display("----------------------------------------------------------------");
        $display("F8 case B: LSB=1, 128 shifts -> expect fsm_state=BUSY, ENCRYPT NOT accepted (hang)");
        run_case(128, PLAINTEXT_LSB1, "F8-B full injection");
        check(dut.fsm_state_q === 1'b1, "F8-B: fsm_state lands BUSY after 128-shift injection with plaintext LSB=1");

        begin : f8b_hang_check
            integer w;
            reg saw_ready;
            saw_ready = 1'b0;
            @(negedge clk);
            pcpi_valid = 1'b1;
            pcpi_insn  = mk_insn(`AES_F3_ENCRYPT);
            pcpi_rs1   = 32'h0; pcpi_rs2 = 32'h0;
            for (w = 0; w < 50; w = w + 1) begin
                @(posedge clk); #1;
                if (pcpi_ready) saw_ready = 1'b1;
            end
            @(negedge clk); pcpi_valid = 1'b0;
            check(saw_ready === 1'b0, "F8-B: ENCRYPT correctly NOT accepted for 50 cycles while fsm_state is falsely BUSY (availability hazard confirmed)");
        end

        $display("================================================================");
        if (errors == 0)
            $display("TESTBENCH: ALL TESTS PASSED");
        else
            $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $display("================================================================");
        $finish;
    end

    initial begin
        #4000000;
        $display("RESULT: GLOBAL TIMEOUT");
        $finish;
    end

endmodule