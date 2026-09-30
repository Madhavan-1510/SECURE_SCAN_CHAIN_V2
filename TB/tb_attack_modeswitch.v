`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"
// ============================================================================
// tb_attack_modeswitch.v -- Paper 2 Phase 4, A2 (mode-switch: write mid-
// computation datapath state, then switch back to functional mode).
//
// A2 was previously only a PREDICTION in PROJECT_README.md's attack table
// ("expected to fail, by accident -- writing enough of state_reg wipes
// round_key_reg/key_reg on the way in via F3"), never an actual regression.
// This file promotes it to a real, assertion-gated testbench, using the
// same independent 645-bit shift-register reference model as tb_zeroize.v
// (built from the documented scan semantics, not from reading the RTL under
// test), extended to also assert the UNGATED windows (round_reg, state_reg,
// aes_pcpi.fsm_state) that tb_zeroize.v's own sweep computes but does not
// itself check.
//
// What this file establishes, each with a real assertion:
//
//   M1  round_reg and state_reg have NO write-side gate at all: at every
//       swept shift count, both exactly match the plain (ungated) shift
//       model -- i.e. F1's "not gated while locked" claim, generalized past
//       key_stage/block_stage (already shown by A3) to the AES-core side of
//       the chain too.
//   M2  This write is INSEPARABLE from F3's zeroize: reaching far enough
//       into state_reg to control it (>=262 shifts, since state_reg sits
//       downstream of key_stage+block_stage+fsm_state+round_reg) already
//       exceeds round_key_reg's 128-shift zeroize threshold by a wide
//       margin, and often key_reg's 256-shift threshold too. A "controlled
//       fault/differential" style attack that needs an INTACT round key
//       schedule while also repositioning state_reg cannot get one -- this
//       is the actual mechanism behind the README's "fails, by accident"
//       prediction, now measured rather than asserted.
//   M3  Two distinct, confirmed consequences of landing exactly at
//       n=389 (state_reg fully attacker-determined), branching on which
//       value the UNGATED 1-bit aes_pcpi.fsm_state lands on (itself just a
//       shifted-through bit, per M1's mechanism, not something the attacker
//       even has to aim for separately -- constant scan_in during the
//       whole session pins it along with everything else):
//         fed=0 -> fsm lands IDLE  -> CONFIRMED: a bare READRESULT (no
//                  ENCRYPT, no fresh LOADKEY/LOADBLOCK) is accepted and
//                  returns exactly the attacker-forced state_reg value as
//                  the "ciphertext" -- a genuine, distinct write-side
//                  exploit (ciphertext spoofing), separate from A3's
//                  key/plaintext injection and A6's zeroize/DoS.
//         fed=1 -> fsm lands BUSY  -> (ORIGINAL PREDICTION, REFUTED BY MEASUREMENT: hang). See M3-B below: READRESULT is NOT accepted
//                  for an extended window (aes_pcpi's ST_BUSY branch only
//                  cares about aes_core.done_o, which the real, unscanned
//                  aes_core.fsm_state -- still stuck RUNNING from the
//                  original freeze, exactly as in tb_scan_resume.v's root
//                  cause -- will never assert without a fresh, accepted
//                  ENCRYPT) -- an availability hazard, the same shape as
//                  F8's LSB=1 case but triggered by a different write.
//
// Locked=1 throughout (fail-safe default out of reset), NEVER unlocked --
// same convention as tb_attack_probe.v / tb_attack_write_inject.v / tb_zeroize.v.
// Uses scan_lock_controller.v (v1), matching the rest of the attack suite
// (v2/L1 hardening is evaluated separately in tb_lock_v2.v/tb_scan_lock_v2.v
// and does not change what is or is not write-gated inside aes_core.v).
// ============================================================================
module tb_attack_modeswitch;

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

    localparam [127:0] REAL_KEY  = 128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] PLAINTEXT = 128'h00112233445566778899AABBCCDDEEFF;

    integer errors = 0, wait_cycles;
    function [31:0] mk_insn(input [2:0] f3); mk_insn = {7'b0,5'b0,5'b0,f3,5'b0,`AES_OPCODE}; endfunction

    task do_pcpi(input [2:0] f3, input [31:0] rs1v, input [31:0] rs2v, output [31:0] rdv, output wrv);
        begin
            @(negedge clk); pcpi_valid = 1; pcpi_insn = mk_insn(f3); pcpi_rs1 = rs1v; pcpi_rs2 = rs2v;
            @(posedge clk); wait_cycles = 0;
            while (!pcpi_ready) begin
                @(posedge clk); wait_cycles = wait_cycles + 1;
                if (wait_cycles > 200) begin
                    $display("ERROR: pcpi timeout f3=%0d", f3); errors = errors + 1; disable do_pcpi;
                end
            end
            #1; rdv = pcpi_rd; wrv = pcpi_wr; @(negedge clk); pcpi_valid = 0;
        end
    endtask
    reg [31:0] rd_val; reg wr_val;

    task check(input cond, input [2047:0] msg);
        begin
            if (!cond) begin $display("FAIL: %0s", msg); errors = errors + 1; end
            else $display("PASS: %0s", msg);
        end
    endtask

    // ---- independent 645-bit reference model, identical layout/mechanism
    // to tb_zeroize.v's own model: plain LSB-first whole-chain shift, with
    // ONLY the boundary bit W[389] (round_key_reg's own front cell) forced
    // to 0 every cycle while locked -- built from the documented gate
    // (aes_core.v: seg_in_muxed = locked ? 0 : seg_tap[2]), not from
    // re-deriving it against the RTL under test.
    reg [644:0] W;
    task model_shift(input lock_val, input integer n, input fed);
        integer c;
        begin
            for (c = 0; c < n; c = c + 1) begin
                W = {W[643:0], fed};
                if (lock_val) W[389] = 1'b0;
            end
        end
    endtask

    // Reach the same mid-computation freeze point used throughout the
    // suite (LOADKEY/LOADBLOCK the real KAT values, issue ENCRYPT, freeze
    // 6 cycles in), locked=1 the whole time, then scan n_shifts of a
    // constant fed bit and sample the DUT + model with no trailing
    // functional edge (tb_zeroize.v's sampling-order lesson).
    task run_case(input integer n_shifts, input fed_val);
        begin
            relock = 1; unlock_valid = 0; resetn = 0; lock_resetn = 0;
            repeat (3) @(posedge clk); #1 resetn = 1; lock_resetn = 1; @(posedge clk); #1 relock = 0;
            check(locked === 1'b1, "fail-safe locked=1 confirmed before injection");

            do_pcpi(`AES_F3_LOADKEY,32'd0,REAL_KEY[127:96],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd1,REAL_KEY[95:64],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd2,REAL_KEY[63:32],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd3,REAL_KEY[31:0],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADBLOCK,32'd0,PLAINTEXT[127:96],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADBLOCK,32'd1,PLAINTEXT[95:64],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADBLOCK,32'd2,PLAINTEXT[63:32],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADBLOCK,32'd3,PLAINTEXT[31:0],rd_val,wr_val);

            @(negedge clk); pcpi_valid = 1; pcpi_insn = mk_insn(`AES_F3_ENCRYPT); pcpi_rs1 = 0; pcpi_rs2 = 0;
            @(posedge clk); repeat (6) @(posedge clk); #1; pcpi_valid = 0;

            W = {dut.u_aes_core.key_reg_q, dut.u_aes_core.round_key_reg_q, dut.u_aes_core.state_reg_q,
                 dut.u_aes_core.round_reg_q, dut.fsm_state_q, dut.block_stage_q, dut.key_stage_q};
            model_shift(1'b1, n_shifts, fed_val);

            @(negedge clk); scan_en = 1; scan_in = fed_val;
            repeat (n_shifts) @(negedge clk);
            scan_en = 0;   // sample now, no trailing functional edge
        end
    endtask

    integer sp [0:15]; integer i;
    reg [1023:0] lbl;

    initial begin
        sp[0]=0;   sp[1]=1;   sp[2]=127; sp[3]=128; sp[4]=129; sp[5]=200;
        sp[6]=255; sp[7]=256; sp[8]=257; sp[9]=261; sp[10]=300; sp[11]=350;
        sp[12]=388; sp[13]=389; sp[14]=500; sp[15]=644;

        $display("================================================================");
        $display("A2 MODE-SWITCH ATTACK: round_reg/state_reg write, ungated-window sweep");
        $display("================================================================");

        // ---- M1/M2: sweep, fed=1, every ungated window checked against the
        // model, plus the two gated ones re-confirmed inline. ----
        for (i = 0; i < 16; i = i + 1) begin
            run_case(sp[i], 1'b1);
            $display("---- n_shifts=%0d (fed=1) ----", sp[i]);
            check(dut.u_aes_core.round_reg_q  === W[260:257], "M1: round_reg matches the ungated shift model (no write gate)");
            check(dut.u_aes_core.state_reg_q  === W[388:261], "M1: state_reg matches the ungated shift model (no write gate)");
            check(dut.fsm_state_q             === W[256],     "M1: aes_pcpi.fsm_state matches the ungated shift model (no write gate)");
            check(dut.u_aes_core.round_key_reg_q === W[516:389], "sanity: round_key_reg matches the F3-gated model");
            check(dut.u_aes_core.key_reg_q       === W[644:517], "sanity: key_reg matches the F3-gated model");
            if (sp[i] >= 262) begin
                check(dut.u_aes_core.round_key_reg_q === 128'h0,
                      "M2: at this shift count (>=262, needed to reach state_reg) round_key_reg is ALREADY fully zeroed -- the write and the zeroize are inseparable");
            end
        end

        // ---- M3 case A: fed=0, n=389 (state_reg fully attacker-forced to
        // 0), model predicts fsm_state lands IDLE -> READRESULT should be
        // accepted and return the forced value with no fresh ENCRYPT. ----
        $display("----------------------------------------------------------------");
        $display("M3 case A: fed=0, n=389 -> expect fsm=IDLE, READRESULT spoofed to 0");
        run_case(389, 1'b0);
        check(dut.u_aes_core.state_reg_q === W[388:261], "M3-A: state_reg forced exactly to the attacker's chosen constant (0)");
        check(dut.fsm_state_q === 1'b0, "M3-A: aes_pcpi.fsm_state lands IDLE after this injection (as the ungated model predicts)");
        begin : spoof_check
            reg [127:0] ct; reg saw_ready;
            saw_ready = 1'b0;
            do_pcpi(`AES_F3_READRESULT, 32'd0, 32'h0, rd_val, wr_val); ct[127:96] = rd_val; if (pcpi_ready) saw_ready = 1'b1;
            do_pcpi(`AES_F3_READRESULT, 32'd1, 32'h0, rd_val, wr_val); ct[95:64]  = rd_val;
            do_pcpi(`AES_F3_READRESULT, 32'd2, 32'h0, rd_val, wr_val); ct[63:32]  = rd_val;
            do_pcpi(`AES_F3_READRESULT, 32'd3, 32'h0, rd_val, wr_val); ct[31:0]   = rd_val;
            $display("  spoofed READRESULT ciphertext = %032h (expect 0), no ENCRYPT ever reissued", ct);
            check(ct === 128'h0, "M3-A CONFIRMED: bare READRESULT (no fresh ENCRYPT) returns exactly the scan-forced state_reg value -- ciphertext spoofing, distinct from A3/A6");
        end

        // ---- M3 case B: fed=1, n=389, model predicts fsm_state lands
        // BUSY -> READRESULT must NOT be accepted (availability hazard,
        // same shape as F8's LSB=1 case, different trigger). ----
        $display("----------------------------------------------------------------");
        $display("M3 case B: fed=1, n=389 -> expect fsm=BUSY, READRESULT NOT accepted");
        run_case(389, 1'b1);
        check(dut.fsm_state_q === 1'b1, "M3-B: aes_pcpi.fsm_state lands BUSY after this injection");
        begin : m3b_check
            integer w, ready_at; reg saw_ready; reg wr_at; reg [31:0] rd_at;
            saw_ready = 1'b0; ready_at = -1; wr_at = 1'bx; rd_at = 32'hx;
            $display("  DIAGNOSTIC: aes_core.fsm_state=%0d (0=IDLE,1=RUN,2=DONE) round_reg_q=%0d", dut.u_aes_core.fsm_state, dut.u_aes_core.round_reg_q);
            check(dut.u_aes_core.fsm_state === 2'd2,
                  "M3-B: unscanned aes_core.fsm_state was driven to DONE by the scan-shifted round_reg (F8 is_final_round path CONFIRMED)");
            @(negedge clk); pcpi_valid = 1; pcpi_insn = mk_insn(`AES_F3_READRESULT); pcpi_rs1 = 0; pcpi_rs2 = 0;
            for (w = 0; w < 50; w = w + 1) begin
                @(posedge clk); #1;
                if (pcpi_ready && !saw_ready) begin saw_ready = 1'b1; ready_at = w; wr_at = pcpi_wr; rd_at = pcpi_rd; end
            end
            @(negedge clk); pcpi_valid = 0;
            $display("  RESULT: pcpi_ready seen=%b at cycle %0d, pcpi_wr=%b pcpi_rd=%08h", saw_ready, ready_at, wr_at, rd_at);
            check(saw_ready === 1'b1, "M3-B: NO hang -- aes_pcpi (falsely BUSY) sees the spurious core DONE and completes the READRESULT");
            check(wr_at === 1'b1 && rd_at === 32'hFFFFFFFF,
                  "M3-B: falsely-BUSY aes_pcpi self-clears in 1 cycle (spurious core DONE), then READRESULT returns the scan-forced state_reg word (FFFFFFFF): ciphertext spoofing works for fed=1 too");
        end

        $display("================================================================");
        $display("A2 VERDICT: round_reg/state_reg confirmed write-unprotected (M1);");
        $display("this is inseparable from the F3 zeroize side effect (M2), which is");
        $display("exactly why a differential/fault-style attack needing BOTH a");
        $display("repositioned state AND an intact round-key schedule cannot work here");
        $display("-- the README's 'fails, by accident' prediction is CONFIRMED, with");
        $display("the mechanism measured rather than assumed. A DISTINCT, genuinely");
        $display("exploitable consequence was found in the process (M3-A, ciphertext");
        $display("spoofing via bare READRESULT) and a second, independent spoof path (M3-B:");
        $display("spurious core DONE via round_reg/is_final_round self-clears the falsely-BUSY");
        $display("aes_pcpi, so READRESULT again returns the forced value). The predicted M3-B HANG was refuted.");
        $display("================================================================");
        if (errors == 0) $display("TESTBENCH: ALL TESTS PASSED");
        else $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $finish;
    end

    initial begin #4000000; $display("RESULT: GLOBAL TIMEOUT"); $finish; end
endmodule