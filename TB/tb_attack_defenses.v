`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"
// ============================================================================
// tb_attack_defenses.v -- Paper 2 Phase 5: attack x design matrix incl. G4.
//
// Columns (each is an independent mx_cell: own DUT, own clock):
//   K0  G0  undefended            aes_pcpi          locked=0
//   K1  G1  Paper-1 lock          aes_pcpi          locked=1
//   K4  G4  write-blocking lock   aes_pcpi_def L4   locked=1
//   K5  G4 UNLOCKED (negative ctl) aes_pcpi_def L4  locked=0  (must == G0)
// Rows: A1 scan-read, A2 mode-switch spoof (fed 0), A2b spoof (fed 1),
//       A3 key+pt injection, A6 zeroize@256 / @645, A3b (G4 only) injection with
//       plaintext LSB=1 (the F8 hang case) followed by ENCRYPT.
// Golden ciphertexts are from pycryptodome, not from the DUT:
//   AES(EVIL, 000102..0F)      = 50b58e80ce784e98ad48d63390c5dfd7
//   AES(KEY,  ..EEFE)          = c32d9c183e5b132e3e43fd740aa1290f
//   AES(KEY,  ..EEFF) (KAT)    = 69c4e0d86a7b0430d8cdb78070b4c55a
// State is read only through aes_pcpi's dbg_* ports (no hierarchical paths),
// so the same cell code works for both aes_pcpi and aes_pcpi_def.
// Stimulus on negedge clk; state sampled right after last shift edge.
// ============================================================================
module mx_cell #(parameter integer KIND = 0) (
    output reg a1, a2, a2b, a3, a3_true, a6_256, a6_645,
    output reg a3b_run, a3b_ok, a3c_run, a3c_ok, a1b_leak,
    output reg key_intact_after_a6,
    output reg [127:0] a2_ct, a2b_ct, a3_ct, a1_win, a3b_ct, a3c_ct,
    output reg [5:0] tmo,
    output reg [31:0] a2c_w0, output reg a2c_wr,
    output reg a6_1, ni_same,
    output reg [11:0] wm_imm,
    output reg [5:0] wm_post,
    output reg tail_obs, a8_keyleak,
    output reg [31:0] errs,
    output reg done
);
    localparam LK = (KIND == 0 || KIND == 5) ? 1'b0 : 1'b1;
    // KIND 0=G0, 1=G1, 4=G4 locked, 5=G4 unlocked, 12/13/15 = _def level 2/3/5 LOCKED (G2/G3/G2R)
    localparam integer LVL = (KIND >= 10) ? (KIND - 10) : 4;
    localparam [127:0] KEY  = 128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] EVIL = 128'h0F1E2D3C4B5A69788796A5B4C3D2E1F0;
    localparam [127:0] PT0  = 128'h00112233445566778899AABBCCDDEEFE;
    localparam [127:0] PTK  = 128'h00112233445566778899AABBCCDDEEFF;
    localparam [127:0] GOLD_EVIL = 128'h50b58e80ce784e98ad48d63390c5dfd7;
    localparam [127:0] GOLD_PT0  = 128'hc32d9c183e5b132e3e43fd740aa1290f;
    localparam [127:0] GOLD_KAT  = 128'h69C4E0D86A7B0430D8CDB78070B4C55A;
    localparam [127:0] PTM  = 128'h80112233445566778899AABBCCDDEEFE; // MSB=1: an ungated fsm_state would shift in BUSY
    localparam [127:0] GOLD_PTM = 128'h946f2c6ac94daefa2274c74907b6de87; // AES(KEY, PTM), pycryptodome
    localparam [127:0] KONES = {128{1'b1}};                                // key_reg[127]=1: a 1-bit scan_out leak is visible
    localparam integer W = 645;
    reg [127:0] kcur = KEY;

    reg clk = 0, resetn = 0;
    always #5 clk = ~clk;
    reg pcpi_valid = 0; reg [31:0] pcpi_insn = 0, pcpi_rs1 = 0, pcpi_rs2 = 0;
    wire pcpi_wr, pcpi_wait, pcpi_ready; wire [31:0] pcpi_rd;
    reg scan_en = 0, scan_in = 0; wire scan_out;
    wire [127:0] d_key_stage, d_block_stage, d_key_reg, d_rk_reg, d_state_reg; wire [3:0] d_round;

    generate
      if (KIND == 0 || KIND == 1) begin : g_orig
        aes_pcpi dut (.clk(clk), .resetn(resetn), .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn),
          .pcpi_rs1(pcpi_rs1), .pcpi_rs2(pcpi_rs2), .pcpi_wr(pcpi_wr), .pcpi_rd(pcpi_rd),
          .pcpi_wait(pcpi_wait), .pcpi_ready(pcpi_ready),
          .dbg_key_stage(d_key_stage), .dbg_block_stage(d_block_stage), .dbg_core_key_reg(d_key_reg),
          .dbg_core_round_key_reg(d_rk_reg), .dbg_core_state_reg(d_state_reg), .dbg_core_round_reg(d_round),
          .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out), .locked(LK));
      end else begin : g_def
        aes_pcpi_def #(.DEFENSE_LEVEL(LVL)) dut (.clk(clk), .resetn(resetn), .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn),
          .pcpi_rs1(pcpi_rs1), .pcpi_rs2(pcpi_rs2), .pcpi_wr(pcpi_wr), .pcpi_rd(pcpi_rd),
          .pcpi_wait(pcpi_wait), .pcpi_ready(pcpi_ready),
          .dbg_key_stage(d_key_stage), .dbg_block_stage(d_block_stage), .dbg_core_key_reg(d_key_reg),
          .dbg_core_round_key_reg(d_rk_reg), .dbg_core_state_reg(d_state_reg), .dbg_core_round_reg(d_round),
          .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out), .locked(LK));
      end
    endgenerate

    integer wait_cycles;
    function [31:0] mk_insn(input [2:0] f3); mk_insn = {7'b0,5'b0,5'b0,f3,5'b0,`AES_OPCODE}; endfunction
    reg [31:0] rd_val; reg wr_val;
    task do_pcpi(input [2:0] f3, input [31:0] rs1v, input [31:0] rs2v, output [31:0] rdv, output wrv);
        begin
            @(negedge clk); pcpi_valid = 1; pcpi_insn = mk_insn(f3); pcpi_rs1 = rs1v; pcpi_rs2 = rs2v;
            @(posedge clk); wait_cycles = 0;
            while (!pcpi_ready) begin @(posedge clk); wait_cycles = wait_cycles + 1;
                if (wait_cycles > 200) begin errs = errs + 1; disable do_pcpi; end end
            #1; rdv = pcpi_rd; wrv = pcpi_wr; @(negedge clk); pcpi_valid = 0;
        end
    endtask
    task setup(input [127:0] pt, input freeze);
        begin
            resetn = 0; scan_en = 0; scan_in = 0;
            repeat (3) @(posedge clk); #1 resetn = 1; @(posedge clk);
            do_pcpi(`AES_F3_LOADKEY,32'd0,kcur[127:96],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd1,kcur[95:64],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd2,kcur[63:32],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd3,kcur[31:0],rd_val,wr_val);
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
    task shift_const(input integer n, input bitv);
        integer k;
        begin @(negedge clk); scan_en = 1; scan_in = bitv;
              for (k = 0; k < n; k = k + 1) @(negedge clk);
              scan_en = 0; end
    endtask
    task shift_evil;
        integer k;
        begin @(negedge clk); scan_en = 1;
              for (k = 0; k < 128; k = k + 1) begin scan_in = EVIL[127-k]; @(negedge clk); end
              scan_en = 0; end
    endtask
    task read4(output [127:0] ct);
        begin
            do_pcpi(`AES_F3_READRESULT,32'd0,32'h0,rd_val,wr_val); ct[127:96] = rd_val;
            do_pcpi(`AES_F3_READRESULT,32'd1,32'h0,rd_val,wr_val); ct[95:64]  = rd_val;
            do_pcpi(`AES_F3_READRESULT,32'd2,32'h0,rd_val,wr_val); ct[63:32]  = rd_val;
            do_pcpi(`AES_F3_READRESULT,32'd3,32'h0,rd_val,wr_val); ct[31:0]   = rd_val;
        end
    endtask

    reg [W-1:0] cap, capB; reg [127:0] ct; integer k, j; reg leak; integer e0;
    reg [127:0] sn_ks, sn_bs, sn_st, sn_rk, sn_kr; reg [3:0] sn_rr;
    // 0 = unchanged, 1 = all ones (attacker value landed), 2 = all zero (wiped), 3 = other
    function [1:0] cls128(input [127:0] cur, input [127:0] snap);
        cls128 = (cur === snap) ? 2'd0 : (cur === {128{1'b1}}) ? 2'd1 : (cur === 128'h0) ? 2'd2 : 2'd3;
    endfunction
    function [1:0] cls4(input [3:0] cur, input [3:0] snap);
        cls4 = (cur === snap) ? 2'd0 : (cur === 4'hF) ? 2'd1 : (cur === 4'h0) ? 2'd2 : 2'd3;
    endfunction
    initial begin
        errs = 0; done = 0; a3b_run = (KIND == 4 || KIND >= 10); a3b_ok = 0; a3c_run = (KIND == 4 || KIND >= 10); a3c_ok = 0; a1b_leak = 0;
        a3b_ct = 0; a3c_ct = 0; a2c_w0 = 0; a2c_wr = 0; a6_1 = 0; ni_same = 0; tmo = 0; wm_imm = 0; wm_post = 0; tail_obs = 0; a8_keyleak = 0; e0 = 0;
        // A1
        setup(PTK, 1);
        scan_en = 1; scan_in = 0; cap = 0; cap[W-1] = scan_out;
        for (k = 0; k < W-1; k = k + 1) begin @(posedge clk); #1; cap[W-2-k] = scan_out; end
        scan_en = 0;
        leak = 0; for (j = W-1; j >= 127; j = j - 1) if (cap[j -: 128] === KEY) leak = 1;
        a1 = leak; a1_win = cap[644:517];
        // A2 (fed 0)
        e0 = errs; setup(PTK, 1); shift_const(389, 1'b0); read4(ct); a2_ct = ct; a2 = (ct === 128'h0);
        tmo[0] = (errs != e0);
        // A2b (fed 1)
        e0 = errs; setup(PTK, 1); shift_const(389, 1'b1); read4(ct); a2b_ct = ct; a2b = (ct[127:96] === 32'hFFFFFFFF);
        tmo[1] = (errs != e0);
        // A3
        e0 = errs; setup(PT0, 0); shift_evil;
        do_pcpi(`AES_F3_ENCRYPT,32'd0,32'd0,rd_val,wr_val); read4(ct);
        a3_ct = ct; a3 = (ct === GOLD_EVIL); a3_true = (ct === GOLD_PT0);
        tmo[2] = (errs != e0);
        // A3b (G4 only; in G0/G1 this exact case hangs -- F8 -- so it is not run there)
        if (KIND == 4 || KIND >= 10) begin
            e0 = errs; setup(PTK, 0); shift_evil;
            do_pcpi(`AES_F3_ENCRYPT,32'd0,32'd0,rd_val,wr_val); read4(ct);
            a3b_ok = (ct === GOLD_KAT); a3b_ct = ct; tmo[3] = (errs != e0);
        end
        // A3c (G4 only): plaintext MSB=1 + a few hostile shifts + ENCRYPT. Catches an ungated aes_pcpi.fsm_state
        // (block_stage[127]=1 would be shifted into it -> falsely BUSY -> ENCRYPT never accepted).
        if (KIND == 4 || KIND >= 10) begin
            e0 = errs; setup(PTM, 0); shift_const(5, 1'b0);
            do_pcpi(`AES_F3_ENCRYPT,32'd0,32'd0,rd_val,wr_val); read4(ct);
            a3c_ok = (ct === GOLD_PTM); a3c_ct = ct; tmo[4] = (errs != e0);
        end
        // A1b (all columns): all-ones key, freeze mid-computation, sample scan_out pre-shift + 8 shifts.
        // A frozen G4 chain exposes only its LAST flop (key_reg[127]) on scan_out, so this is the only probe that
        // sees a missing output mask. Unlocked columns must read 1 (positive control), locked columns must read 0.
        kcur = KONES; setup(PTK, 1);
        scan_en = 1; scan_in = 0; a1b_leak = (scan_out !== 1'b0);
        for (k = 0; k < 8; k = k + 1) begin @(posedge clk); #1; if (scan_out !== 1'b0) a1b_leak = 1; end
        scan_en = 0; kcur = KEY;
        // A6
        setup(PTK, 1); shift_const(256, 1'b0);
        a6_256 = (d_key_reg === 128'h0);
        key_intact_after_a6 = (d_key_reg === KEY);
        setup(PTK, 1); shift_const(645, 1'b0);
        a6_645 = (d_key_reg === 128'h0 && d_rk_reg === 128'h0);
        // A7: register write map. 645 hostile shifts of 1 from a frozen RUNNING core; classify each visible register.
        // wm_imm: sampled right after the last shift edge. wm_post: after 2 functional clocks (exposes a flush on the scan_en falling edge).
        // wm_imm layout: [1:0]key_stage [3:2]block_stage [5:4]state_reg [7:6]round_reg [9:8]round_key_reg [11:10]key_reg
        // wm_post layout: [1:0]key_stage [3:2]block_stage [5:4]key_reg
        setup(PTK, 1);
        sn_ks = d_key_stage; sn_bs = d_block_stage; sn_st = d_state_reg; sn_rr = d_round; sn_rk = d_rk_reg; sn_kr = d_key_reg;
        shift_const(645, 1'b1);
        wm_imm = {cls128(d_key_reg, sn_kr), cls128(d_rk_reg, sn_rk), cls4(d_round, sn_rr),
                  cls128(d_state_reg, sn_st), cls128(d_block_stage, sn_bs), cls128(d_key_stage, sn_ks)};
        repeat (2) @(posedge clk); #1;
        wm_post = {cls128(d_key_reg, sn_kr), cls128(d_block_stage, sn_bs), cls128(d_key_stage, sn_ks)};
        // A2c: spoof with scan_en HELD HIGH (no falling edge => no scan_en-edge flush can run) while one READRESULT is issued.
        // Feed = 1 for the first 128 shifts then 0, 389 shifts total: chain position p holds the bit fed at t = 388-p, so an
        // ungated state_reg[388:261] = all ones (t=0..127) while round_reg = 0 and aes_pcpi.fsm_state = 0 (IDLE, t=128..132).
        // A spoofed word 0 therefore reads FFFFFFFF, distinguishable from a wipe (0) and from the true ciphertext.
        e0 = errs; setup(PTK, 1); @(negedge clk); scan_en = 1;
        for (k = 0; k < 389; k = k + 1) begin scan_in = (k < 128); @(negedge clk); end
        scan_in = 1'b0;
        do_pcpi(`AES_F3_READRESULT,32'd0,32'h0,rd_val,wr_val); a2c_w0 = rd_val; a2c_wr = wr_val;
        scan_en = 0; tmo[5] = (errs != e0);
        // A6@1: is key_reg already zero after a SINGLE hostile shift?
        setup(PTK, 1); shift_const(1, 1'b0); a6_1 = (d_key_reg === 128'h0);
        // A9: differential non-interference on scan_out: same plaintext/timeline, two different keys, full 645-sample capture each.
        // ni_same=1 means scan_out did not depend on the key in this scenario (a positive control is the unlocked columns, which must be 0).
        kcur = KEY; setup(PTK, 1);
        scan_en = 1; scan_in = 0; cap = 0; cap[W-1] = scan_out;
        for (k = 0; k < W-1; k = k + 1) begin @(posedge clk); #1; cap[W-2-k] = scan_out; end
        scan_en = 0;
        kcur = KONES; setup(PTK, 1);
        scan_en = 1; scan_in = 0; capB = 0; capB[W-1] = scan_out;
        for (k = 0; k < W-1; k = k + 1) begin @(posedge clk); #1; capB[W-2-k] = scan_out; end
        scan_en = 0;
        ni_same = (cap === capB); kcur = KEY;
        // A8: observability of the NON-sensitive tail while locked. Plaintext (MSB=1, so a leaked 0 cannot hide it) is loaded,
        // core idle, then a full 645-bit scan capture. tail_obs = plaintext appears anywhere in the stream (public data,
        // but proves scan_out carries real chain content). a8_keyleak = the real key (all-ones key here) appears.
        kcur = KONES; setup(PTM, 0);
        scan_en = 1; scan_in = 0; cap = 0; cap[W-1] = scan_out;
        for (k = 0; k < W-1; k = k + 1) begin @(posedge clk); #1; cap[W-2-k] = scan_out; end
        scan_en = 0;
        for (j = W-1; j >= 127; j = j - 1) begin
            if (cap[j -: 128] === PTM) tail_obs = 1;
            if (cap[j -: 128] === KONES) a8_keyleak = 1;
        end
        kcur = KEY;
        done = 1;
    end
endmodule

module tb_attack_defenses;
    localparam integer N = 7;   // 0=G0 1=G1 2=G4 locked 3=G4 unlocked 4=G2 5=G3 6=G2R (all locked unless noted)
    wire [N-1:0] dn;
    wire A1B [0:N-1], A3C [0:N-1], R3C [0:N-1], A1 [0:N-1], A2 [0:N-1], A2B [0:N-1], A3 [0:N-1], A3T [0:N-1],
         A6a [0:N-1], A6b [0:N-1], KI [0:N-1], R3 [0:N-1], O3 [0:N-1], A61 [0:N-1], NI [0:N-1], TO [0:N-1], KL [0:N-1], C2R [0:N-1];
    wire [127:0] C2 [0:N-1], C2B [0:N-1], C3 [0:N-1], W1 [0:N-1];
    wire [31:0] E [0:N-1], C2W [0:N-1];
    wire [5:0] TM [0:N-1], WP [0:N-1];
    wire [11:0] WI [0:N-1];
    genvar g;
    generate for (g = 0; g < N; g = g + 1) begin : c
        localparam integer KD = (g == 0) ? 0 : (g == 1) ? 1 : (g == 2) ? 4 : (g == 3) ? 5 : (g == 4) ? 12 : (g == 5) ? 13 : 15;
        mx_cell #(.KIND(KD)) u (.a1(A1[g]), .a2(A2[g]), .a2b(A2B[g]), .a3(A3[g]), .a3_true(A3T[g]),
            .a6_256(A6a[g]), .a6_645(A6b[g]), .a3b_run(R3[g]), .a3b_ok(O3[g]), .a3c_run(R3C[g]), .a3c_ok(A3C[g]), .a1b_leak(A1B[g]),
            .key_intact_after_a6(KI[g]), .a2_ct(C2[g]), .a2b_ct(C2B[g]), .a3_ct(C3[g]), .a1_win(W1[g]),
            .tmo(TM[g]), .a2c_w0(C2W[g]), .a2c_wr(C2R[g]), .a6_1(A61[g]), .ni_same(NI[g]), .wm_imm(WI[g]), .wm_post(WP[g]),
            .tail_obs(TO[g]), .a8_keyleak(KL[g]), .errs(E[g]), .done(dn[g]));
    end endgenerate

    integer errors = 0;
    task check(input cond, input [2047:0] msg);
        begin if (!cond) begin $display("FAIL: %0s", msg); errors = errors + 1; end
              else $display("PASS: %0s", msg); end
    endtask
    localparam [127:0] KEY = 128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] GOLD_KAT = 128'h69C4E0D86A7B0430D8CDB78070B4C55A;
    localparam [127:0] G2_A3  = 128'ha3b364bf5b70887b3b3fd6e5e47baefd; // AES(KEY, EVIL)          pycryptodome
    localparam [127:0] G3_A3  = 128'h66e94bd4ef8a2c3b884cfa59ca342b2e; // AES(0, 0)               pycryptodome
    localparam [127:0] G2R_A3 = 128'hcdb0244b23c7686e464848c04f428606; // AES(KEY, PT0 >> 5)      pycryptodome
    integer i;
    initial begin
        wait (&dn);
        #1;
        for (i = 0; i < 4; i = i + 1) check(E[i] === 32'd0, "no PCPI timeouts in this column (G0/G1/G4/G4U)");
        // ---- G0 undefended ----
        check(A1[0] === 1'b1,  "G0 A1: key recovered from scan_out");
        check(A2[0] === 1'b1,  "G0 A2: bare READRESULT returns scan-forced value (spoof)");
        check(A2B[0] === 1'b1, "G0 A2b (fed=1): spoof");
        check(A3[0] === 1'b1,  "G0 A3: encrypts attacker (key,pt)");
        check(A6a[0] === 1'b0, "G0 A6: key_reg NOT zero at 256 shifts");
        check(A6b[0] === 1'b1, "G0 A6: all key regs zero at 645 shifts");
        check(C2W[0] === 32'hFFFFFFFF && C2R[0] === 1'b1, "G0 A2c: spoof with scan_en held high returns FFFFFFFF");
        check(NI[0] === 1'b0 && KL[0] === 1'b1, "G0 A9/A8: scan_out depends on the key; all-ones key visible (positive control)");
        // ---- G1 Paper 1 ----
        check(A1[1] === 1'b0 && W1[1] === 128'h0, "G1 A1: BLOCKED (window all-zero, no key anywhere)");
        check(A2[1] === 1'b1,  "G1 A2: spoof NOT blocked");
        check(A2B[1] === 1'b1, "G1 A2b: spoof NOT blocked");
        check(A3[1] === 1'b1,  "G1 A3: injection NOT blocked");
        check(A6a[1] === 1'b1 && A6b[1] === 1'b1, "G1 A6: zeroize works (cheaper: 256 shifts)");
        check(C2W[1] === 32'hFFFFFFFF && C2R[1] === 1'b1, "G1 A2c: spoof NOT blocked");
        check(NI[1] === 1'b1 && KL[1] === 1'b0 && TO[1] === 1'b0, "G1 A9/A8: scan_out key-independent, and nothing observable at all while locked");
        // ---- G4 locked ----
        check(A1[2] === 1'b0 && W1[2] === 128'h0, "G4 A1: BLOCKED (window all-zero, no key anywhere)");
        check(A2[2] === 1'b0,  "G4 A2: spoof BLOCKED");
        check(C2[2] === GOLD_KAT, "G4 A2: READRESULT after 389 hostile shifts returns the TRUE NIST KAT ciphertext");
        check(A2B[2] === 1'b0, "G4 A2b (fed=1): spoof BLOCKED");
        check(C2B[2] === GOLD_KAT, "G4 A2b: READRESULT returns the TRUE NIST KAT ciphertext");
        check(A3[2] === 1'b0,  "G4 A3: attacker (key,pt) NOT encrypted");
        check(A3T[2] === 1'b1, "G4 A3: ciphertext == AES(real KEY, real plaintext) (pycryptodome golden)");
        check(R3[2] === 1'b1 && O3[2] === 1'b1, "G4 A3b: plaintext-LSB=1 injection (F8 hang case) is harmless: ENCRYPT accepted, KAT ciphertext bit-exact");
        check(R3C[2] === 1'b1 && A3C[2] === 1'b1, "G4 A3c: plaintext-MSB=1 + hostile shifts: fsm_state stays IDLE, ENCRYPT accepted, ciphertext == AES(KEY,PTM) (pycryptodome golden)");
        check(A1B[0] === 1'b1 && A1B[3] === 1'b1, "A1b positive control: unlocked G0 and G4-unlocked DO expose key_reg[127]=1 on scan_out (probe can see a leak)");
        check(A1B[1] === 1'b0 && A1B[2] === 1'b0, "A1b: locked G1 and G4 show NO 1 on scan_out (all-ones key, pre-shift + 8 shifts): output mask intact");
        check(A6a[2] === 1'b0 && A6b[2] === 1'b0, "G4 A6: zeroize BLOCKED at 256 and 645 shifts");
        check(KI[2] === 1'b1,  "G4 A6: key_reg still equals the real key after 256 hostile shifts");
        check(A61[2] === 1'b0, "G4 A6@1: a single hostile shift does not zeroize key_reg");
        check(C2W[2] === GOLD_KAT[127:96] && C2R[2] === 1'b1, "G4 A2c: spoof with scan_en HELD HIGH blocked: READRESULT word0 is the true KAT word");
        check(NI[2] === 1'b1 && KL[2] === 1'b0 && TO[2] === 1'b0, "G4 A9/A8: scan_out key-independent; nothing observable while locked");
        check(WI[2][1:0] === 2'd0 && WI[2][3:2] === 2'd0 && WI[2][11:10] === 2'd0 && WP[2] === 6'd0,
              "G4 A7: key_stage, block_stage, key_reg unchanged by 645 hostile shifts (also 2 clocks later: no deferred flush)");
        check(E[2] === 32'd0 && TM[2] === 6'd0, "G4: no PCPI timeouts anywhere");
        // ---- G4 unlocked negative control: must equal G0 ----
        check(A1[3] === A1[0] && W1[3] === KEY, "G4-unlocked A1: key recovered exactly like G0 (lock-sensitive)");
        check(A2[3] === A2[0] && A2B[3] === A2B[0] && A3[3] === A3[0] && A6a[3] === A6a[0] && A6b[3] === A6b[0],
              "G4-unlocked: A2/A2b/A3/A6 all identical to undefended G0");
        check(C2[3] === C2[0] && C2B[3] === C2B[0] && C3[3] === C3[0], "G4-unlocked: spoof/injection ciphertexts bit-identical to G0");
        check(C2W[3] === C2W[0] && NI[3] === NI[0] && KL[3] === KL[0] && A61[3] === A61[0] && WI[3] === WI[0], "G4-unlocked: A2c/A9/A8/A6@1/A7 identical to G0");

        // ================= G2 (DEFENSE_LEVEL 2, locked): granular read masking, tail stays shifting =================
        $display("---- G2 (locked) ----");
        check(A1[4] === 1'b0 && KL[4] === 1'b0 && NI[4] === 1'b1, "G2 A1/A8/A9: key not recoverable, scan_out key-independent (differential over two keys)");
        check(TO[4] === 1'b1, "G2: the non-sensitive tail IS observable while locked (its purpose)");
        check(A3[4] === 1'b0 && A3T[4] === 1'b0 && C3[4] === G2_A3, "G2 A3: INJECTION SUCCEEDS on the tail: ciphertext == AES(real KEY, attacker plaintext) (pycryptodome)");
        check(A2[4] === 1'b0 && C2[4] !== GOLD_KAT && C2[4] !== 128'h0, "G2 A2: state corrupted by tail writes (faulty ciphertext, neither true KAT nor forged zero): integrity NOT preserved");
        check(TM[4] === 6'b001000, "G2 A3b: plaintext-LSB=1 injection HANGS ENCRYPT (availability hazard, F8) and nothing else times out");
        check(A6a[4] === 1'b0 && KI[4] === 1'b1, "G2 A6: key_reg intact after 256 hostile shifts (sensitive regs frozen)");
        // ================= G3 (DEFENSE_LEVEL 3, locked): flush on scan_en edge =================
        $display("---- G3 (locked) ----");
        check(E[5] === 32'd0, "G3: no PCPI timeouts");
        check(A1[5] === 1'b0 && KL[5] === 1'b0 && NI[5] === 1'b1 && TO[5] === 1'b0, "G3 A1/A8/A9: read blocked, nothing observable");
        check(A3[5] === 1'b0 && C3[5] === G3_A3, "G3 A3: injection becomes a WIPE: ciphertext == AES(0,0) (pycryptodome), attacker value does not land");
        check(A61[5] === 1'b1 && A6a[5] === 1'b1 && KI[5] === 1'b0, "G3 A6: ONE hostile shift zeroizes key_reg (flush): cheapest DoS of any variant");
        check(C2W[5] === 32'hFFFFFFFF && C2R[5] === 1'b1, "G3 A2c: FAILS when scan_en is held high (no falling edge => no flush): forged word FFFFFFFF accepted by READRESULT");
        check(C2B[5] === 128'h0, "G3 A2b: with the falling edge present the spoof becomes a wipe (all-zero, not attacker-chosen)");
        // ================= G2R (DEFENSE_LEVEL 5, locked): tail recirculates =================
        $display("---- G2R (locked) ----");
        check(A1[6] === 1'b0 && KL[6] === 1'b0 && NI[6] === 1'b1 && TO[6] === 1'b1, "G2R A1/A8/A9: key not leaked, tail observable");
        check(A3[6] === 1'b0 && A3T[6] === 1'b0 && C3[6] === G2R_A3, "G2R A3: attacker cannot choose plaintext but the tail ROTATES it: ciphertext == AES(KEY, PT0>>5) (pycryptodome): integrity NOT preserved");
        check(TM[6] === 6'b001000, "G2R A3b: plaintext-LSB=1 case still HANGS ENCRYPT (rotation corrupts fsm_state)");
        check(C2W[6] === 32'h0 && C2R[6] === 1'b0, "G2R A2c: READRESULT completes without a data write (pcpi_wr=0), no forged value returned");
        check(A6a[6] === 1'b0 && KI[6] === 1'b1, "G2R A6: key_reg intact after 256 hostile shifts");

        $display("");
        $display("========= ATTACK x DESIGN (measured, all cells asserted; G2/G3/G2R locked) =========");
        $display("  attack      | G0        | G1        | G4 locked | G2        | G3        | G2R");
        $display("  A1 read     | %-9s | %-9s | %-9s | %-9s | %-9s | %s", A1[0]?"SUCCEEDS":"blocked", A1[1]?"SUCCEEDS":"BLOCKED", A1[2]?"SUCCEEDS":"BLOCKED", A1[4]?"SUCCEEDS":"BLOCKED", A1[5]?"SUCCEEDS":"BLOCKED", A1[6]?"SUCCEEDS":"BLOCKED");
        $display("  A2c spoof   | %-9s | %-9s | %-9s | n/a       | %-9s | %s", (C2W[0]===32'hFFFFFFFF)?"SUCCEEDS":"blocked", (C2W[1]===32'hFFFFFFFF)?"SUCCEEDS":"BLOCKED", (C2W[2]===32'hFFFFFFFF)?"SUCCEEDS":"BLOCKED", (C2W[5]===32'hFFFFFFFF)?"SUCCEEDS":"BLOCKED", (C2W[6]===32'hFFFFFFFF)?"SUCCEEDS":"BLOCKED");
        $display("  A3 inject   | %-9s | %-9s | %-9s | %-9s | %-9s | %s", A3[0]?"SUCCEEDS":"blocked", A3[1]?"SUCCEEDS":"BLOCKED", A3[2]?"SUCCEEDS":"BLOCKED", "PARTIAL", "WIPE", "ROTATE");
        $display("  A6@1 zero   | %-9s | %-9s | %-9s | %-9s | %-9s | %s", A61[0]?"zeroed":"intact", A61[1]?"zeroed":"intact", A61[2]?"zeroed":"intact", A61[4]?"zeroed":"intact", A61[5]?"ZEROED":"intact", A61[6]?"zeroed":"intact");
        $display("===================================================================================");
        if (errors == 0) $display("TESTBENCH: ALL TESTS PASSED"); else $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $finish;
    end
    initial begin #120000000; $display("RESULT: GLOBAL TIMEOUT"); $finish; end
endmodule