// ============================================================================
// tb_attack_top_def.v  (Paper 2, Phase 5)
//
// Attack matrix run THROUGH the full top-level (secure_scan_rv_top_def): the
// real picorv32 drives the coprocessor over PCPI, the real lock controller
// drives `locked`, and the attacker only has the scan port (scan_en/scan_in/
// scan_out). No `locked` override, no hierarchical writes into the design.
//
// Firmware model: tb_cpu_driven_aes.v's program (LOADKEY, LOADBLOCK, ENCRYPT,
// READRESULT -> 0x800), then a service loop added here: poll the word at
// 0x700; flag 1 = ENCRYPT + READRESULT, flag 2 = READRESULT only; results to
// 0x810; EBREAK. (A device that loads its key once and encrypts on request.)
// New words were hand-assembled by a script whose encoder reproduces the
// existing program's lui/addi/sw/custom-1 words exactly.
// The attacker acts while the CPU sits in the poll loop, then the tb writes
// the flag (the "legitimate request") and reads what the CPU stored.
//
// Configurations (cfg):
//   0 P1     DEFENSE_LEVEL=0 LOCK_VERSION=1  Paper 1 exactly, locked
//   1 G0     DEFENSE_LEVEL=0 LOCK_VERSION=0  undefended
//   2 G1+L1  DEFENSE_LEVEL=1 LOCK_VERSION=2  Paper 1 masking + hardened lock, locked
//   3 G4+L1  DEFENSE_LEVEL=4 LOCK_VERSION=2  proposed design, locked
//   4 G4+L1U DEFENSE_LEVEL=4 LOCK_VERSION=2  unlocked with the secret (authorised
//                                            test mode; negative control)
// Attacks (atk):
//   0 none : flag 1, expect the true KAT (checks the service loop itself)
//   1 A1   : 645-shift scan read; KAT key in the stream (any alignment/order)?
//   2 A2   : 389 shifts of 1 (fills state_reg), flag 2 (READRESULT only):
//            forged all-ones "ciphertext" returned to the CPU?
//   3 A3   : 128 shifts of EVIL (MSB first), flag 1: ciphertext
//            AES(EVIL, 000102..0f) = 50b58e80... (pycryptodome)?
//   4 A6   : 256 shifts of 0, flag 1: key/plaintext staging wiped, ciphertext
//            AES(0,0) = 66e94bd4... (pycryptodome)?
// Expected (fixed before running, from s5e/s5f module-level results):
//   write attacks A2/A3/A6 succeed on P1, G0, G1+L1, G4+L1U; blocked (true
//   KAT) on G4+L1. A1 leaks on G0 and G4+L1U only.
// ============================================================================
`timescale 1ns/1ps

module attack_top_runner #(
    parameter integer CFG = 3,
    parameter integer ATK = 3
) (
    output reg        done,
    output reg [31:0] errors,
    output reg [3:0]  outcome   // 0 blocked/true KAT, 1 attack succeeded, 2 other
);
    localparam integer DL = (CFG == 0 || CFG == 1) ? 0 : (CFG == 2) ? 1 : 4;
    localparam integer LV = (CFG == 0) ? 1 : (CFG == 1) ? 0 : 2;
    localparam         UNLOCK = (CFG == 4);
    localparam         WRITE_BLOCKED = (CFG == 3);
    localparam         READ_LEAKS    = (CFG == 1 || CFG == 4);

    localparam [127:0] KEY       = 128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] KAT       = 128'h69C4E0D86A7B0430D8CDB78070B4C55A;
    localparam [127:0] EVIL      = 128'h0F1E2D3C4B5A69788796A5B4C3D2E1F0;
    localparam [127:0] GOLD_EVIL = 128'h50b58e80ce784e98ad48d63390c5dfd7; // AES(EVIL, 000102..0f)
    localparam [127:0] GOLD_ZERO = 128'h66e94bd4ef8a2c3b884cfa59ca342b2e; // AES(0, 0)
    localparam [127:0] FORGED    = {128{1'b1}};
    localparam [31:0]  SECRET    = 32'h5EC2_E7A1;
    localparam integer R1 = 512, R2 = 516, FLAG = 448;   // word addresses 0x800, 0x810, 0x700
    localparam integer CHAIN = 645;

    reg clk = 0;
    reg resetn = 0, lock_resetn = 0;
    reg unlock_valid = 0, relock = 0;
    reg [31:0] unlock_code_i = 0;
    reg scan_en = 0, scan_in = 0;
    wire scan_out, trap, locked, lockout_o;

    secure_scan_rv_top_def #(
        .DEFENSE_LEVEL(DL), .LOCK_VERSION(LV), .MEM_WORDS(1024),
        .MAX_FAILS(3), .LOCKOUT_CYCLES(400), .BOOT_DELAY_CYCLES(400)
    ) top (
        .clk(clk), .resetn(resetn), .lock_resetn(lock_resetn), .trap(trap),
        .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out),
        .unlock_valid(unlock_valid), .unlock_code_i(unlock_code_i), .relock(relock),
        .secret_i(SECRET), .secret_valid_i(1'b1),
        .locked(locked), .lockout_o(lockout_o)
    );

    always #5 clk = ~clk;

    task check(input cond, input [8*112-1:0] msg);
        begin
            if (cond) $display("PASS: cfg=%0d atk=%0d %0s", CFG, ATK, msg);
            else begin $display("FAIL: cfg=%0d atk=%0d %0s", CFG, ATK, msg); errors = errors + 1; end
        end
    endtask

    function [127:0] rd128(input integer base);
        rd128 = {top.memory[base], top.memory[base+1], top.memory[base+2], top.memory[base+3]};
    endfunction

    task shift_const(input integer n, input b);
        integer k;
        begin
            @(negedge clk); scan_en = 1; scan_in = b;
            for (k = 0; k < n; k = k + 1) @(negedge clk);
            scan_en = 0; scan_in = 0;
        end
    endtask

    task shift_evil;
        integer k;
        begin
            @(negedge clk); scan_en = 1;
            for (k = 0; k < 128; k = k + 1) begin scan_in = EVIL[127-k]; @(negedge clk); end
            scan_en = 0; scan_in = 0;
        end
    endtask

    reg [CHAIN:0] s;
    task scan_read;
        integer k;
        begin
            @(negedge clk); scan_en = 1; scan_in = 0; #1;
            s[0] = scan_out;
            for (k = 1; k <= CHAIN; k = k + 1) begin @(posedge clk); #1; s[k] = scan_out; end
            @(negedge clk); scan_en = 0;
        end
    endtask

    function key_in_stream(input dummy);
        integer o, b;
        reg fwd, rev;
        begin
            key_in_stream = 0;
            for (o = 0; o + 127 <= CHAIN; o = o + 1) begin
                fwd = 1; rev = 1;
                for (b = 0; b < 128; b = b + 1) begin
                    if (s[o+b] !== KEY[127-b]) fwd = 0;
                    if (s[o+b] !== KEY[b])     rev = 0;
                end
                if (fwd || rev) key_in_stream = 1;
            end
        end
    endfunction

    task wait_trap;
        integer n;
        begin
            n = 0;
            while (trap !== 1'b1 && n < 20000) begin @(posedge clk); n = n + 1; end
            @(posedge clk); #1;
            if (trap !== 1'b1) begin
                $display("FAIL: cfg=%0d atk=%0d service request never completed (no EBREAK in 20000 cycles)", CFG, ATK);
                errors = errors + 1;
            end
        end
    endtask

    reg [127:0] ct1, ct2;
    reg leak;
    integer n;

    initial begin
        done = 0; errors = 0; outcome = 2;
        // Words 0..58: tb_cpu_driven_aes.v program, unchanged (its EBREAK at 59 replaced).
        top.memory[0]  = 32'h000000b7; top.memory[1]  = 32'h00008093;
        top.memory[2]  = 32'h00010137; top.memory[3]  = 32'h20310113;
        top.memory[4]  = 32'h0020802b; top.memory[5]  = 32'h000000b7;
        top.memory[6]  = 32'h00108093; top.memory[7]  = 32'h04050137;
        top.memory[8]  = 32'h60710113; top.memory[9]  = 32'h0020802b;
        top.memory[10] = 32'h000000b7; top.memory[11] = 32'h00208093;
        top.memory[12] = 32'h08091137; top.memory[13] = 32'ha0b10113;
        top.memory[14] = 32'h0020802b; top.memory[15] = 32'h000000b7;
        top.memory[16] = 32'h00308093; top.memory[17] = 32'h0c0d1137;
        top.memory[18] = 32'he0f10113; top.memory[19] = 32'h0020802b;
        top.memory[20] = 32'h000000b7; top.memory[21] = 32'h00008093;
        top.memory[22] = 32'h00112137; top.memory[23] = 32'h23310113;
        top.memory[24] = 32'h0020902b; top.memory[25] = 32'h000000b7;
        top.memory[26] = 32'h00108093; top.memory[27] = 32'h44556137;
        top.memory[28] = 32'h67710113; top.memory[29] = 32'h0020902b;
        top.memory[30] = 32'h000000b7; top.memory[31] = 32'h00208093;
        top.memory[32] = 32'h8899b137; top.memory[33] = 32'habb10113;
        top.memory[34] = 32'h0020902b; top.memory[35] = 32'h000000b7;
        top.memory[36] = 32'h00308093; top.memory[37] = 32'hccddf137;
        top.memory[38] = 32'heff10113; top.memory[39] = 32'h0020902b;
        top.memory[40] = 32'h0000202b; top.memory[41] = 32'h00001237;
        top.memory[42] = 32'h80020213; top.memory[43] = 32'h000000b7;
        top.memory[44] = 32'h00008093; top.memory[45] = 32'h0000b1ab;
        top.memory[46] = 32'h00322023; top.memory[47] = 32'h000000b7;
        top.memory[48] = 32'h00108093; top.memory[49] = 32'h0000b1ab;
        top.memory[50] = 32'h00322223; top.memory[51] = 32'h000000b7;
        top.memory[52] = 32'h00208093; top.memory[53] = 32'h0000b1ab;
        top.memory[54] = 32'h00322423; top.memory[55] = 32'h000000b7;
        top.memory[56] = 32'h00308093; top.memory[57] = 32'h0000b1ab;
        top.memory[58] = 32'h00322623;
        // Service loop (new): poll 0x700; 1 = ENCRYPT+READ, 2 = READ only; results to 0x810.
        top.memory[59] = 32'h70002283;  // lw   x5, 0x700(x0)
        top.memory[60] = 32'hfe028ee3;  // beq  x5, x0, -4
        top.memory[61] = 32'h00200313;  // addi x6, x0, 2
        top.memory[62] = 32'h00628463;  // beq  x5, x6, +8   (skip ENCRYPT)
        top.memory[63] = 32'h0000202b;  // AES ENCRYPT
        top.memory[64] = 32'h01020213;  // addi x4, x4, 16   (0x810)
        top.memory[65] = 32'h000000b7; top.memory[66] = 32'h00008093;
        top.memory[67] = 32'h0000b1ab; top.memory[68] = 32'h00322023;
        top.memory[69] = 32'h000000b7; top.memory[70] = 32'h00108093;
        top.memory[71] = 32'h0000b1ab; top.memory[72] = 32'h00322223;
        top.memory[73] = 32'h000000b7; top.memory[74] = 32'h00208093;
        top.memory[75] = 32'h0000b1ab; top.memory[76] = 32'h00322423;
        top.memory[77] = 32'h000000b7; top.memory[78] = 32'h00308093;
        top.memory[79] = 32'h0000b1ab; top.memory[80] = 32'h00322623;
        top.memory[81] = 32'h00100073;  // ebreak
        top.memory[FLAG] = 32'h0;

        repeat (5) @(posedge clk);
        #1 resetn = 1; lock_resetn = 1;

        // First (legitimate) encryption; CPU then sits in the poll loop.
        n = 0;
        while (top.memory[R1+3] !== KAT[31:0] && n < 20000) begin @(posedge clk); n = n + 1; end
        repeat (20) @(posedge clk);
        ct1 = rd128(R1);
        check(ct1 === KAT, "first CPU-driven encryption == KAT");
        check(locked === (LV != 0), "lock in reset state (locked unless no lock)");

        if (UNLOCK) begin
            n = 0; while (lockout_o && n < 5000) begin @(posedge clk); n = n + 1; end
            @(negedge clk); unlock_code_i = SECRET; unlock_valid = 1;
            @(negedge clk); unlock_valid = 0; #1;
            check(locked === 1'b0, "authorised unlock with the v2 secret");
        end

        leak = 0;
        case (ATK)
            1: begin scan_read; leak = key_in_stream(0); end
            2: shift_const(389, 1'b1);
            3: shift_evil;
            4: shift_const(256, 1'b0);
            default: ;
        endcase

        repeat (5) @(posedge clk);
        top.memory[FLAG] = (ATK == 2) ? 32'd2 : 32'd1;
        wait_trap;
        ct2 = rd128(R2);

        case (ATK)
            0: begin
                check(ct2 === KAT, "no attack: service-loop encryption == KAT");
                outcome = (ct2 === KAT) ? 0 : 2;
            end
            1: begin
                check(leak === READ_LEAKS, READ_LEAKS ? "A1: key visible in scan read (expected for this config)"
                                                      : "A1: key NOT visible in scan read");
                outcome = leak ? 1 : 0;
            end
            2: begin
                if (WRITE_BLOCKED) check(ct2 === KAT,    "A2: READRESULT returns the true KAT, spoof blocked");
                else               check(ct2 === FORGED, "A2: READRESULT returns the scan-forced all-ones value (spoof succeeds)");
                outcome = (ct2 === KAT) ? 0 : (ct2 === FORGED) ? 1 : 2;
            end
            3: begin
                if (WRITE_BLOCKED) check(ct2 === KAT,       "A3: ciphertext == true KAT, injection blocked");
                else               check(ct2 === GOLD_EVIL, "A3: ciphertext == AES(EVIL, 000102..0f) (injection succeeds)");
                outcome = (ct2 === KAT) ? 0 : (ct2 === GOLD_EVIL) ? 1 : 2;
            end
            4: begin
                if (WRITE_BLOCKED) check(ct2 === KAT,       "A6: ciphertext == true KAT, wipe blocked");
                else               check(ct2 === GOLD_ZERO, "A6: ciphertext == AES(0,0) (key and plaintext wiped)");
                outcome = (ct2 === KAT) ? 0 : (ct2 === GOLD_ZERO) ? 1 : 2;
            end
        endcase
        if (outcome == 2) $display("INFO: cfg=%0d atk=%0d unexpected ciphertext %032h", CFG, ATK, ct2);
        check(locked === (UNLOCK ? 1'b0 : (LV != 0)),"lock state unchanged by the attack");
        done = 1;
    end
endmodule

module tb_attack_top_def;
    wire [24:0] d;
    wire [31:0] e [0:24];
    wire [3:0]  o [0:24];

    genvar gc, ga;
    generate
        for (gc = 0; gc < 5; gc = gc + 1) begin : g_cfg
            for (ga = 0; ga < 5; ga = ga + 1) begin : g_atk
                attack_top_runner #(.CFG(gc), .ATK(ga)) r (.done(d[gc*5+ga]), .errors(e[gc*5+ga]), .outcome(o[gc*5+ga]));
            end
        end
    endgenerate

    function [8*10-1:0] cellstr(input integer atk, input [3:0] oc);
        cellstr = (oc == 2) ? "OTHER     " :
               (atk == 0) ? "KAT ok    " :
               (oc == 1) ? ((atk == 1) ? "LEAKS     " : "SUCCEEDS  ") : "BLOCKED   ";
    endfunction

    integer c, tot;
    initial begin
        wait (&d === 1'b1);
        #1;
        tot = 0;
        for (c = 0; c < 25; c = c + 1) tot = tot + e[c];
        $display("");
        $display("===== ATTACKS THROUGH secure_scan_rv_top_def (real CPU + real lock, scan port only) =====");
        $display("  config        | none      | A1 read   | A2 spoof  | A3 inject | A6 wipe");
        for (c = 0; c < 5; c = c + 1)
            $display("  %0s | %0s| %0s| %0s| %0s| %0s",
                c == 0 ? "P1 (DL0,v1)  " : c == 1 ? "G0 (DL0,none)" : c == 2 ? "G1+L1 locked " :
                c == 3 ? "G4+L1 locked " : "G4+L1 unlock ",
                cellstr(0, o[c*5+0]), cellstr(1, o[c*5+1]), cellstr(2, o[c*5+2]), cellstr(3, o[c*5+3]), cellstr(4, o[c*5+4]));
        $display("==========================================================================================");
        if (tot == 0) $display("TESTBENCH: ALL TESTS PASSED (25 runs)");
        else          $display("TESTBENCH: %0d TEST(S) FAILED", tot);
        $finish;
    end

    initial begin
        #5000000;
        $display("RESULT: GLOBAL TIMEOUT");
        $finish;
    end
endmodule
