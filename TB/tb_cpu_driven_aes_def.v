// ============================================================================
// tb_cpu_driven_aes_def.v  (Paper 2, Phase 5)
//
// tb_cpu_driven_aes.v's hand-assembled program (LOADKEY x4, LOADBLOCK x4,
// ENCRYPT, READRESULT x4 + SW, EBREAK), run through the real picorv32 in
// secure_scan_rv_top_def for every DEFENSE_LEVEL (0..5) x LOCK_VERSION (0,1,2).
// Each configuration is an independent runner (own clock, DUT, memory).
//
// Per configuration:
//   C1  program run from reset, lock in its reset state: ciphertext stored
//       by the CPU == NIST KAT; `locked` == (LOCK_VERSION != 0).
//   C2  645-shift scan read after the program (scan_in=0): the KAT key
//       (MSB-first or LSB-first, any alignment) appears in the 646-sample
//       scan_out stream iff the design is unlocked.
//   C3  (LOCK_VERSION=2) 3 wrong codes incl. the v1 default DEC0DED1 ->
//       lockout_o=1, and the real secret is rejected during the lockout.
//       (LOCK_VERSION=1) wrong code 0 is rejected.
//   C4  unlock (v1: DEC0DED1; v2: secret, after lockout_o drops) -> locked=0.
//   C5  resetn-only pulse (lock domain untouched), program re-run unlocked:
//       ciphertext == KAT; locked stays 0.
//   C6  unlocked 645-shift scan read: KAT key found (positive control that
//       C2 could have seen it).
// ============================================================================
`timescale 1ns/1ps

module cpu_aes_def_runner #(
    parameter integer DL = 4,
    parameter integer LV = 2
) (
    output reg        done,
    output reg [31:0] errors
);
    localparam [127:0] KEY         = 128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] EXPECTED_CT = 128'h69C4E0D86A7B0430D8CDB78070B4C55A;
    localparam [31:0]  SECRET      = 32'h5EC2_E7A1;
    localparam integer RESULT_WORD_BASE = 512;
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

    task check(input cond, input [8*96-1:0] msg);
        begin
            if (cond) $display("PASS: DL=%0d LV=%0d %0s", DL, LV, msg);
            else begin $display("FAIL: DL=%0d LV=%0d %0s", DL, LV, msg); errors = errors + 1; end
        end
    endtask

    task run_program(output [127:0] ct);
        integer n;
        begin
            n = 0;
            while (trap !== 1'b1 && n < 20000) begin @(posedge clk); n = n + 1; end
            @(posedge clk); #1;
            if (trap !== 1'b1) begin
                $display("FAIL: DL=%0d LV=%0d program did not trap within 20000 cycles", DL, LV);
                errors = errors + 1;
            end
            ct[127:96] = top.memory[RESULT_WORD_BASE+0];
            ct[95:64]  = top.memory[RESULT_WORD_BASE+1];
            ct[63:32]  = top.memory[RESULT_WORD_BASE+2];
            ct[31:0]   = top.memory[RESULT_WORD_BASE+3];
        end
    endtask

    // 1 pre-shift sample + CHAIN shifts, scan_in=0.
    reg [CHAIN:0] s;
    task scan_read;
        integer k;
        begin
            @(negedge clk); scan_en = 1; scan_in = 0; #1;
            s[0] = scan_out;
            for (k = 1; k <= CHAIN; k = k + 1) begin
                @(posedge clk); #1; s[k] = scan_out;
            end
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

    task attempt(input [31:0] code);
        begin
            @(negedge clk); unlock_code_i = code; unlock_valid = 1;
            @(negedge clk); unlock_valid = 0;
        end
    endtask

    reg [127:0] ct;
    integer i, n;

    initial begin
        done = 0; errors = 0;
        // Program from tb_cpu_driven_aes.v, unchanged.
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
        top.memory[58] = 32'h00322623; top.memory[59] = 32'h00100073;

        // ---- C1 ----
        repeat (5) @(posedge clk);
        #1 resetn = 1; lock_resetn = 1;
        run_program(ct);
        check(ct === EXPECTED_CT, "C1 CPU-driven KAT from reset (lock in reset state)");
        check(locked === (LV != 0), "C1 locked == (LOCK_VERSION != 0)");

        // ---- C2 ----
        scan_read;
        if (LV == 0) check(key_in_stream(0) === 1'b1, "C2 no lock: key visible in 645-shift scan read (G0 positive control)");
        else         check(key_in_stream(0) === 1'b0, "C2 locked: key NOT in 645-shift scan read");

        if (LV != 0) begin
            // ---- C3 ----
            if (LV == 2) begin
                attempt(32'hDEC0DED1); attempt(32'h0000_0000); attempt(32'hFFFF_FFFF);
                #1;
                // Attempts inside the boot delay are ignored, so the three
                // wrong codes only trigger a lockout if presented after it.
                n = 0; while (lockout_o && n < 5000) begin @(posedge clk); n = n + 1; end
                attempt(32'hDEC0DED1); attempt(32'h0000_0000); attempt(32'hFFFF_FFFF);
                #1;
                check(lockout_o === 1'b1, "C3 v2: 3 wrong codes (incl. v1 default DEC0DED1) after boot delay -> lockout_o=1");
                attempt(SECRET);
                #1;
                check(locked === 1'b1, "C3 v2: real secret rejected during lockout");
                n = 0; while (lockout_o && n < 5000) begin @(posedge clk); n = n + 1; end
                check(lockout_o === 1'b0, "C3 v2: lockout expires");
            end else begin
                attempt(32'h0000_0000); #1;
                check(locked === 1'b1, "C3 v1: wrong code rejected");
            end
            // ---- C4 ----
            attempt(LV == 2 ? SECRET : 32'hDEC0DED1); #1;
            check(locked === 1'b0, "C4 correct code unlocks");
        end

        // ---- C5 ----
        @(negedge clk); resetn = 0;
        repeat (5) @(posedge clk);
        for (i = RESULT_WORD_BASE; i < RESULT_WORD_BASE + 4; i = i + 1) top.memory[i] = 32'h0;
        #1 resetn = 1;
        run_program(ct);
        check(ct === EXPECTED_CT, "C5 CPU-driven KAT again after resetn-only pulse, unlocked");
        check(locked === 1'b0, "C5 lock state survives datapath reset (still unlocked)");

        // ---- C6 ----
        scan_read;
        check(key_in_stream(0) === 1'b1, "C6 unlocked: key visible in scan read (positive control)");

        done = 1;
    end
endmodule

module tb_cpu_driven_aes_def;
    wire [17:0] d;
    wire [31:0] e [0:17];

    genvar gd, gl;
    generate
        for (gd = 0; gd <= 5; gd = gd + 1) begin : g_dl
            for (gl = 0; gl <= 2; gl = gl + 1) begin : g_lv
                cpu_aes_def_runner #(.DL(gd), .LV(gl)) r (.done(d[gd*3+gl]), .errors(e[gd*3+gl]));
            end
        end
    endgenerate

    integer k, tot;
    initial begin
        wait (&d === 1'b1);
        #1;
        tot = 0;
        $display("================ CPU-DRIVEN AES x DEFENSE_LEVEL x LOCK_VERSION ================");
        for (k = 0; k < 18; k = k + 1) begin
            $display("  DEFENSE_LEVEL=%0d LOCK_VERSION=%0d : %0s (%0d errors)", k / 3, k % 3,
                     (e[k] == 0) ? "PASS" : "FAIL", e[k]);
            tot = tot + e[k];
        end
        if (tot == 0) $display("TESTBENCH: ALL TESTS PASSED (18 configurations)");
        else          $display("TESTBENCH: %0d TEST(S) FAILED", tot);
        $finish;
    end

    initial begin
        #5000000;
        $display("RESULT: GLOBAL TIMEOUT");
        $finish;
    end
endmodule
