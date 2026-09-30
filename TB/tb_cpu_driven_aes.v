// ============================================================================
// tb_cpu_driven_aes.v
//
// Closes Gap 1 from secure1.md: every prior testbench drove aes_pcpi's PCPI
// pins directly, standing in for the CPU. This is the first test where the
// real picorv32 core fetches real instructions, decodes them, recognizes
// the custom-1 (AES) opcode is not its own, offers it over PCPI, and
// aes_pcpi claims and executes it -- exactly the path a real program would
// take, and the one thing in the whole project that was still unverified.
//
// The program below was hand-assembled (see gen_prog.py) because no RISC-V
// toolchain is available in this environment; every instruction encoding
// was independently traced bit-by-bit against the RV32I spec and the
// project's own AES_OPCODE/funct3 definitions (aes_pcpi_defs.vh) before
// being used here. Program:
//
//   LOADKEY x4    (word 0..3, via li+custom1, x1=index x2=data)
//   LOADBLOCK x4  (same pattern, plaintext words)
//   ENCRYPT
//   READRESULT x4, each result SW'd to memory at byte offset 0x800+
//   EBREAK (halts the CPU; asserts top.trap)
//
// The ciphertext is recovered from *memory* (via hierarchical access to the
// behavioral memory array, which is legitimate in simulation -- this is not
// a scan attack, it is the testbench reading back what the CPU itself
// explicitly stored with an SW instruction) and compared against the NIST
// AES-128 KAT, exactly like every other testbench in the suite.
// ============================================================================
`timescale 1ns/1ps

module tb_cpu_driven_aes;

    reg clk = 0;
    reg resetn = 0;
    reg lock_resetn = 0;

    reg        unlock_valid = 0;
    reg [31:0] unlock_code_i = 0;
    reg        relock = 0;
    wire       locked;

    reg        scan_en = 0;
    reg        scan_in = 0;
    wire       scan_out;

    wire       trap;

    localparam [127:0] EXPECTED_CT = 128'h69C4E0D86A7B0430D8CDB78070B4C55A;
    localparam integer RESULT_WORD_BASE = 512; // byte 0x800 / 4

    secure_scan_rv_top_v2 #(
        .SECURE_SCAN(1),
        .MEM_WORDS(1024)
    ) top (
        .clk(clk), .resetn(resetn), .lock_resetn(lock_resetn),
        .trap(trap),
        .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out),
        .unlock_valid(unlock_valid), .unlock_code_i(unlock_code_i),
        .relock(relock), .locked(locked)
    );

    always #5 clk = ~clk;

    integer errors = 0;

    initial begin
        // ---- Load the hand-assembled program directly into the DUT's
        // memory array via hierarchical access (simulation-only setup step,
        // not part of the DUT itself -- equivalent to what a real bring-up
        // flow does via $readmemh from a linked .hex image). ----
        top.memory[0] = 32'h000000b7;
        top.memory[1] = 32'h00008093;
        top.memory[2] = 32'h00010137;
        top.memory[3] = 32'h20310113;
        top.memory[4] = 32'h0020802b;
        top.memory[5] = 32'h000000b7;
        top.memory[6] = 32'h00108093;
        top.memory[7] = 32'h04050137;
        top.memory[8] = 32'h60710113;
        top.memory[9] = 32'h0020802b;
        top.memory[10] = 32'h000000b7;
        top.memory[11] = 32'h00208093;
        top.memory[12] = 32'h08091137;
        top.memory[13] = 32'ha0b10113;
        top.memory[14] = 32'h0020802b;
        top.memory[15] = 32'h000000b7;
        top.memory[16] = 32'h00308093;
        top.memory[17] = 32'h0c0d1137;
        top.memory[18] = 32'he0f10113;
        top.memory[19] = 32'h0020802b;
        top.memory[20] = 32'h000000b7;
        top.memory[21] = 32'h00008093;
        top.memory[22] = 32'h00112137;
        top.memory[23] = 32'h23310113;
        top.memory[24] = 32'h0020902b;
        top.memory[25] = 32'h000000b7;
        top.memory[26] = 32'h00108093;
        top.memory[27] = 32'h44556137;
        top.memory[28] = 32'h67710113;
        top.memory[29] = 32'h0020902b;
        top.memory[30] = 32'h000000b7;
        top.memory[31] = 32'h00208093;
        top.memory[32] = 32'h8899b137;
        top.memory[33] = 32'habb10113;
        top.memory[34] = 32'h0020902b;
        top.memory[35] = 32'h000000b7;
        top.memory[36] = 32'h00308093;
        top.memory[37] = 32'hccddf137;
        top.memory[38] = 32'heff10113;
        top.memory[39] = 32'h0020902b;
        top.memory[40] = 32'h0000202b;
        top.memory[41] = 32'h00001237;
        top.memory[42] = 32'h80020213;
        top.memory[43] = 32'h000000b7;
        top.memory[44] = 32'h00008093;
        top.memory[45] = 32'h0000b1ab;
        top.memory[46] = 32'h00322023;
        top.memory[47] = 32'h000000b7;
        top.memory[48] = 32'h00108093;
        top.memory[49] = 32'h0000b1ab;
        top.memory[50] = 32'h00322223;
        top.memory[51] = 32'h000000b7;
        top.memory[52] = 32'h00208093;
        top.memory[53] = 32'h0000b1ab;
        top.memory[54] = 32'h00322423;
        top.memory[55] = 32'h000000b7;
        top.memory[56] = 32'h00308093;
        top.memory[57] = 32'h0000b1ab;
        top.memory[58] = 32'h00322623;
        top.memory[59] = 32'h00100073;

        // ---- Power-on reset. Lock defaults fail-safe locked=1 (Phase 8/9
        // fail-safe behavior) so this run also confirms LOADKEY/LOADBLOCK/
        // ENCRYPT/READRESULT work correctly through the real CPU while the
        // scan segment is locked -- the two features are independent and
        // this is the first time they have been exercised together through
        // genuine CPU fetch/decode. ----
        resetn = 0; lock_resetn = 0;
        repeat (5) @(posedge clk);
        #1 resetn = 1; lock_resetn = 1;

        // ---- Run until EBREAK traps, or timeout. ----
        wait (trap === 1'b1);
        @(posedge clk); #1;

        $display("================================================================");
        $display("CPU-DRIVEN END-TO-END TEST (real picorv32 fetch/decode/PCPI path)");
        $display("locked = %b (fail-safe default out of reset)", locked);
        $display("================================================================");

        begin : check_result
            reg [127:0] ct;
            ct[127:96] = top.memory[RESULT_WORD_BASE+0];
            ct[95:64]  = top.memory[RESULT_WORD_BASE+1];
            ct[63:32]  = top.memory[RESULT_WORD_BASE+2];
            ct[31:0]   = top.memory[RESULT_WORD_BASE+3];

            $display("Ciphertext (via real CPU + PCPI + SW to memory): %032h", ct);
            $display("Ciphertext (NIST KAT):                           %032h", EXPECTED_CT);

            if (ct === EXPECTED_CT) begin
                $display("RESULT: PASS -- real picorv32 core correctly drove AES_LOADKEY/");
                $display("        LOADBLOCK/ENCRYPT/READRESULT over genuine PCPI fetch/decode,");
                $display("        matching the NIST KAT. Gap 1 is closed.");
            end else begin
                $display("RESULT: FAIL -- CPU-driven path did not reproduce the KAT ciphertext.");
                errors = errors + 1;
            end
        end

        if (errors == 0)
            $display("TESTBENCH: ALL TESTS PASSED");
        else
            $display("TESTBENCH: %0d TEST(S) FAILED", errors);

        $finish;
    end

    initial begin
        #100000;
        $display("RESULT: GLOBAL TIMEOUT -- trap never asserted (CPU stuck or program wrong)");
        $finish;
    end

endmodule
