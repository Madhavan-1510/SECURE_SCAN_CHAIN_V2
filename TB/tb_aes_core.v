// ============================================================================
// tb_aes_core.v
//
// Objective: verify aes_core.v produces the correct ciphertext for the
// standard FIPS-197 Appendix B / NIST AES-128 known-answer test, BEFORE any
// PCPI or scan logic is introduced (Phase 4 of the project plan).
//
// Key:        000102030405060708090A0B0C0D0E0F
// Plaintext:  00112233445566778899AABBCCDDEEFF
// Expected:   69C4E0D86A7B0430D8CDB78070B4C55A
// ============================================================================
`timescale 1ns/1ps

module tb_aes_core;

    reg clk = 0;
    reg resetn = 0;
    reg start_i = 0;
    reg [127:0] key_i;
    reg [127:0] block_i;
    wire busy_o, done_o;
    wire [127:0] ciphertext_o;

    localparam [127:0] KEY        = 128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] PLAINTEXT  = 128'h00112233445566778899AABBCCDDEEFF;
    localparam [127:0] EXPECTED_CT= 128'h69C4E0D86A7B0430D8CDB78070B4C55A;

    aes_core dut (
        .clk(clk), .resetn(resetn),
        .start_i(start_i), .key_i(key_i), .block_i(block_i),
        .busy_o(busy_o), .done_o(done_o), .ciphertext_o(ciphertext_o),
        .dbg_key_reg(), .dbg_round_key_reg(), .dbg_state_reg(), .dbg_round_reg(),
        // Phase 6 regression: scan disabled, functional behavior must be
        // bit-for-bit identical to Phase 3/4.
        .scan_en(1'b0), .scan_in(1'b0), .scan_out(),
        // Phase 8: unlocked, so scan wiring (if ever exercised) behaves
        // exactly like the original Phase 6 chain. Irrelevant here since
        // scan_en=0 throughout this regression.
        .locked(1'b0)
    );

    always #5 clk = ~clk;

    integer errors = 0;

    initial begin
        resetn = 0;
        key_i = 128'h0;
        block_i = 128'h0;
        start_i = 0;
        repeat (3) @(posedge clk);
        #1 resetn = 1;
        @(posedge clk);

        #1;
        key_i   = KEY;
        block_i = PLAINTEXT;
        start_i = 1;
        @(posedge clk);
        #1 start_i = 0;

        // 11 clocks total latency (1 init + 10 rounds); wait generously
        wait (done_o == 1'b1);
        @(posedge clk); // settle

        $display("Key:               %032h", KEY);
        $display("Plaintext:         %032h", PLAINTEXT);
        $display("Ciphertext (DUT):  %032h", ciphertext_o);
        $display("Ciphertext (NIST): %032h", EXPECTED_CT);

        if (ciphertext_o === EXPECTED_CT) begin
            $display("RESULT: AES CORE KAT PASS");
        end else begin
            $display("RESULT: AES CORE KAT FAIL");
            errors = errors + 1;
        end

        if (errors == 0)
            $display("TESTBENCH: ALL TESTS PASSED");
        else
            $display("TESTBENCH: %0d TEST(S) FAILED", errors);

        $finish;
    end

    initial begin
        #2000;
        $display("RESULT: TIMEOUT - done_o never asserted");
        $finish;
    end

endmodule