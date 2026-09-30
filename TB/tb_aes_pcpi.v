// ============================================================================
// tb_aes_pcpi.v
//
// Objective: drive aes_pcpi.v with the exact signal contract PicoRV32 uses
// (pcpi_valid/pcpi_insn/pcpi_rs1/pcpi_rs2 in, pcpi_wr/pcpi_rd/pcpi_wait/
// pcpi_ready out) WITHOUT instantiating the full CPU, to validate:
//
//   1. Full LOADKEY(x4) -> LOADBLOCK(x4) -> ENCRYPT -> READ_RESULT(x4)
//      sequence reproduces the NIST AES-128 KAT ciphertext.
//   2. An instruction that is NOT ours (different opcode) gets
//      pcpi_wait=0, pcpi_ready=0 immediately -- i.e. we never stall
//      unrelated CPU instructions (required by the project spec).
//   3. AES_ENCRYPT correctly holds pcpi_wait=1 for the full multi-cycle
//      AES latency and only pulses pcpi_ready once, at completion.
// ============================================================================
`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"

module tb_aes_pcpi;

    reg clk = 0;
    reg resetn = 0;

    reg         pcpi_valid = 0;
    reg  [31:0] pcpi_insn  = 32'h0;
    reg  [31:0] pcpi_rs1   = 32'h0;
    reg  [31:0] pcpi_rs2   = 32'h0;
    wire        pcpi_wr;
    wire [31:0] pcpi_rd;
    wire        pcpi_wait;
    wire        pcpi_ready;

    aes_pcpi dut (
        .clk(clk), .resetn(resetn),
        .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn),
        .pcpi_rs1(pcpi_rs1), .pcpi_rs2(pcpi_rs2),
        .pcpi_wr(pcpi_wr), .pcpi_rd(pcpi_rd),
        .pcpi_wait(pcpi_wait), .pcpi_ready(pcpi_ready),
        .dbg_key_stage(), .dbg_block_stage(),
        .dbg_core_key_reg(), .dbg_core_round_key_reg(),
        .dbg_core_state_reg(), .dbg_core_round_reg(),
        // Phase 6 regression: scan disabled, functional behavior must be
        // bit-for-bit identical to Phase 2/3/4.
        .scan_en(1'b0), .scan_in(1'b0), .scan_out(),
        // Phase 8: unlocked; irrelevant here since scan_en=0 throughout.
        .locked(1'b0)
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
    reg [127:0] ct_reconstructed;

    initial begin
        resetn = 0;
        repeat (3) @(posedge clk);
        #1 resetn = 1;
        @(posedge clk);

        // ---- Check 1: a non-AES instruction never stalls or is claimed ----
        @(negedge clk);
        pcpi_valid = 1'b1;
        pcpi_insn  = 32'b0000000_00000_00000_000_00000_0110011; // ADD, opcode 0110011
        pcpi_rs1   = 32'hDEADBEEF;
        pcpi_rs2   = 32'hCAFEF00D;
        @(posedge clk);
        #1;
        if (pcpi_wait !== 1'b0 || pcpi_ready !== 1'b0) begin
            $display("RESULT: FAIL - non-AES instruction was claimed (wait=%b ready=%b)", pcpi_wait, pcpi_ready);
            errors = errors + 1;
        end else begin
            $display("CHECK 1 PASS: non-AES instruction correctly ignored (wait=0, ready=0)");
        end
        @(negedge clk);
        pcpi_valid = 1'b0;
        @(posedge clk);

        // ---- Check 2: LOADKEY x4 ----
        do_pcpi(`AES_F3_LOADKEY, 32'd0, KEY[127:96], rd_val, wr_val);
        do_pcpi(`AES_F3_LOADKEY, 32'd1, KEY[95:64],  rd_val, wr_val);
        do_pcpi(`AES_F3_LOADKEY, 32'd2, KEY[63:32],  rd_val, wr_val);
        do_pcpi(`AES_F3_LOADKEY, 32'd3, KEY[31:0],   rd_val, wr_val);
        $display("CHECK 2: key loaded via 4x AES_LOADKEY words");

        // ---- Check 3: LOADBLOCK x4 ----
        do_pcpi(`AES_F3_LOADBLOCK, 32'd0, PLAINTEXT[127:96], rd_val, wr_val);
        do_pcpi(`AES_F3_LOADBLOCK, 32'd1, PLAINTEXT[95:64],  rd_val, wr_val);
        do_pcpi(`AES_F3_LOADBLOCK, 32'd2, PLAINTEXT[63:32],  rd_val, wr_val);
        do_pcpi(`AES_F3_LOADBLOCK, 32'd3, PLAINTEXT[31:0],   rd_val, wr_val);
        $display("CHECK 3: plaintext loaded via 4x AES_LOADBLOCK words");

        // ---- Check 4: AES_ENCRYPT must hold pcpi_wait for the full latency ----
        @(negedge clk);
        pcpi_valid = 1'b1;
        pcpi_insn  = mk_insn(`AES_F3_ENCRYPT);
        pcpi_rs1   = 32'h0;
        pcpi_rs2   = 32'h0;
        @(posedge clk);
        #1;
        if (pcpi_wait !== 1'b1) begin
            $display("RESULT: FAIL - AES_ENCRYPT did not assert pcpi_wait on first cycle");
            errors = errors + 1;
        end
        wait_cycles = 0;
        while (!pcpi_ready) begin
            @(posedge clk);
            #1;
            if (!pcpi_ready && pcpi_wait !== 1'b1) begin
                $display("RESULT: FAIL - pcpi_wait dropped before pcpi_ready during ENCRYPT (cycle %0d)", wait_cycles);
                errors = errors + 1;
            end
            wait_cycles = wait_cycles + 1;
            if (wait_cycles > 100) begin
                $display("RESULT: FAIL - AES_ENCRYPT never completed (timeout)");
                errors = errors + 1;
                disable do_pcpi;
            end
        end
        $display("CHECK 4 PASS: AES_ENCRYPT held pcpi_wait for %0d cycles, then pcpi_ready pulsed", wait_cycles);
        @(negedge clk);
        pcpi_valid = 1'b0;
        @(posedge clk);

        // ---- Check 5: READ_RESULT x4, reconstruct and compare ----
        do_pcpi(`AES_F3_READRESULT, 32'd0, 32'h0, rd_val, wr_val);
        ct_reconstructed[127:96] = rd_val;
        if (!wr_val) begin $display("RESULT: FAIL - READ_RESULT did not set pcpi_wr"); errors = errors + 1; end

        do_pcpi(`AES_F3_READRESULT, 32'd1, 32'h0, rd_val, wr_val);
        ct_reconstructed[95:64] = rd_val;

        do_pcpi(`AES_F3_READRESULT, 32'd2, 32'h0, rd_val, wr_val);
        ct_reconstructed[63:32] = rd_val;

        do_pcpi(`AES_F3_READRESULT, 32'd3, 32'h0, rd_val, wr_val);
        ct_reconstructed[31:0] = rd_val;

        $display("Key:                %032h", KEY);
        $display("Plaintext:          %032h", PLAINTEXT);
        $display("Ciphertext via PCPI:%032h", ct_reconstructed);
        $display("Ciphertext (NIST):  %032h", EXPECTED_CT);

        if (ct_reconstructed === EXPECTED_CT) begin
            $display("CHECK 5 PASS: PCPI-driven AES matches NIST KAT");
        end else begin
            $display("CHECK 5 FAIL: ciphertext mismatch");
            errors = errors + 1;
        end

        if (errors == 0)
            $display("TESTBENCH: ALL TESTS PASSED");
        else
            $display("TESTBENCH: %0d TEST(S) FAILED", errors);

        $finish;
    end

    initial begin
        #20000;
        $display("RESULT: GLOBAL TIMEOUT");
        $finish;
    end

endmodule