// ============================================================================
// tb_double_encrypt_control.v
//
// CONTROL EXPERIMENT -- not part of the permanent regression suite.
//
// Purpose: tb_scan_resume.v reported IDENTICAL wrong ciphertexts across
// every shift count from 0 to 1290, in both lock states. If scan-induced
// corruption of round_reg/state_reg were the mechanism, different shift
// counts should leave different residues and produce DIFFERENT wrong
// results. Getting the exact same wrong answer at n_shifts=0 (where
// scan_en never even reaches a clock edge) strongly suggests the failure
// has nothing to do with scan at all.
//
// This test removes scan completely and asks the more basic question:
// can this DUT run a SECOND full LOADKEY/LOADBLOCK/ENCRYPT/READRESULT
// sequence immediately after a FIRST one completes, through the normal
// PCPI interface, with NO scan_en ever asserted and NO reset in between?
//
// This exact scenario -- two operations back-to-back without an
// intervening resetn pulse -- does not appear to be covered by
// tb_aes_pcpi.v (single sequence only) or tb_scan_lock.v's run_attack
// (which explicitly resets resetn at the start of every iteration, per
// its own comment: "Reset the coprocessor's FUNCTIONAL state only,
// between runs"). If this control ALSO fails, the tb_scan_resume.v
// result is not evidence of a scan-related bug -- it is evidence of a
// more fundamental multi-operation sequencing issue that scan happened
// to expose only because it was the first test to chain two operations
// without a reset.
// ============================================================================
`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"

module tb_double_encrypt_control;

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
        // scan_en tied LOW for this entire test -- never touched, not
        // even once. This is the key difference from tb_scan_resume.v.
        .scan_en(1'b0), .scan_in(1'b0), .scan_out(),
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

    task run_kat(output [127:0] ct);
        begin
            do_pcpi(`AES_F3_LOADKEY, 32'd0, KEY[127:96], rd_val, wr_val);
            do_pcpi(`AES_F3_LOADKEY, 32'd1, KEY[95:64],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADKEY, 32'd2, KEY[63:32],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADKEY, 32'd3, KEY[31:0],   rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd0, PLAINTEXT[127:96], rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd1, PLAINTEXT[95:64],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd2, PLAINTEXT[63:32],  rd_val, wr_val);
            do_pcpi(`AES_F3_LOADBLOCK, 32'd3, PLAINTEXT[31:0],   rd_val, wr_val);
            do_pcpi(`AES_F3_ENCRYPT, 32'd0, 32'd0, rd_val, wr_val);
            do_pcpi(`AES_F3_READRESULT, 32'd0, 32'h0, rd_val, wr_val); ct[127:96] = rd_val;
            do_pcpi(`AES_F3_READRESULT, 32'd1, 32'h0, rd_val, wr_val); ct[95:64]  = rd_val;
            do_pcpi(`AES_F3_READRESULT, 32'd2, 32'h0, rd_val, wr_val); ct[63:32]  = rd_val;
            do_pcpi(`AES_F3_READRESULT, 32'd3, 32'h0, rd_val, wr_val); ct[31:0]   = rd_val;
        end
    endtask

    reg [127:0] ct1, ct2;

    initial begin
        resetn = 0;
        repeat (3) @(posedge clk);
        #1 resetn = 1;
        @(posedge clk);

        $display("================================================================");
        $display("CONTROL: two back-to-back KATs, scan_en NEVER asserted, no reset between them");
        $display("================================================================");

        run_kat(ct1);
        $display("KAT #1 ciphertext: %032h  (expected %032h)  %s",
                  ct1, EXPECTED_CT, (ct1 === EXPECTED_CT) ? "MATCH" : "MISMATCH");
        if (ct1 !== EXPECTED_CT) errors = errors + 1;

        // NO reset here. Immediately run a second, identical KAT through
        // the same PCPI interface, exactly as run_kat #1.
        run_kat(ct2);
        $display("KAT #2 ciphertext: %032h  (expected %032h)  %s",
                  ct2, EXPECTED_CT, (ct2 === EXPECTED_CT) ? "MATCH" : "MISMATCH");
        if (ct2 !== EXPECTED_CT) errors = errors + 1;

        $display("================================================================");
        if (errors == 0)
            $display("TESTBENCH: ALL TESTS PASSED -- back-to-back encryption without reset works with scan fully out of the picture");
        else
            $display("TESTBENCH: %0d TEST(S) FAILED -- failure reproduces WITHOUT any scan_en activity", errors);
        $display("================================================================");

        $finish;
    end

    initial begin
        #20000;
        $display("RESULT: GLOBAL TIMEOUT");
        $finish;
    end

endmodule