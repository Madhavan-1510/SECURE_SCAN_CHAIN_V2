// Write-side non-interference miter.
// Two copies of aes_pcpi_def #(DL), identical functional inputs and the SAME
// scan_en, but INDEPENDENT scan_in (scan_in_a vs scan_in_b), held locked=1.
// If an attacker's scan_in cannot change any register while locked, the two
// copies' datapath stays bit-identical forever. Asserting equality therefore
// proves "scan writes have no effect while locked" (the G4 property); on a
// design where scan writes DO land (G1), the assertion must fail.
`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"
module fv_writeblock #(parameter integer DL = 4) (input clk);
    (* anyseq *) reg scan_en, scan_in_a, scan_in_b;
    wire locked = 1'b1;                       // held locked

    wire [127:0] ksa,bsa,kra,rka,sra,  ksb,bsb,krb,rkb,srb;
    wire [3:0]   rra, rrb;

    aes_pcpi_def #(.DEFENSE_LEVEL(DL)) a (
        .clk(clk), .resetn(1'b1),
        .pcpi_valid(1'b0), .pcpi_insn(32'h0), .pcpi_rs1(32'h0), .pcpi_rs2(32'h0),
        .pcpi_wr(), .pcpi_rd(), .pcpi_wait(), .pcpi_ready(),
        .dbg_key_stage(ksa), .dbg_block_stage(bsa), .dbg_core_key_reg(kra),
        .dbg_core_round_key_reg(rka), .dbg_core_state_reg(sra), .dbg_core_round_reg(rra),
        .scan_en(scan_en), .scan_in(scan_in_a), .scan_out(), .locked(locked));

    aes_pcpi_def #(.DEFENSE_LEVEL(DL)) b (
        .clk(clk), .resetn(1'b1),
        .pcpi_valid(1'b0), .pcpi_insn(32'h0), .pcpi_rs1(32'h0), .pcpi_rs2(32'h0),
        .pcpi_wr(), .pcpi_rd(), .pcpi_wait(), .pcpi_ready(),
        .dbg_key_stage(ksb), .dbg_block_stage(bsb), .dbg_core_key_reg(krb),
        .dbg_core_round_key_reg(rkb), .dbg_core_state_reg(srb), .dbg_core_round_reg(rrb),
        .scan_en(scan_en), .scan_in(scan_in_b), .scan_out(), .locked(locked));

    always @(posedge clk)
        assert (ksa==ksb && bsa==bsb && kra==krb && rka==rkb && sra==srb && rra==rrb);
endmodule
