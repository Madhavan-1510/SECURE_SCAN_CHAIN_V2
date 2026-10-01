// Write-side non-interference miter (bounded from reset).
// Two copies of aes_pcpi_def #(DL): identical functional inputs and the SAME
// scan_en, but INDEPENDENT scan_in. Both are reset together (rc counter holds
// resetn low for 3 cycles) so they start from the same state, then held
// locked=1 with no PCPI activity. The ONLY difference an attacker introduces
// is scan_in. If scan writes cannot affect any register while locked, the two
// copies' key/datapath registers stay bit-identical. Asserting that equality,
// model-checked from reset, proves the G4 write-block property; on G1 (where
// scan writes land) the check fails with a counterexample.
`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"
module fv_writeblock #(parameter integer DL = 4) (input clk);
    reg [1:0] rc = 2'd0;
    always @(posedge clk) if (rc != 2'd3) rc <= rc + 2'd1;
    wire resetn = (rc == 2'd3);               // low for 3 cycles, then high
    wire locked = 1'b1;

    (* anyseq *) reg scan_en, scan_in_a, scan_in_b;

    wire [127:0] ksa,bsa,kra,rka,sra,  ksb,bsb,krb,rkb,srb;
    wire [3:0]   rra, rrb;

    aes_pcpi_def #(.DEFENSE_LEVEL(DL)) a (
        .clk(clk), .resetn(resetn),
        .pcpi_valid(1'b0), .pcpi_insn(32'h0), .pcpi_rs1(32'h0), .pcpi_rs2(32'h0),
        .pcpi_wr(), .pcpi_rd(), .pcpi_wait(), .pcpi_ready(),
        .dbg_key_stage(ksa), .dbg_block_stage(bsa), .dbg_core_key_reg(kra),
        .dbg_core_round_key_reg(rka), .dbg_core_state_reg(sra), .dbg_core_round_reg(rra),
        .scan_en(scan_en), .scan_in(scan_in_a), .scan_out(), .locked(locked));

    aes_pcpi_def #(.DEFENSE_LEVEL(DL)) b (
        .clk(clk), .resetn(resetn),
        .pcpi_valid(1'b0), .pcpi_insn(32'h0), .pcpi_rs1(32'h0), .pcpi_rs2(32'h0),
        .pcpi_wr(), .pcpi_rd(), .pcpi_wait(), .pcpi_ready(),
        .dbg_key_stage(ksb), .dbg_block_stage(bsb), .dbg_core_key_reg(krb),
        .dbg_core_round_key_reg(rkb), .dbg_core_state_reg(srb), .dbg_core_round_reg(rrb),
        .scan_en(scan_en), .scan_in(scan_in_b), .scan_out(), .locked(locked));

    always @(posedge clk)
        if (resetn)
            assert (ksa==ksb && bsa==bsb && kra==krb && rka==rkb && sra==srb && rra==rrb);
endmodule
