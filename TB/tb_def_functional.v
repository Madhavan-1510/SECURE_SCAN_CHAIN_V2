`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"
// tb_def_functional.v -- Paper 2 Phase 5: functional correctness of every aes_pcpi_def
// variant (DEFENSE_LEVEL 1..5), locked and unlocked, with scan_en never asserted for
// checks F1/F2, and asserted for F3.
//   F1  NIST KAT bit-exact
//   F2  second KAT immediately after the first, no reset (the tb_double_encrypt_control case)
//   F3  scan session (60 shifts of 0, mid-computation) then a fresh KAT with NO reset,
//       the tb_scan_resume scenario. Expected outcome is REPORTED per cell, not assumed:
//       unlocked variants behave like the original (tb_scan_resume: unlocked fails? see log),
//       so F3 is informational; F1/F2 are gated.
module def_cell #(parameter integer LVL = 4, parameter LK = 1'b1) (output reg done, output reg f1, output reg f2, output reg f3, output reg [127:0] ct3);
    localparam [127:0] KEY = 128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] PT  = 128'h00112233445566778899AABBCCDDEEFF;
    localparam [127:0] CT  = 128'h69C4E0D86A7B0430D8CDB78070B4C55A;
    reg clk = 0, resetn = 0; always #5 clk = ~clk;
    reg pv = 0; reg [31:0] insn = 0, rs1 = 0, rs2 = 0; wire wr, wt, rdy, so; wire [31:0] rd;
    reg se = 0, si = 0;
    aes_pcpi_def #(.DEFENSE_LEVEL(LVL)) dut (.clk(clk), .resetn(resetn), .pcpi_valid(pv), .pcpi_insn(insn),
        .pcpi_rs1(rs1), .pcpi_rs2(rs2), .pcpi_wr(wr), .pcpi_rd(rd), .pcpi_wait(wt), .pcpi_ready(rdy),
        .dbg_key_stage(), .dbg_block_stage(), .dbg_core_key_reg(), .dbg_core_round_key_reg(),
        .dbg_core_state_reg(), .dbg_core_round_reg(), .scan_en(se), .scan_in(si), .scan_out(so), .locked(LK));
    function [31:0] mk(input [2:0] f3); mk = {7'b0,5'b0,5'b0,f3,5'b0,`AES_OPCODE}; endfunction
    integer w; reg [31:0] r;
    task op(input [2:0] f3, input [31:0] a, input [31:0] b, output [31:0] o);
        begin @(negedge clk); pv=1; insn=mk(f3); rs1=a; rs2=b; @(posedge clk); w=0;
              while(!rdy && w<100) begin @(posedge clk); w=w+1; end
              #1; o=rd; @(negedge clk); pv=0; end
    endtask
    task kat(output [127:0] c);
        begin
            op(`AES_F3_LOADKEY,0,KEY[127:96],r); op(`AES_F3_LOADKEY,1,KEY[95:64],r);
            op(`AES_F3_LOADKEY,2,KEY[63:32],r);  op(`AES_F3_LOADKEY,3,KEY[31:0],r);
            op(`AES_F3_LOADBLOCK,0,PT[127:96],r); op(`AES_F3_LOADBLOCK,1,PT[95:64],r);
            op(`AES_F3_LOADBLOCK,2,PT[63:32],r);  op(`AES_F3_LOADBLOCK,3,PT[31:0],r);
            op(`AES_F3_ENCRYPT,0,0,r);
            op(`AES_F3_READRESULT,0,0,r); c[127:96]=r; op(`AES_F3_READRESULT,1,0,r); c[95:64]=r;
            op(`AES_F3_READRESULT,2,0,r); c[63:32]=r;  op(`AES_F3_READRESULT,3,0,r); c[31:0]=r;
        end
    endtask
    reg [127:0] c1, c2; integer k;
    initial begin
        done=0; f1=0; f2=0; f3=0;
        repeat(3) @(posedge clk); #1 resetn=1; @(posedge clk);
        kat(c1); f1=(c1===CT);
        kat(c2); f2=(c2===CT);
        // F3: reset, start ENCRYPT, freeze 6 cycles, 60 shifts, drop scan_en, fresh KAT, no reset
        resetn=0; repeat(3) @(posedge clk); #1 resetn=1; @(posedge clk);
        op(`AES_F3_LOADKEY,0,KEY[127:96],r); op(`AES_F3_LOADKEY,1,KEY[95:64],r);
        op(`AES_F3_LOADKEY,2,KEY[63:32],r);  op(`AES_F3_LOADKEY,3,KEY[31:0],r);
        op(`AES_F3_LOADBLOCK,0,PT[127:96],r); op(`AES_F3_LOADBLOCK,1,PT[95:64],r);
        op(`AES_F3_LOADBLOCK,2,PT[63:32],r);  op(`AES_F3_LOADBLOCK,3,PT[31:0],r);
        @(negedge clk); pv=1; insn=mk(`AES_F3_ENCRYPT); @(posedge clk); repeat(6) @(posedge clk); #1 pv=0;
        @(negedge clk); se=1; si=0; for(k=0;k<60;k=k+1) @(negedge clk); se=0;
        kat(ct3); f3=(ct3===CT);
        done=1;
    end
endmodule

module tb_def_functional;
    wire [9:0] dn, f1, f2, f3; wire [127:0] c3 [0:9];
    genvar g;
    generate for (g=0; g<10; g=g+1) begin : c
        def_cell #(.LVL(g%5+1), .LK(g<5)) u (.done(dn[g]), .f1(f1[g]), .f2(f2[g]), .f3(f3[g]), .ct3(c3[g]));
    end endgenerate
    integer errors=0, i;
    initial begin
        wait(&dn); #1;
        for (i=0;i<10;i=i+1) begin
            if (f1[i] && f2[i]) $display("PASS: L%0d %s: KAT bit-exact, and again back-to-back without reset", i%5+1, (i<5)?"LOCKED  ":"UNLOCKED");
            else begin $display("FAIL: L%0d %s: f1=%b f2=%b", i%5+1, (i<5)?"LOCKED  ":"UNLOCKED", f1[i], f2[i]); errors=errors+1; end
            $display("  info: L%0d %s scan-session-then-fresh-KAT (no reset): %s ct=%032h", i%5+1, (i<5)?"locked  ":"unlocked", f3[i]?"OK":"WRONG", c3[i]);
        end
        if (errors==0) $display("TESTBENCH: ALL TESTS PASSED"); else $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $finish;
    end
    initial begin #20000000; $display("RESULT: GLOBAL TIMEOUT"); $finish; end
endmodule