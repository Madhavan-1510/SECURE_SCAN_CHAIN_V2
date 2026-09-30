`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"
// tb_zeroize.v -- F3/A6. Checks round_key_reg/key_reg after n scan shifts
// against an independent 645-bit shift model of the whole chain.
// Chain (LSB side = scan_in): key_stage[127:0] block_stage[255:128] fsm[256]
// round_reg[260:257] state_reg[388:261] round_key_reg[516:389] key_reg[644:517]
// Locked: aes_core forces round_key_reg's scan_in to 0 (model: bit 389 := 0).
// NOTE: registers are sampled right after the last shift edge; NO trailing
// functional clock (it would advance the still-RUNNING core and pollute state).
module tb_zeroize;
    reg clk=0, resetn=0, lock_resetn=0;
    reg pcpi_valid=0; reg [31:0] pcpi_insn=0, pcpi_rs1=0, pcpi_rs2=0;
    wire pcpi_wr, pcpi_wait, pcpi_ready; wire [31:0] pcpi_rd;
    reg scan_en=0, scan_in=0; wire scan_out;
    wire locked; reg unlock_valid=0; reg [31:0] unlock_code_i=0; reg relock=0;
    localparam [31:0] UNLOCK_CODE=32'hDEC0DED1;
    scan_lock_controller #(.UNLOCK_CODE(UNLOCK_CODE)) u_lock(.clk(clk),.resetn(lock_resetn),
        .unlock_valid(unlock_valid),.unlock_code_i(unlock_code_i),.relock(relock),.locked(locked));
    aes_pcpi dut(.clk(clk),.resetn(resetn),.pcpi_valid(pcpi_valid),.pcpi_insn(pcpi_insn),
        .pcpi_rs1(pcpi_rs1),.pcpi_rs2(pcpi_rs2),.pcpi_wr(pcpi_wr),.pcpi_rd(pcpi_rd),
        .pcpi_wait(pcpi_wait),.pcpi_ready(pcpi_ready),
        .dbg_key_stage(),.dbg_block_stage(),.dbg_core_key_reg(),.dbg_core_round_key_reg(),
        .dbg_core_state_reg(),.dbg_core_round_reg(),
        .scan_en(scan_en),.scan_in(scan_in),.scan_out(scan_out),.locked(locked));
    always #5 clk=~clk;
    localparam [127:0] REAL_KEY =128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] PLAINTEXT=128'h00112233445566778899AABBCCDDEEFF;
    integer errors=0, wait_cycles;
    function [31:0] mk_insn(input [2:0] f3); mk_insn={7'b0,5'b0,5'b0,f3,5'b0,`AES_OPCODE}; endfunction
    task do_pcpi(input [2:0] f3,input [31:0] rs1v,input [31:0] rs2v,output [31:0] rdv,output wrv);
        begin
            @(negedge clk); pcpi_valid=1; pcpi_insn=mk_insn(f3); pcpi_rs1=rs1v; pcpi_rs2=rs2v;
            @(posedge clk); wait_cycles=0;
            while(!pcpi_ready) begin @(posedge clk); wait_cycles=wait_cycles+1;
                if(wait_cycles>200) begin $display("ERROR: pcpi timeout f3=%0d",f3); errors=errors+1; disable do_pcpi; end end
            #1; rdv=pcpi_rd; wrv=pcpi_wr; @(negedge clk); pcpi_valid=0;
        end
    endtask
    reg [31:0] rd_val; reg wr_val;
    task check(input cond, input [1023:0] msg);
        begin if(!cond) begin $display("FAIL: %0s",msg); errors=errors+1; end
              else $display("PASS: %0s",msg); end
    endtask

    reg [644:0] W;      // independent model of full chain
    task model_shift(input lock_val, input integer n, input fed);
        integer c;
        begin
            for(c=0;c<n;c=c+1) begin
                W = {W[643:0], fed};
                if(lock_val) W[389] = 1'b0;   // documented lock behaviour
            end
        end
    endtask

    task run_shift(input lock_val, input integer n_shifts, input fed_val);
        integer k;
        begin
            relock=1; unlock_valid=0; resetn=0; lock_resetn=0;
            repeat(3) @(posedge clk); #1 resetn=1; lock_resetn=1; @(posedge clk); #1 relock=0;
            if(!lock_val) begin
                @(negedge clk); unlock_code_i=UNLOCK_CODE; unlock_valid=1;
                @(posedge clk); #1 unlock_valid=0;
            end
            check(locked===(lock_val?1'b1:1'b0),"lock state set as requested");
            do_pcpi(`AES_F3_LOADKEY,32'd0,REAL_KEY[127:96],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd1,REAL_KEY[95:64],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd2,REAL_KEY[63:32],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd3,REAL_KEY[31:0],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADBLOCK,32'd0,PLAINTEXT[127:96],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADBLOCK,32'd1,PLAINTEXT[95:64],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADBLOCK,32'd2,PLAINTEXT[63:32],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADBLOCK,32'd3,PLAINTEXT[31:0],rd_val,wr_val);
            @(negedge clk); pcpi_valid=1; pcpi_insn=mk_insn(`AES_F3_ENCRYPT); pcpi_rs1=0; pcpi_rs2=0;
            @(posedge clk); repeat(6) @(posedge clk); #1; pcpi_valid=0;
            check(dut.u_aes_core.round_key_reg_q!==128'h0,"sanity: round_key_reg non-zero before scan");
            W = {dut.u_aes_core.key_reg_q, dut.u_aes_core.round_key_reg_q, dut.u_aes_core.state_reg_q,
                 dut.u_aes_core.round_reg_q, dut.fsm_state_q, dut.block_stage_q, dut.key_stage_q};
            model_shift(lock_val,n_shifts,fed_val);
            @(negedge clk); scan_en=1; scan_in=fed_val;
            for(k=0;k<n_shifts;k=k+1) @(negedge clk);
            scan_en=0;   // sample now: no trailing functional edge
        end
    endtask

    integer sp[0:9]; integer i;
    initial begin
        sp[0]=0; sp[1]=1; sp[2]=64; sp[3]=127; sp[4]=128; sp[5]=129; sp[6]=200; sp[7]=255; sp[8]=256; sp[9]=257;
        $display("tb_zeroize: F3/A6, exact model comparison + zeroize boundaries");
        $display("---- LOCKED (attacker feeds all-1s) ----");
        for(i=0;i<10;i=i+1) begin
            $display("  [LOCKED n_shifts=%0d]",sp[i]);
            run_shift(1'b1,sp[i],1'b1);
            check(dut.u_aes_core.round_key_reg_q===W[516:389],"LOCKED: round_key_reg == independent model");
            check(dut.u_aes_core.key_reg_q===W[644:517],"LOCKED: key_reg == independent model");
            if(sp[i]>=128) check(dut.u_aes_core.round_key_reg_q===128'h0,"LOCKED: round_key_reg===0 (>=128 shifts)");
            if(sp[i]>=256) check(dut.u_aes_core.key_reg_q===128'h0,"LOCKED: key_reg===0 (>=256 shifts)");
        end
        $display("---- UNLOCKED negative control ----");
        for(i=0;i<10;i=i+1) begin
            $display("  [UNLOCKED n_shifts=%0d]",sp[i]);
            run_shift(1'b0,sp[i],1'b1);
            check(dut.u_aes_core.round_key_reg_q===W[516:389],"UNLOCKED: round_key_reg == independent model");
            check(dut.u_aes_core.key_reg_q===W[644:517],"UNLOCKED: key_reg == independent model");
            if(sp[i]>=128) check(dut.u_aes_core.round_key_reg_q!==128'h0,"UNLOCKED: round_key_reg NOT zero (>=128) -- assertion is lock-sensitive");
            if(sp[i]>=256) check(dut.u_aes_core.key_reg_q!==128'h0,"UNLOCKED: key_reg NOT zero (>=256) -- assertion is lock-sensitive");
        end
        if(errors==0) $display("TESTBENCH: ALL TESTS PASSED"); else $display("TESTBENCH: %0d TEST(S) FAILED",errors);
        $finish;
    end
    initial begin #4000000; $display("RESULT: GLOBAL TIMEOUT"); $finish; end
endmodule