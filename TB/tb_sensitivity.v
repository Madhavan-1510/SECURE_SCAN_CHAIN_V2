`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"
// tb_sensitivity.v -- Paper 2 Phase 3 (README sec 8): sensitivity map.
// For N_PAIRS random (Ka,Kb,Pa,Pb): runs (Ka,Pa),(Kb,Pa),(Ka,Pb); each run walks
// one timeline and snapshots the 645-bit chain at 16 capture points:
//   cp0  idle after LOADKEY          cp1  idle after LOADBLOCK
//   cp2..cp13  ENCRYPT+k edges, k=0..11 (k=0 is the edge that accepts ENCRYPT)
//   cp14 DONE (core DONE, pcpi idle) cp15 after 4x READRESULT
// key-dep(bit,cp)   : bit differs between (Ka,Pa) and (Kb,Pa)
// plain-dep(bit,cp) : bit differs between (Ka,Pa) and (Ka,Pb)
// Snapshot = hierarchical read of the 645 scanned flops in chain order
// (unlocked scan is a lossless shift; equivalence is checked at 3 points below).
// Chain: key_stage[127:0] block_stage[255:128] fsm[256] round[260:257]
//        state[388:261] round_key[516:389] key_reg[644:517]
module tb_sensitivity;
    parameter N_PAIRS = 32;
    localparam NCP = 16;
    reg clk=0, resetn=0;
    reg pcpi_valid=0; reg [31:0] pcpi_insn=0, pcpi_rs1=0, pcpi_rs2=0;
    wire pcpi_wr, pcpi_wait, pcpi_ready; wire [31:0] pcpi_rd;
    reg scan_en=0, scan_in=0; wire scan_out;
    aes_pcpi dut(.clk(clk),.resetn(resetn),.pcpi_valid(pcpi_valid),.pcpi_insn(pcpi_insn),
        .pcpi_rs1(pcpi_rs1),.pcpi_rs2(pcpi_rs2),.pcpi_wr(pcpi_wr),.pcpi_rd(pcpi_rd),
        .pcpi_wait(pcpi_wait),.pcpi_ready(pcpi_ready),
        .dbg_key_stage(),.dbg_block_stage(),.dbg_core_key_reg(),.dbg_core_round_key_reg(),
        .dbg_core_state_reg(),.dbg_core_round_reg(),
        .scan_en(scan_en),.scan_in(scan_in),.scan_out(scan_out),.locked(1'b0));
    always #5 clk=~clk;

    integer errors=0, wait_cycles;
    function [31:0] mk_insn(input [2:0] f3); mk_insn={7'b0,5'b0,5'b0,f3,5'b0,`AES_OPCODE}; endfunction
    task do_pcpi(input [2:0] f3,input [31:0] rs1v,input [31:0] rs2v,output [31:0] rdv,output wrv);
        begin
            @(negedge clk); pcpi_valid=1; pcpi_insn=mk_insn(f3); pcpi_rs1=rs1v; pcpi_rs2=rs2v;
            @(posedge clk); wait_cycles=0;
            while(!pcpi_ready) begin @(posedge clk); wait_cycles=wait_cycles+1;
                if(wait_cycles>200) begin $display("ERROR pcpi timeout"); errors=errors+1; disable do_pcpi; end end
            #1; rdv=pcpi_rd; wrv=pcpi_wr; @(negedge clk); pcpi_valid=0;
        end
    endtask
    reg [31:0] rd_val; reg wr_val;

    function [644:0] chain_now(input dummy);
        begin chain_now = {dut.u_aes_core.key_reg_q, dut.u_aes_core.round_key_reg_q,
            dut.u_aes_core.state_reg_q, dut.u_aes_core.round_reg_q, dut.fsm_state_q,
            dut.block_stage_q, dut.key_stage_q}; end
    endfunction

    reg [644:0] snap [0:3*NCP-1];      // which*NCP+cp
    reg [127:0] ct_run [0:2];
    integer scan_check_cp;             // -1 = none
    reg stopped;
    integer scan_ok=0;

    task scan_verify(input [644:0] ref_snap, input integer cp);
        integer i; reg [644:0] cap;
        begin
            scan_en=1; scan_in=0;
            cap[644]=scan_out;
            for(i=0;i<644;i=i+1) begin @(posedge clk); #1; cap[643-i]=scan_out; end
            scan_en=0;
            if(cap===ref_snap) begin scan_ok=scan_ok+1; $display("SCAN-EQUIV PASS at cp%0d: 645-bit scan capture == hierarchical snapshot",cp); end
            else begin $display("SCAN-EQUIV FAIL at cp%0d",cp); errors=errors+1; end
        end
    endtask

    task snapit(input integer which, input integer cp);
        begin
            snap[which*NCP+cp]=chain_now(0);
            if(scan_check_cp==cp) begin scan_verify(snap[which*NCP+cp],cp); stopped=1; end
        end
    endtask

    task run_timeline(input [127:0] K, input [127:0] P, input integer which);
        integer k; reg [127:0] ct;
        begin
            stopped=0;
            resetn=0; scan_en=0; scan_in=0; pcpi_valid=0;
            repeat(3) @(posedge clk); #1 resetn=1; @(posedge clk); #1;
            do_pcpi(`AES_F3_LOADKEY,32'd0,K[127:96],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd1,K[95:64],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd2,K[63:32],rd_val,wr_val);
            do_pcpi(`AES_F3_LOADKEY,32'd3,K[31:0],rd_val,wr_val);
            @(posedge clk); #1; snapit(which,0);
            if(!stopped) begin
                do_pcpi(`AES_F3_LOADBLOCK,32'd0,P[127:96],rd_val,wr_val);
                do_pcpi(`AES_F3_LOADBLOCK,32'd1,P[95:64],rd_val,wr_val);
                do_pcpi(`AES_F3_LOADBLOCK,32'd2,P[63:32],rd_val,wr_val);
                do_pcpi(`AES_F3_LOADBLOCK,32'd3,P[31:0],rd_val,wr_val);
                @(posedge clk); #1; snapit(which,1);
            end
            if(!stopped) begin
                @(negedge clk); pcpi_valid=1; pcpi_insn=mk_insn(`AES_F3_ENCRYPT); pcpi_rs1=0; pcpi_rs2=0;
                @(posedge clk); #1; snapit(which,2);           // k=0
                @(negedge clk); pcpi_valid=0;                  // single-cycle ENCRYPT pulse
                for(k=1;k<12;k=k+1) if(!stopped) begin @(posedge clk); #1; snapit(which,2+k); end
            end
            if(!stopped) begin
                wait_cycles=0;
                while(!(dut.u_aes_core.fsm_state==2'd2 && dut.fsm_state_q==1'b0) && wait_cycles<50) begin
                    @(posedge clk); #1; wait_cycles=wait_cycles+1; end
                snapit(which,14);
            end
            if(!stopped) begin
                do_pcpi(`AES_F3_READRESULT,32'd0,32'h0,rd_val,wr_val); ct[127:96]=rd_val;
                do_pcpi(`AES_F3_READRESULT,32'd1,32'h0,rd_val,wr_val); ct[95:64]=rd_val;
                do_pcpi(`AES_F3_READRESULT,32'd2,32'h0,rd_val,wr_val); ct[63:32]=rd_val;
                do_pcpi(`AES_F3_READRESULT,32'd3,32'h0,rd_val,wr_val); ct[31:0]=rd_val;
                @(posedge clk); #1; snapit(which,15);
                ct_run[which]=ct;
            end
        end
    endtask

    integer seed=32'h5EC5CA17;
    function [127:0] rand128(input dummy);
        begin rand128={$random(seed),$random(seed),$random(seed),$random(seed)}; end
    endfunction

    integer kd_cnt [0:NCP*645-1];
    integer pd_cnt [0:NCP*645-1];
    reg [127:0] Ka,Kb,Pa,Pb,ctref;
    integer p,cp,b,f;
    reg [644:0] dk, dp;
    localparam [127:0] KAT_K=128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] KAT_P=128'h00112233445566778899AABBCCDDEEFF;
    localparam [127:0] KAT_C=128'h69C4E0D86A7B0430D8CDB78070B4C55A;

    initial begin
        scan_check_cp=-1;
        for(b=0;b<NCP*645;b=b+1) begin kd_cnt[b]=0; pd_cnt[b]=0; end

        // ---- scan-equivalence check: 3 points (idle, mid-freeze, DONE) ----
        $display("== scan vs hierarchical snapshot equivalence ==");
        scan_check_cp=1;  run_timeline(KAT_K,KAT_P,0);
        scan_check_cp=8;  run_timeline(KAT_K,KAT_P,0);
        scan_check_cp=14; run_timeline(KAT_K,KAT_P,0);
        scan_check_cp=-1;

        // ---- KAT run: dump snapshots for F5/F6 analysis + sanity ----
        run_timeline(KAT_K,KAT_P,0);
        if(ct_run[0]!==KAT_C) begin $display("FAIL: KAT ciphertext mismatch"); errors=errors+1; end
        else $display("PASS: KAT ciphertext via timeline == NIST KAT");
        f=$fopen("kat_snaps.txt","w");
        for(cp=0;cp<NCP;cp=cp+1) $fdisplay(f,"%0d %0161h",cp,snap[cp]);
        $fclose(f);

        // ---- random pairs ----
        for(p=0;p<N_PAIRS;p=p+1) begin
            Ka=rand128(0); Kb=rand128(0); Pa=rand128(0); Pb=rand128(0);
            run_timeline(Ka,Pa,0); run_timeline(Kb,Pa,1); run_timeline(Ka,Pb,2);
            for(cp=0;cp<NCP;cp=cp+1) begin
                dk=snap[0*NCP+cp]^snap[1*NCP+cp];
                dp=snap[0*NCP+cp]^snap[2*NCP+cp];
                for(b=0;b<645;b=b+1) begin
                    if(dk[b]) kd_cnt[cp*645+b]=kd_cnt[cp*645+b]+1;
                    if(dp[b]) pd_cnt[cp*645+b]=pd_cnt[cp*645+b]+1;
                end
            end
            // F5 direct check: at cp3 (k=1) core has loaded, state_reg == P^K, round_reg==1
            if(snap[0*NCP+3][388:261]!==(Pa^Ka) || snap[0*NCP+3][260:257]!==4'd1) begin
                $display("FAIL F5: state_reg != P^K at k=1 (pair %0d)",p); errors=errors+1; end
            // public: state_reg at DONE == ciphertext read back
            if(snap[0*NCP+14][388:261]!==ct_run[0] || snap[0*NCP+15][388:261]!==ct_run[0]) begin
                $display("FAIL: state_reg at DONE/after-read != ciphertext (pair %0d)",p); errors=errors+1; end
        end
        $display("F5 check (state_reg == P xor K at k=1) run on %0d random pairs", N_PAIRS);

        f=$fopen("sens_bits.csv","w");
        $fdisplay(f,"cp,bit,keydep_pairs,plaindep_pairs,n_pairs");
        for(cp=0;cp<NCP;cp=cp+1) for(b=0;b<645;b=b+1)
            $fdisplay(f,"%0d,%0d,%0d,%0d,%0d",cp,b,kd_cnt[cp*645+b],pd_cnt[cp*645+b],N_PAIRS);
        $fclose(f);

        if(scan_ok!==3) begin $display("FAIL: scan equivalence not confirmed at all 3 points"); errors=errors+1; end
        if(errors==0) $display("TESTBENCH: ALL TESTS PASSED"); else $display("TESTBENCH: %0d TEST(S) FAILED",errors);
        $finish;
    end
    initial begin #400000000; $display("RESULT: GLOBAL TIMEOUT"); $finish; end
endmodule