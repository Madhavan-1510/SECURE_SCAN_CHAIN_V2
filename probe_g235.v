`timescale 1ns/1ps
// PRINT-ONLY measurement probe (no assertions): all 7 columns, every field of mx_cell.
module probe_g235;
    localparam integer N = 7;
    wire [N-1:0] dn;
    wire A1[0:N-1],A2[0:N-1],A2B[0:N-1],A3[0:N-1],A3T[0:N-1],A6a[0:N-1],A6b[0:N-1],R3[0:N-1],O3[0:N-1],R3C[0:N-1],A3C[0:N-1],A1B[0:N-1],KI[0:N-1],TO[0:N-1],KL[0:N-1];
    wire [127:0] C2[0:N-1],C2B[0:N-1],C3[0:N-1],W1[0:N-1],C3B[0:N-1],C3C[0:N-1];
    wire [31:0] E[0:N-1]; wire [5:0] TM[0:N-1]; wire [31:0] C2W[0:N-1]; wire C2R[0:N-1]; wire A61[0:N-1],NI[0:N-1]; wire [11:0] WI[0:N-1]; wire [5:0] WP[0:N-1];
    genvar g;
    generate for (g = 0; g < N; g = g + 1) begin : c
        localparam integer KD = (g==0)?0:(g==1)?1:(g==2)?4:(g==3)?5:(g==4)?12:(g==5)?13:15;
        mx_cell #(.KIND(KD)) u (.a1(A1[g]), .a2(A2[g]), .a2b(A2B[g]), .a3(A3[g]), .a3_true(A3T[g]),
            .a6_256(A6a[g]), .a6_645(A6b[g]), .a3b_run(R3[g]), .a3b_ok(O3[g]), .a3c_run(R3C[g]), .a3c_ok(A3C[g]), .a1b_leak(A1B[g]),
            .key_intact_after_a6(KI[g]), .a2_ct(C2[g]), .a2b_ct(C2B[g]), .a3_ct(C3[g]), .a1_win(W1[g]),
            .a3b_ct(C3B[g]), .a3c_ct(C3C[g]), .tmo(TM[g]), .a2c_w0(C2W[g]), .a2c_wr(C2R[g]), .a6_1(A61[g]), .ni_same(NI[g]), .wm_imm(WI[g]), .wm_post(WP[g]), .tail_obs(TO[g]), .a8_keyleak(KL[g]),
            .errs(E[g]), .done(dn[g]));
    end endgenerate
    integer i;
    initial begin
        wait (&dn); #1;
        for (i = 0; i < N; i = i + 1) begin
            $display("=== col %0d (order G0,G1,G4L,G4U,G2L,G3L,G2RL) ===", i);
            $display(" a1=%b a1win=%032h a1b=%b a2=%b a2ct=%032h a2b=%b a2bct=%032h", A1[i], W1[i], A1B[i], A2[i], C2[i], A2B[i], C2B[i]);
            $display(" a3=%b a3true=%b a3ct=%032h a3b_ok=%b a3bct=%032h a3c_ok=%b a3cct=%032h", A3[i], A3T[i], C3[i], O3[i], C3B[i], A3C[i], C3C[i]);
            $display(" a6_256zero=%b a6_645zero=%b key_intact=%b errs=%0d tmo[A2c,A3c,A3b,A3,A2b,A2]=%b", A6a[i], A6b[i], KI[i], E[i], TM[i]);
            $display(" a2c_w0=%08h a2c_wr=%b a6_1zero=%b ni_same=%b", C2W[i], C2R[i], A61[i], NI[i]);
            $display(" wm_imm  (kr,rk,rr,st,bs,ks) = %0d %0d %0d %0d %0d %0d   (0=unch 1=ones 2=zero 3=other)", WI[i][11:10], WI[i][9:8], WI[i][7:6], WI[i][5:4], WI[i][3:2], WI[i][1:0]);
            $display(" wm_post (kr,bs,ks) = %0d %0d %0d   tail_obs=%b a8_keyleak=%b", WP[i][5:4], WP[i][3:2], WP[i][1:0], TO[i], KL[i]);
        end
        $finish;
    end
    initial begin #80000000; $display("PROBE TIMEOUT"); $finish; end
endmodule
