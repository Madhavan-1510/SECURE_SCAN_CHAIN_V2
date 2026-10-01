// Minimal formal check: G4 (DEFENSE_LEVEL=4) masks scan_out while locked,
// for ALL inputs (not just test vectors). All DUT inputs are free.
`timescale 1ns/1ps
module fv_readlock (input clk);
    (* anyseq *) reg         resetn, start_i, scan_en, scan_in, locked;
    (* anyseq *) reg [127:0] key_i, block_i;
    wire scan_out;
    aes_core_def #(.DEFENSE_LEVEL(4)) dut (
        .clk(clk), .resetn(resetn), .start_i(start_i),
        .key_i(key_i), .block_i(block_i),
        .busy_o(), .done_o(), .ciphertext_o(),
        .dbg_key_reg(), .dbg_round_key_reg(), .dbg_state_reg(), .dbg_round_reg(),
        .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out),
        .locked(locked), .scan_out_tail());
    always @(posedge clk)
        if (locked) assert (scan_out == 1'b0);   // read lock holds
endmodule
