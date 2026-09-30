// ============================================================================
// aes_sbox.v
//
// Purpose:
//   Combinational AES forward S-box lookup (FIPS-197 Figure 7). Pure lookup
//   table, no state, no secrets stored here -- this is public, standardized
//   constant data, not something a scan attack needs to target.
//
// Interface:
//   in_byte  -> out_byte = SBOX[in_byte]
//
// Clock/Reset: none (fully combinational).
//
// Scan relevance:
//   Not scan-modeled. This block holds no secret state; it is pure constant
//   ROM/logic. Excluding it from the scan chain has no security implication
//   since there is nothing here to observe or control that isn't already
//   public.
// ============================================================================
`timescale 1ns/1ps

module aes_sbox (
    input  wire [7:0] in_byte,
    output wire [7:0] out_byte
);

    reg [7:0] sbox_table [0:255];

    initial begin
        sbox_table[8'h00]=8'h63; sbox_table[8'h01]=8'h7c; sbox_table[8'h02]=8'h77; sbox_table[8'h03]=8'h7b;
        sbox_table[8'h04]=8'hf2; sbox_table[8'h05]=8'h6b; sbox_table[8'h06]=8'h6f; sbox_table[8'h07]=8'hc5;
        sbox_table[8'h08]=8'h30; sbox_table[8'h09]=8'h01; sbox_table[8'h0a]=8'h67; sbox_table[8'h0b]=8'h2b;
        sbox_table[8'h0c]=8'hfe; sbox_table[8'h0d]=8'hd7; sbox_table[8'h0e]=8'hab; sbox_table[8'h0f]=8'h76;
        sbox_table[8'h10]=8'hca; sbox_table[8'h11]=8'h82; sbox_table[8'h12]=8'hc9; sbox_table[8'h13]=8'h7d;
        sbox_table[8'h14]=8'hfa; sbox_table[8'h15]=8'h59; sbox_table[8'h16]=8'h47; sbox_table[8'h17]=8'hf0;
        sbox_table[8'h18]=8'had; sbox_table[8'h19]=8'hd4; sbox_table[8'h1a]=8'ha2; sbox_table[8'h1b]=8'haf;
        sbox_table[8'h1c]=8'h9c; sbox_table[8'h1d]=8'ha4; sbox_table[8'h1e]=8'h72; sbox_table[8'h1f]=8'hc0;
        sbox_table[8'h20]=8'hb7; sbox_table[8'h21]=8'hfd; sbox_table[8'h22]=8'h93; sbox_table[8'h23]=8'h26;
        sbox_table[8'h24]=8'h36; sbox_table[8'h25]=8'h3f; sbox_table[8'h26]=8'hf7; sbox_table[8'h27]=8'hcc;
        sbox_table[8'h28]=8'h34; sbox_table[8'h29]=8'ha5; sbox_table[8'h2a]=8'he5; sbox_table[8'h2b]=8'hf1;
        sbox_table[8'h2c]=8'h71; sbox_table[8'h2d]=8'hd8; sbox_table[8'h2e]=8'h31; sbox_table[8'h2f]=8'h15;
        sbox_table[8'h30]=8'h04; sbox_table[8'h31]=8'hc7; sbox_table[8'h32]=8'h23; sbox_table[8'h33]=8'hc3;
        sbox_table[8'h34]=8'h18; sbox_table[8'h35]=8'h96; sbox_table[8'h36]=8'h05; sbox_table[8'h37]=8'h9a;
        sbox_table[8'h38]=8'h07; sbox_table[8'h39]=8'h12; sbox_table[8'h3a]=8'h80; sbox_table[8'h3b]=8'he2;
        sbox_table[8'h3c]=8'heb; sbox_table[8'h3d]=8'h27; sbox_table[8'h3e]=8'hb2; sbox_table[8'h3f]=8'h75;
        sbox_table[8'h40]=8'h09; sbox_table[8'h41]=8'h83; sbox_table[8'h42]=8'h2c; sbox_table[8'h43]=8'h1a;
        sbox_table[8'h44]=8'h1b; sbox_table[8'h45]=8'h6e; sbox_table[8'h46]=8'h5a; sbox_table[8'h47]=8'ha0;
        sbox_table[8'h48]=8'h52; sbox_table[8'h49]=8'h3b; sbox_table[8'h4a]=8'hd6; sbox_table[8'h4b]=8'hb3;
        sbox_table[8'h4c]=8'h29; sbox_table[8'h4d]=8'he3; sbox_table[8'h4e]=8'h2f; sbox_table[8'h4f]=8'h84;
        sbox_table[8'h50]=8'h53; sbox_table[8'h51]=8'hd1; sbox_table[8'h52]=8'h00; sbox_table[8'h53]=8'hed;
        sbox_table[8'h54]=8'h20; sbox_table[8'h55]=8'hfc; sbox_table[8'h56]=8'hb1; sbox_table[8'h57]=8'h5b;
        sbox_table[8'h58]=8'h6a; sbox_table[8'h59]=8'hcb; sbox_table[8'h5a]=8'hbe; sbox_table[8'h5b]=8'h39;
        sbox_table[8'h5c]=8'h4a; sbox_table[8'h5d]=8'h4c; sbox_table[8'h5e]=8'h58; sbox_table[8'h5f]=8'hcf;
        sbox_table[8'h60]=8'hd0; sbox_table[8'h61]=8'hef; sbox_table[8'h62]=8'haa; sbox_table[8'h63]=8'hfb;
        sbox_table[8'h64]=8'h43; sbox_table[8'h65]=8'h4d; sbox_table[8'h66]=8'h33; sbox_table[8'h67]=8'h85;
        sbox_table[8'h68]=8'h45; sbox_table[8'h69]=8'hf9; sbox_table[8'h6a]=8'h02; sbox_table[8'h6b]=8'h7f;
        sbox_table[8'h6c]=8'h50; sbox_table[8'h6d]=8'h3c; sbox_table[8'h6e]=8'h9f; sbox_table[8'h6f]=8'ha8;
        sbox_table[8'h70]=8'h51; sbox_table[8'h71]=8'ha3; sbox_table[8'h72]=8'h40; sbox_table[8'h73]=8'h8f;
        sbox_table[8'h74]=8'h92; sbox_table[8'h75]=8'h9d; sbox_table[8'h76]=8'h38; sbox_table[8'h77]=8'hf5;
        sbox_table[8'h78]=8'hbc; sbox_table[8'h79]=8'hb6; sbox_table[8'h7a]=8'hda; sbox_table[8'h7b]=8'h21;
        sbox_table[8'h7c]=8'h10; sbox_table[8'h7d]=8'hff; sbox_table[8'h7e]=8'hf3; sbox_table[8'h7f]=8'hd2;
        sbox_table[8'h80]=8'hcd; sbox_table[8'h81]=8'h0c; sbox_table[8'h82]=8'h13; sbox_table[8'h83]=8'hec;
        sbox_table[8'h84]=8'h5f; sbox_table[8'h85]=8'h97; sbox_table[8'h86]=8'h44; sbox_table[8'h87]=8'h17;
        sbox_table[8'h88]=8'hc4; sbox_table[8'h89]=8'ha7; sbox_table[8'h8a]=8'h7e; sbox_table[8'h8b]=8'h3d;
        sbox_table[8'h8c]=8'h64; sbox_table[8'h8d]=8'h5d; sbox_table[8'h8e]=8'h19; sbox_table[8'h8f]=8'h73;
        sbox_table[8'h90]=8'h60; sbox_table[8'h91]=8'h81; sbox_table[8'h92]=8'h4f; sbox_table[8'h93]=8'hdc;
        sbox_table[8'h94]=8'h22; sbox_table[8'h95]=8'h2a; sbox_table[8'h96]=8'h90; sbox_table[8'h97]=8'h88;
        sbox_table[8'h98]=8'h46; sbox_table[8'h99]=8'hee; sbox_table[8'h9a]=8'hb8; sbox_table[8'h9b]=8'h14;
        sbox_table[8'h9c]=8'hde; sbox_table[8'h9d]=8'h5e; sbox_table[8'h9e]=8'h0b; sbox_table[8'h9f]=8'hdb;
        sbox_table[8'ha0]=8'he0; sbox_table[8'ha1]=8'h32; sbox_table[8'ha2]=8'h3a; sbox_table[8'ha3]=8'h0a;
        sbox_table[8'ha4]=8'h49; sbox_table[8'ha5]=8'h06; sbox_table[8'ha6]=8'h24; sbox_table[8'ha7]=8'h5c;
        sbox_table[8'ha8]=8'hc2; sbox_table[8'ha9]=8'hd3; sbox_table[8'haa]=8'hac; sbox_table[8'hab]=8'h62;
        sbox_table[8'hac]=8'h91; sbox_table[8'had]=8'h95; sbox_table[8'hae]=8'he4; sbox_table[8'haf]=8'h79;
        sbox_table[8'hb0]=8'he7; sbox_table[8'hb1]=8'hc8; sbox_table[8'hb2]=8'h37; sbox_table[8'hb3]=8'h6d;
        sbox_table[8'hb4]=8'h8d; sbox_table[8'hb5]=8'hd5; sbox_table[8'hb6]=8'h4e; sbox_table[8'hb7]=8'ha9;
        sbox_table[8'hb8]=8'h6c; sbox_table[8'hb9]=8'h56; sbox_table[8'hba]=8'hf4; sbox_table[8'hbb]=8'hea;
        sbox_table[8'hbc]=8'h65; sbox_table[8'hbd]=8'h7a; sbox_table[8'hbe]=8'hae; sbox_table[8'hbf]=8'h08;
        sbox_table[8'hc0]=8'hba; sbox_table[8'hc1]=8'h78; sbox_table[8'hc2]=8'h25; sbox_table[8'hc3]=8'h2e;
        sbox_table[8'hc4]=8'h1c; sbox_table[8'hc5]=8'ha6; sbox_table[8'hc6]=8'hb4; sbox_table[8'hc7]=8'hc6;
        sbox_table[8'hc8]=8'he8; sbox_table[8'hc9]=8'hdd; sbox_table[8'hca]=8'h74; sbox_table[8'hcb]=8'h1f;
        sbox_table[8'hcc]=8'h4b; sbox_table[8'hcd]=8'hbd; sbox_table[8'hce]=8'h8b; sbox_table[8'hcf]=8'h8a;
        sbox_table[8'hd0]=8'h70; sbox_table[8'hd1]=8'h3e; sbox_table[8'hd2]=8'hb5; sbox_table[8'hd3]=8'h66;
        sbox_table[8'hd4]=8'h48; sbox_table[8'hd5]=8'h03; sbox_table[8'hd6]=8'hf6; sbox_table[8'hd7]=8'h0e;
        sbox_table[8'hd8]=8'h61; sbox_table[8'hd9]=8'h35; sbox_table[8'hda]=8'h57; sbox_table[8'hdb]=8'hb9;
        sbox_table[8'hdc]=8'h86; sbox_table[8'hdd]=8'hc1; sbox_table[8'hde]=8'h1d; sbox_table[8'hdf]=8'h9e;
        sbox_table[8'he0]=8'he1; sbox_table[8'he1]=8'hf8; sbox_table[8'he2]=8'h98; sbox_table[8'he3]=8'h11;
        sbox_table[8'he4]=8'h69; sbox_table[8'he5]=8'hd9; sbox_table[8'he6]=8'h8e; sbox_table[8'he7]=8'h94;
        sbox_table[8'he8]=8'h9b; sbox_table[8'he9]=8'h1e; sbox_table[8'hea]=8'h87; sbox_table[8'heb]=8'he9;
        sbox_table[8'hec]=8'hce; sbox_table[8'hed]=8'h55; sbox_table[8'hee]=8'h28; sbox_table[8'hef]=8'hdf;
        sbox_table[8'hf0]=8'h8c; sbox_table[8'hf1]=8'ha1; sbox_table[8'hf2]=8'h89; sbox_table[8'hf3]=8'h0d;
        sbox_table[8'hf4]=8'hbf; sbox_table[8'hf5]=8'he6; sbox_table[8'hf6]=8'h42; sbox_table[8'hf7]=8'h68;
        sbox_table[8'hf8]=8'h41; sbox_table[8'hf9]=8'h99; sbox_table[8'hfa]=8'h2d; sbox_table[8'hfb]=8'h0f;
        sbox_table[8'hfc]=8'hb0; sbox_table[8'hfd]=8'h54; sbox_table[8'hfe]=8'hbb; sbox_table[8'hff]=8'h16;
    end

    assign out_byte = sbox_table[in_byte];

endmodule
