// ============================================================================
// seven_seg_hex.v
//
// Drives the board's two 4-digit 7-segment modules (D0, D1) to show one
// 32-bit value as 8 hex digits: D1 shows value_i[31:16] (left/high digits),
// D0 shows value_i[15:0] (right/low digits). Each display module shares one
// SEG bus across its 4 digits, so both are time-multiplexed at a refresh
// rate fast enough to look solid to the eye (~1 kHz per-digit switching).
//
// POLARITY ASSUMPTION (verify against your board's schematic before relying
// on it): AN (digit enable) active-LOW, SEG segments active-LOW, standard
// common-anode convention used by most Digilent 7-segment modules. If digits
// appear inverted/ghosted on real hardware, invert an_d0/an_d1/seg_d0/seg_d1
// at the point they're driven in board_top.v -- nothing else needs to change.
// ============================================================================
`timescale 1ns/1ps

module seven_seg_hex #(
    parameter integer CLK_FREQ_HZ = 100_000_000,
    parameter integer REFRESH_HZ  = 1000   // per-digit switch rate
) (
    input  wire        clk,
    input  wire        resetn,
    input  wire [31:0] value_i,
    output reg  [3:0]  an_d0,
    output reg  [7:0]  seg_d0,
    output reg  [3:0]  an_d1,
    output reg  [7:0]  seg_d1
);

    localparam integer DIV   = CLK_FREQ_HZ / (REFRESH_HZ*4);
    localparam integer CNT_W = (DIV <= 1) ? 1 : $clog2(DIV);

    reg [CNT_W-1:0] cnt;
    reg [1:0]       digit_sel;

    always @(posedge clk) begin
        if (!resetn) begin
            cnt       <= {CNT_W{1'b0}};
            digit_sel <= 2'd0;
        end else if (cnt == DIV[CNT_W-1:0]-1'b1) begin
            cnt       <= {CNT_W{1'b0}};
            digit_sel <= digit_sel + 2'd1;
        end else
            cnt <= cnt + 1'b1;
    end

    function [7:0] hex_to_seg(input [3:0] h); // active-low {dp,g,f,e,d,c,b,a}
        begin
            case (h)
                4'h0: hex_to_seg = 8'b1100_0000;
                4'h1: hex_to_seg = 8'b1111_1001;
                4'h2: hex_to_seg = 8'b1010_0100;
                4'h3: hex_to_seg = 8'b1011_0000;
                4'h4: hex_to_seg = 8'b1001_1001;
                4'h5: hex_to_seg = 8'b1001_0010;
                4'h6: hex_to_seg = 8'b1000_0010;
                4'h7: hex_to_seg = 8'b1111_1000;
                4'h8: hex_to_seg = 8'b1000_0000;
                4'h9: hex_to_seg = 8'b1001_0000;
                4'ha: hex_to_seg = 8'b1000_1000;
                4'hb: hex_to_seg = 8'b1000_0011;
                4'hc: hex_to_seg = 8'b1100_0110;
                4'hd: hex_to_seg = 8'b1010_0001;
                4'he: hex_to_seg = 8'b1000_0110;
                4'hf: hex_to_seg = 8'b1000_1110;
                default: hex_to_seg = 8'b1111_1111;
            endcase
        end
    endfunction

    wire [3:0] nib_d0 = (digit_sel==2'd0) ? value_i[3:0]   :
                        (digit_sel==2'd1) ? value_i[7:4]   :
                        (digit_sel==2'd2) ? value_i[11:8]  : value_i[15:12];
    wire [3:0] nib_d1 = (digit_sel==2'd0) ? value_i[19:16] :
                        (digit_sel==2'd1) ? value_i[23:20] :
                        (digit_sel==2'd2) ? value_i[27:24] : value_i[31:28];

    always @* begin
        an_d0 = 4'b1111;
        an_d0[digit_sel] = 1'b0;
        seg_d0 = hex_to_seg(nib_d0);

        an_d1 = 4'b1111;
        an_d1[digit_sel] = 1'b0;
        seg_d1 = hex_to_seg(nib_d1);
    end

endmodule