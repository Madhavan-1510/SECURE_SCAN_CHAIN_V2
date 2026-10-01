// ============================================================================
// uart_rx.v  (Paper 2, board demo)
//
// 8N1 UART receiver, matches uart_tx.v's CLK_FREQ_HZ/BAUD convention.
// Samples the start bit, then each data bit at its mid-point. One-cycle
// valid_o pulse with data_o when a byte is complete. No parity, 1 stop bit.
// ============================================================================
`timescale 1ns/1ps

module uart_rx #(
    parameter integer CLK_FREQ_HZ = 100_000_000,
    parameter integer BAUD        = 115200
) (
    input  wire       clk,
    input  wire       resetn,
    input  wire       rxd,          // asynchronous serial input (idle high)
    output reg  [7:0] data_o,
    output reg        valid_o       // 1-cycle strobe when data_o is valid
);
    localparam integer DIV  = CLK_FREQ_HZ / BAUD;      // cycles per bit
    localparam integer HALF = DIV / 2;

    // 2-flop synchronizer for the async input
    reg rxd_m, rxd_s;
    always @(posedge clk) begin rxd_m <= rxd; rxd_s <= rxd_m; end

    localparam S_IDLE = 2'd0, S_START = 2'd1, S_DATA = 2'd2, S_STOP = 2'd3;
    reg [1:0]  state;
    reg [31:0] cnt;
    reg [2:0]  bitn;
    reg [7:0]  sh;

    always @(posedge clk) begin
        if (!resetn) begin
            state <= S_IDLE; cnt <= 0; bitn <= 0; sh <= 0;
            data_o <= 0; valid_o <= 0;
        end else begin
            valid_o <= 1'b0;
            case (state)
                S_IDLE: begin
                    if (!rxd_s) begin          // falling edge = start bit
                        state <= S_START; cnt <= 0;
                    end
                end
                S_START: begin
                    if (cnt == HALF) begin     // mid of start bit
                        if (!rxd_s) begin state <= S_DATA; cnt <= 0; bitn <= 0; end
                        else          state <= S_IDLE;   // false start
                    end else cnt <= cnt + 1;
                end
                S_DATA: begin
                    if (cnt == DIV-1) begin
                        cnt <= 0;
                        sh  <= {rxd_s, sh[7:1]};   // LSB first
                        if (bitn == 3'd7) state <= S_STOP;
                        else bitn <= bitn + 1;
                    end else cnt <= cnt + 1;
                end
                S_STOP: begin
                    if (cnt == DIV-1) begin
                        state   <= S_IDLE;
                        data_o  <= sh;
                        valid_o <= 1'b1;
                    end else cnt <= cnt + 1;
                end
            endcase
        end
    end
endmodule
