// ============================================================================
// uart_tx.v
//
// Minimal 8N1 UART transmitter. Standard valid/ready handshake:
//   - ready_o high  -> idle, may accept a new byte
//   - valid_i pulsed high for 1 cycle with data_i held -> byte is queued
//
// DIV is computed from CLK_FREQ_HZ/BAUD. For board synthesis use the real
// clock (100 MHz on the Boolean board) and a standard baud (115200). For
// simulation, override CLK_FREQ_HZ down to a small ratio so testbenches
// don't have to wait out real UART bit periods -- same pattern already
// used project-wide for DEBOUNCE_CYCLES (see io_conditioning.v).
// ============================================================================
`timescale 1ns/1ps

module uart_tx #(
    parameter integer CLK_FREQ_HZ = 100_000_000,
    parameter integer BAUD        = 115200
) (
    input  wire       clk,
    input  wire       resetn,
    input  wire [7:0] data_i,
    input  wire       valid_i,
    output wire       ready_o,
    output reg        txd
);

    localparam integer DIV   = (CLK_FREQ_HZ + BAUD/2) / BAUD;
    localparam integer CNT_W = (DIV <= 1) ? 1 : $clog2(DIV);

    localparam ST_IDLE  = 2'd0;
    localparam ST_START = 2'd1;
    localparam ST_DATA  = 2'd2;
    localparam ST_STOP  = 2'd3;

    reg [1:0]       state;
    reg [2:0]       bit_idx;
    reg [7:0]       data_q;
    reg [CNT_W-1:0] baud_cnt;

    assign ready_o = (state == ST_IDLE);

    always @(posedge clk) begin
        if (!resetn) begin
            state    <= ST_IDLE;
            txd      <= 1'b1;
            baud_cnt <= {CNT_W{1'b0}};
            bit_idx  <= 3'd0;
        end else begin
            case (state)
                ST_IDLE: begin
                    txd <= 1'b1;
                    if (valid_i) begin
                        data_q   <= data_i;
                        baud_cnt <= {CNT_W{1'b0}};
                        state    <= ST_START;
                    end
                end

                ST_START: begin
                    txd <= 1'b0;
                    if (baud_cnt == DIV[CNT_W-1:0]-1'b1) begin
                        baud_cnt <= {CNT_W{1'b0}};
                        bit_idx  <= 3'd0;
                        state    <= ST_DATA;
                    end else
                        baud_cnt <= baud_cnt + 1'b1;
                end

                ST_DATA: begin
                    txd <= data_q[bit_idx];
                    if (baud_cnt == DIV[CNT_W-1:0]-1'b1) begin
                        baud_cnt <= {CNT_W{1'b0}};
                        if (bit_idx == 3'd7)
                            state <= ST_STOP;
                        else
                            bit_idx <= bit_idx + 1'b1;
                    end else
                        baud_cnt <= baud_cnt + 1'b1;
                end

                ST_STOP: begin
                    txd <= 1'b1;
                    if (baud_cnt == DIV[CNT_W-1:0]-1'b1) begin
                        baud_cnt <= {CNT_W{1'b0}};
                        state    <= ST_IDLE;
                    end else
                        baud_cnt <= baud_cnt + 1'b1;
                end

                default: state <= ST_IDLE;
            endcase
        end
    end

endmodule