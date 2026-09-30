// ============================================================================
// uart_hex_dumper.v
//
// On a 1-cycle start_i pulse, latches data_i and streams it out over UART as
// WIDTH/4 ASCII hex nibbles (MSB nibble first), followed by CR LF. Built on
// top of uart_tx.v's valid/ready handshake -- one nibble is queued only once
// the previous byte has fully finished transmitting.
//
// WIDTH must be a multiple of 4. Used for: 128-bit key/ciphertext dumps, and
// (separately instantiated with WIDTH=648, the 645-bit scan segment rounded
// up to a whole nibble) the full scan-capture dump -- the hardware
// equivalent of tb_scan_lock.v's exhaustive full-stream check, but readable
// on a serial terminal instead of only in simulation.
// ============================================================================
`timescale 1ns/1ps

module uart_hex_dumper #(
    parameter integer WIDTH        = 128,
    parameter integer CLK_FREQ_HZ  = 100_000_000,
    parameter integer BAUD         = 115200
) (
    input  wire             clk,
    input  wire             resetn,
    input  wire [WIDTH-1:0] data_i,
    input  wire             start_i,
    output wire             busy_o,
    output wire             txd
);

    localparam integer NIBBLES = WIDTH/4;
    localparam integer NCNT_W  = (NIBBLES <= 1) ? 1 : $clog2(NIBBLES);

    localparam ST_IDLE = 2'd0;
    localparam ST_NIB  = 2'd1;
    localparam ST_CR   = 2'd2;
    localparam ST_LF   = 2'd3;

    reg [1:0]           state;
    reg [WIDTH-1:0]      shift_data;
    reg [NCNT_W-1:0]     nib_cnt;

    wire       tx_ready;
    reg        tx_valid;
    reg [7:0]  tx_data;

    uart_tx #(.CLK_FREQ_HZ(CLK_FREQ_HZ), .BAUD(BAUD)) u_tx (
        .clk    (clk),
        .resetn (resetn),
        .data_i (tx_data),
        .valid_i(tx_valid),
        .ready_o(tx_ready),
        .txd    (txd)
    );

    function [7:0] nibble_to_ascii(input [3:0] n);
        begin
            nibble_to_ascii = (n < 4'ha) ? (8'h30 + n) : (8'h41 + (n - 4'ha));
        end
    endfunction

    assign busy_o = (state != ST_IDLE);

    always @(posedge clk) begin
        tx_valid <= 1'b0;
        if (!resetn) begin
            state   <= ST_IDLE;
            nib_cnt <= {NCNT_W{1'b0}};
        end else begin
            case (state)
                ST_IDLE: begin
                    if (start_i) begin
                        shift_data <= data_i;
                        nib_cnt    <= {NCNT_W{1'b0}};
                        state      <= ST_NIB;
                    end
                end

                ST_NIB: begin
                    if (tx_ready && !tx_valid) begin
                        tx_data    <= nibble_to_ascii(shift_data[WIDTH-1 -: 4]);
                        tx_valid   <= 1'b1;
                        shift_data <= shift_data << 4;
                        if (nib_cnt == NIBBLES[NCNT_W-1:0]-1'b1)
                            state <= ST_CR;
                        else
                            nib_cnt <= nib_cnt + 1'b1;
                    end
                end

                ST_CR: begin
                    if (tx_ready && !tx_valid) begin
                        tx_data  <= 8'h0D;
                        tx_valid <= 1'b1;
                        state    <= ST_LF;
                    end
                end

                ST_LF: begin
                    if (tx_ready && !tx_valid) begin
                        tx_data  <= 8'h0A;
                        tx_valid <= 1'b1;
                        state    <= ST_IDLE;
                    end
                end

                default: state <= ST_IDLE;
            endcase
        end
    end

endmodule