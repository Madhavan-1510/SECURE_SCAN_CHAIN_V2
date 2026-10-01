// ============================================================================
// scan_uart_bridge.v  (Paper 2, board demo)
//
// A UART command console that drives ONE AES coprocessor's PCPI port, its
// scan port, and its lock. It is the on-board stand-in for the testbenches:
// it lets you type the read / write / encrypt / unlock operations over a
// serial terminal and see the result as ASCII hex, so the Paper 1 (read lock)
// and Paper 2 (write lock) behaviour can be demonstrated live.
//
// It is a PCPI *master* (same transaction shape as the CPU: drive
// pcpi_valid/insn/rs1/rs2, wait for pcpi_ready) AND a scan driver
// (scan_en/scan_in/scan_out). board_top_def muxes it onto the selected
// defense instance (G1 or G4).
//
// Protocol: ASCII, line-based. Type a command letter, optional hex digits,
// then Enter (CR or LF). Replies end with CRLF. Spaces are ignored.
//   S            -> status: "S def=<d> locked=<0/1> lockout=<0/1>"
//   R            -> scan-read 645 bits, reply "R <162 hex>" (MSB-padded)
//   W<32 hex>    -> shift 128 bits into the chain (write attack), "W ok"
//   K<32 hex>    -> LOADKEY  (4 PCPI words from the 128-bit arg), "K ok"
//   B<32 hex>    -> LOADBLOCK(4 PCPI words), "B ok"
//   E            -> ENCRYPT + READRESULT x4, reply "E <32 hex>" ciphertext
//   U<8 hex>     -> unlock attempt with that 32-bit code, then status
//   L            -> relock, "L ok"
// Unknown command -> "? err".
// ============================================================================
`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"

module scan_uart_bridge #(
    parameter integer DEF_LEVEL = 4   // for the S reply only (display)
) (
    input  wire        clk,
    input  wire        resetn,

    // UART
    input  wire        rx_valid,
    input  wire [7:0]  rx_data,
    output reg  [7:0]  tx_data,
    output reg         tx_valid,
    input  wire        tx_ready,

    // PCPI master (to the selected aes_pcpi_def)
    output reg         pcpi_valid,
    output reg  [31:0] pcpi_insn,
    output reg  [31:0] pcpi_rs1,
    output reg  [31:0] pcpi_rs2,
    input  wire        pcpi_wr,
    input  wire [31:0] pcpi_rd,
    input  wire        pcpi_wait,
    input  wire        pcpi_ready,

    // Scan port
    output reg         scan_en,
    output reg         scan_in,
    input  wire        scan_out,

    // Lock control (to the selected scan_lock_controller_v2)
    output reg         unlock_valid,
    output reg  [31:0] unlock_code,
    output reg         relock,
    input  wire        locked,
    input  wire        lockout,

    // last ciphertext low word, for the 7-seg display
    output reg  [31:0] disp_o
);
    localparam integer CHAIN = 645;
    localparam integer OBUF  = 200;    // output byte buffer

    // ------------------------------------------------------------------
    // Hex helpers
    // ------------------------------------------------------------------
    function [7:0] hexc(input [3:0] n);
        hexc = (n < 10) ? (8'h30 + n) : (8'h41 + n - 10);  // 0-9 A-F
    endfunction
    function [3:0] unhex(input [7:0] c);
        if (c >= 8'h30 && c <= 8'h39)      unhex = c - 8'h30;
        else if (c >= 8'h41 && c <= 8'h46) unhex = c - 8'h41 + 10;
        else if (c >= 8'h61 && c <= 8'h66) unhex = c - 8'h61 + 10;
        else                               unhex = 4'h0;
    endfunction
    function ishex(input [7:0] c);
        ishex = (c >= 8'h30 && c <= 8'h39) || (c >= 8'h41 && c <= 8'h46) || (c >= 8'h61 && c <= 8'h66);
    endfunction

    // ------------------------------------------------------------------
    // Output buffer + drain
    // ------------------------------------------------------------------
    reg [7:0]  obuf [0:OBUF-1];
    reg [8:0]  olen, oidx;
    reg        sending;

    // ------------------------------------------------------------------
    // Line input
    // ------------------------------------------------------------------
    reg [7:0]   cmd;
    reg [127:0] arg;
    reg [7:0]   argn;      // hex digits seen
    reg         have_cmd;

    reg [CHAIN-1:0] cap;   // scan capture

    localparam
        S_RX    = 5'd0,  S_EXEC = 5'd1,
        S_RD    = 5'd2,  S_RD_FMT = 5'd3,
        S_WR    = 5'd4,
        S_LD    = 5'd5,  S_LD_WAIT = 5'd6,
        S_ENC   = 5'd7,  S_ENC_WAIT = 5'd8, S_RR = 5'd9, S_RR_WAIT = 5'd10, S_ENC_FMT = 5'd11,
        S_UNL   = 5'd12, S_UNL2 = 5'd13,
        S_STAT  = 5'd14, S_OKMSG = 5'd15, S_DRAIN = 5'd16, S_DONE = 5'd17;
    reg [4:0] state, retst;

    integer k;
    reg [15:0] shcnt;
    reg [1:0]  word_i;
    reg [127:0] ct;

    // small helpers to append to obuf
    task put1(input [7:0] b); begin obuf[olen] = b; olen = olen + 1; end endtask

    // build a status string into obuf: "S def=D locked=x lockout=y\r\n"
    task build_status;
        begin
            olen = 0;
            put1("S"); put1(" "); put1("d"); put1("e"); put1("f"); put1("=");
            put1(hexc(DEF_LEVEL[3:0]));
            put1(" "); put1("l"); put1("k"); put1("="); put1(locked  ? "1" : "0");
            put1(" "); put1("l"); put1("o"); put1("="); put1(lockout ? "1" : "0");
            put1(8'h0d); put1(8'h0a);
        end
    endtask

    always @(posedge clk) begin
        if (!resetn) begin
            state <= S_RX; have_cmd <= 0; argn <= 0; arg <= 0;
            pcpi_valid <= 0; pcpi_insn <= 0; pcpi_rs1 <= 0; pcpi_rs2 <= 0;
            scan_en <= 0; scan_in <= 0;
            unlock_valid <= 0; unlock_code <= 0; relock <= 0;
            tx_valid <= 0; tx_data <= 0; sending <= 0; olen <= 0; oidx <= 0; disp_o <= 0;
        end else begin
            unlock_valid <= 1'b0;  // 1-cycle strobes by default
            relock       <= 1'b0;
            tx_valid     <= 1'b0;

            case (state)
            // -------- collect a line --------
            S_RX: begin
                if (rx_valid) begin
                    if (rx_data == 8'h0d || rx_data == 8'h0a) begin
                        if (have_cmd) state <= S_EXEC;
                    end else if (rx_data == " ") begin
                        // ignore spaces
                    end else if (!have_cmd) begin
                        cmd <= rx_data; have_cmd <= 1'b1; arg <= 0; argn <= 0;
                    end else if (ishex(rx_data)) begin
                        arg  <= {arg[123:0], unhex(rx_data)};
                        argn <= argn + 1'b1;
                    end
                end
            end

            // -------- dispatch --------
            S_EXEC: begin
                olen <= 0;
                case (cmd)
                    "S": state <= S_STAT;
                    "R": begin scan_en <= 1'b1; scan_in <= 1'b0; shcnt <= 0; state <= S_RD; end
                    "W": begin scan_en <= 1'b1; shcnt <= 0; scan_in <= arg[127]; state <= S_WR; end
                    "K","B": begin word_i <= 0; state <= S_LD; end
                    "E": begin pcpi_valid <= 1'b1;
                               pcpi_insn <= {7'b0,5'b0,5'b0,`AES_F3_ENCRYPT,5'b0,`AES_OPCODE};
                               pcpi_rs1 <= 0; pcpi_rs2 <= 0; state <= S_ENC_WAIT; end
                    "U": begin unlock_code <= arg[31:0]; unlock_valid <= 1'b1; state <= S_UNL; end
                    "L": begin relock <= 1'b1; retst <= S_OKMSG; state <= S_OKMSG; end
                    default: begin
                        olen <= 0; obuf[0] <= "?"; obuf[1] <= " ";
                        obuf[2] <= "e"; obuf[3] <= "r"; obuf[4] <= "r";
                        obuf[5] <= 8'h0d; obuf[6] <= 8'h0a; olen <= 7;
                        state <= S_DRAIN;
                    end
                endcase
            end

            // -------- R: read 645 scan bits --------
            S_RD: begin
                cap[shcnt] <= scan_out;
                shcnt <= shcnt + 1'b1;
                if (shcnt == CHAIN-1) begin scan_en <= 1'b0; state <= S_RD_FMT; end
            end
            S_RD_FMT: begin
                // "R " + 162 nibbles (648 bits, MSB cell = cap[0]) + CRLF
                olen = 0; put1("R"); put1(" ");
                for (k = 0; k < 162; k = k + 1) begin : fmt
                    reg [3:0] nib; integer base; integer b;
                    base = k*4; nib = 4'h0;
                    for (b = 0; b < 4; b = b + 1)
                        if (base + b < CHAIN) nib[3-b] = cap[base + b];
                    put1(hexc(nib));
                end
                put1(8'h0d); put1(8'h0a);
                state <= S_DRAIN;
            end

            // -------- W: shift 128 bits in --------
            S_WR: begin
                shcnt <= shcnt + 1'b1;
                scan_in <= arg[126 - shcnt];           // next bit, MSB-first
                if (shcnt == 127) begin
                    scan_en <= 1'b0; scan_in <= 1'b0;
                    obuf[0]<="W";obuf[1]<=" ";obuf[2]<="o";obuf[3]<="k";obuf[4]<=8'h0d;obuf[5]<=8'h0a;olen<=6;
                    state <= S_DRAIN;
                end
            end

            // -------- K/B: load 4 words over PCPI --------
            S_LD: begin
                pcpi_valid <= 1'b1;
                pcpi_insn  <= (cmd=="K") ? {7'b0,5'b0,5'b0,`AES_F3_LOADKEY,5'b0,`AES_OPCODE}
                                         : {7'b0,5'b0,5'b0,`AES_F3_LOADBLOCK,5'b0,`AES_OPCODE};
                pcpi_rs1   <= {30'b0, word_i};
                case (word_i) 2'd0: pcpi_rs2 <= arg[127:96]; 2'd1: pcpi_rs2 <= arg[95:64];
                              2'd2: pcpi_rs2 <= arg[63:32];  2'd3: pcpi_rs2 <= arg[31:0]; endcase
                state <= S_LD_WAIT;
            end
            S_LD_WAIT: begin
                if (pcpi_ready) begin
                    pcpi_valid <= 1'b0;
                    if (word_i == 2'd3) begin
                        obuf[0]<=cmd;obuf[1]<=" ";obuf[2]<="o";obuf[3]<="k";obuf[4]<=8'h0d;obuf[5]<=8'h0a;olen<=6;
                        state <= S_DRAIN;
                    end else begin word_i <= word_i + 1'b1; state <= S_LD; end
                end
            end

            // -------- E: encrypt then read 4 result words --------
            S_ENC_WAIT: begin
                if (pcpi_ready) begin pcpi_valid <= 1'b0; word_i <= 0; state <= S_RR; end
            end
            S_RR: begin
                pcpi_valid <= 1'b1;
                pcpi_insn  <= {7'b0,5'b0,5'b0,`AES_F3_READRESULT,5'b0,`AES_OPCODE};
                pcpi_rs1   <= {30'b0, word_i};
                state <= S_RR_WAIT;
            end
            S_RR_WAIT: begin
                if (pcpi_ready) begin
                    pcpi_valid <= 1'b0;
                    case (word_i) 2'd0: ct[127:96] <= pcpi_rd; 2'd1: ct[95:64] <= pcpi_rd;
                                  2'd2: ct[63:32]  <= pcpi_rd; 2'd3: ct[31:0]  <= pcpi_rd; endcase
                    if (word_i == 2'd3) state <= S_ENC_FMT;
                    else begin word_i <= word_i + 1'b1; state <= S_RR; end
                end
            end
            S_ENC_FMT: begin
                disp_o <= ct[31:0];
                olen = 0; put1("E"); put1(" ");
                for (k = 0; k < 32; k = k + 1) put1(hexc(ct[127 - k*4 -: 4]));
                put1(8'h0d); put1(8'h0a);
                state <= S_DRAIN;
            end

            // -------- U: unlock attempt, then status --------
            S_UNL:  state <= S_UNL2;      // let the lock register the attempt
            S_UNL2: state <= S_STAT;

            // -------- status --------
            S_STAT: begin build_status; state <= S_DRAIN; end

            // -------- generic "ok" for L --------
            S_OKMSG: begin
                obuf[0]<=cmd;obuf[1]<=" ";obuf[2]<="o";obuf[3]<="k";obuf[4]<=8'h0d;obuf[5]<=8'h0a;olen<=6;
                state <= S_DRAIN;
            end

            // -------- drain obuf to UART --------
            S_DRAIN: begin oidx <= 0; sending <= 1'b1; state <= S_DONE; end
            S_DONE: begin
                if (sending) begin
                    if (tx_ready && !tx_valid) begin
                        tx_data  <= obuf[oidx];
                        tx_valid <= 1'b1;
                        oidx     <= oidx + 1'b1;
                        if (oidx + 1 == olen) sending <= 1'b0;
                    end
                end else begin
                    have_cmd <= 1'b0; argn <= 0; arg <= 0;
                    state <= S_RX;
                end
            end
            endcase
        end
    end
endmodule
