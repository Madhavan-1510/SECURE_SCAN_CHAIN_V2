// ============================================================================
// board_top_def.v  (Paper 2, board demo for Spartan-7 Boolean Board)
//
// A live UART console that demonstrates BOTH defenses on one bitstream:
//   - a G1 instance  (aes_pcpi_def DEFENSE_LEVEL=1, Paper 1 read lock)
//   - a G4 instance  (aes_pcpi_def DEFENSE_LEVEL=4, Paper 2 read+write lock)
// sharing ONE hardened lock (scan_lock_controller_v2). sw[0] selects which
// instance the UART console drives; the other is held idle (scan_en=0,
// pcpi_valid=0) so it keeps its state. This lets you run the SAME scan
// read / write / encrypt sequence on each and watch G1 fall and G4 hold.
//
// The console (scan_uart_bridge) is a PCPI master + scan driver, so it plays
// the role the CPU plays in simulation. The real-CPU path is already proven
// in tb_cpu_driven_aes_def; this top focuses on the scan attack/defense
// surface, which is the attacker's actual interface.
//
// It does NOT expose any key/ciphertext debug tap to the board (unlike the
// Paper 1 board_top.v, F9) -- the only readback is the scan port itself,
// which is exactly what the defense governs. The 7-seg shows the last
// ciphertext low word (public output), never a key.
//
// UART: 115200 8N1 on UART_rxd (V12) / UART_txd (U11), already in the XDC.
// Type commands (S/R/W/K/B/E/U/L) + Enter; see scan_uart_bridge.v.
//
// LEDs: led[0]=locked led[1]=lockout led[2]=sel(0=G1,1=G4) led[3]=busy
//       led[15:4]=0
// RGB0: R=locked, G=unlocked. RGB1: B while busy.
// btn[0]=system reset  btn[1]=lock-domain reset
//
// NOTE on lock timing: BOOT_DELAY/LOCKOUT are set to demo-friendly values
// here (ms-scale). The production rule BOOT_DELAY_CYCLES >= LOCKOUT_CYCLES
// (see PROJECT_README s5d) and the ~1e8-cycle defaults still apply for the
// real design; override the parameters for a security build.
// ============================================================================
`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"

module board_top_def #(
    parameter integer CLK_FREQ_HZ       = 100_000_000,
    parameter integer BAUD              = 115200,
    parameter [31:0]  SECRET            = 32'h5EC2_E7A1,  // provisioned unlock code
    parameter integer MAX_FAILS         = 3,
    parameter integer LOCKOUT_CYCLES    = 100_000_000,    // ~1 s @100 MHz
    parameter integer BOOT_DELAY_CYCLES = 1_000_000,      // ~10 ms (demo; prod >= LOCKOUT)
    parameter integer DEBOUNCE_CYCLES   = 200_000
) (
    input  wire        clk,
    input  wire [15:0] sw,
    output wire [15:0] led,
    input  wire [3:0]  btn,
    output wire [2:0]  RGB0,
    output wire [2:0]  RGB1,
    output wire [3:0]  D0_AN,
    output wire [7:0]  D0_SEG,
    output wire [3:0]  D1_AN,
    output wire [7:0]  D1_SEG,
    input  wire        UART_rxd,
    output wire        UART_txd
);
    // ---------------- reset conditioning ----------------
    wire por_resetn;
    power_on_reset #(.POR_CYCLES(64)) u_por (.clk(clk), .resetn_o(por_resetn));
    wire resetn_btn, lock_resetn_btn;
    edge_reset_pulse #(.PULSE_CYCLES(64)) u_rst_func (.clk(clk), .btn_raw(btn[0]), .resetn_o(resetn_btn));
    edge_reset_pulse #(.PULSE_CYCLES(64)) u_rst_lock (.clk(clk), .btn_raw(btn[1]), .resetn_o(lock_resetn_btn));
    wire resetn      = por_resetn & resetn_btn;
    wire lock_resetn = por_resetn & lock_resetn_btn;

    wire [15:0] sw_cond;
    level_debounce_sync #(.WIDTH(16), .DEBOUNCE_CYCLES(DEBOUNCE_CYCLES)) u_sw (
        .clk(clk), .resetn(resetn), .level_raw(sw), .level_o(sw_cond));
    wire sel = sw_cond[0];     // 0 = G1, 1 = G4

    // ---------------- UART ----------------
    wire [7:0] rx_data; wire rx_valid;
    uart_rx #(.CLK_FREQ_HZ(CLK_FREQ_HZ), .BAUD(BAUD)) u_rx (
        .clk(clk), .resetn(resetn), .rxd(UART_rxd), .data_o(rx_data), .valid_o(rx_valid));

    wire [7:0] tx_data; wire tx_valid; wire tx_ready;
    uart_tx #(.CLK_FREQ_HZ(CLK_FREQ_HZ), .BAUD(BAUD)) u_tx (
        .clk(clk), .resetn(resetn), .data_i(tx_data), .valid_i(tx_valid),
        .ready_o(tx_ready), .txd(UART_txd));

    // ---------------- shared hardened lock ----------------
    wire        locked, lockout;
    wire        unlock_valid; wire [31:0] unlock_code; wire relock;
    scan_lock_controller_v2 #(
        .MAX_FAILS(MAX_FAILS), .LOCKOUT_CYCLES(LOCKOUT_CYCLES),
        .BOOT_DELAY_CYCLES(BOOT_DELAY_CYCLES), .HARD_LOCKOUT(1'b0)
    ) u_lock (
        .clk(clk), .resetn(lock_resetn),
        .unlock_valid(unlock_valid), .unlock_code_i(unlock_code),
        .secret_i(SECRET), .secret_valid_i(1'b1),
        .relock(relock), .locked(locked), .lockout_o(lockout));

    // ---------------- bridge (console / PCPI master / scan driver) ----------
    wire        b_pcpi_valid; wire [31:0] b_pcpi_insn, b_pcpi_rs1, b_pcpi_rs2;
    wire        b_scan_en, b_scan_in;
    wire [31:0] disp_val;
    // muxed responses from the selected instance
    wire        mx_pcpi_wr, mx_pcpi_wait, mx_pcpi_ready, mx_scan_out;
    wire [31:0] mx_pcpi_rd;

    scan_uart_bridge #(.DEF_LEVEL(0)) u_bridge (
        .clk(clk), .resetn(resetn),
        .rx_valid(rx_valid), .rx_data(rx_data),
        .tx_data(tx_data), .tx_valid(tx_valid), .tx_ready(tx_ready),
        .pcpi_valid(b_pcpi_valid), .pcpi_insn(b_pcpi_insn),
        .pcpi_rs1(b_pcpi_rs1), .pcpi_rs2(b_pcpi_rs2),
        .pcpi_wr(mx_pcpi_wr), .pcpi_rd(mx_pcpi_rd),
        .pcpi_wait(mx_pcpi_wait), .pcpi_ready(mx_pcpi_ready),
        .scan_en(b_scan_en), .scan_in(b_scan_in), .scan_out(mx_scan_out),
        .unlock_valid(unlock_valid), .unlock_code(unlock_code), .relock(relock),
        .locked(locked), .lockout(lockout),
        .disp_o(disp_val));
    // (DEF_LEVEL in the S reply is cosmetic; the live def is shown by led[2]/sel.)

    // ---------------- G1 instance ----------------
    wire g1_wr, g1_wait, g1_ready, g1_so; wire [31:0] g1_rd;
    aes_pcpi_def #(.DEFENSE_LEVEL(1)) u_g1 (
        .clk(clk), .resetn(resetn),
        .pcpi_valid(sel ? 1'b0 : b_pcpi_valid), .pcpi_insn(b_pcpi_insn),
        .pcpi_rs1(b_pcpi_rs1), .pcpi_rs2(b_pcpi_rs2),
        .pcpi_wr(g1_wr), .pcpi_rd(g1_rd), .pcpi_wait(g1_wait), .pcpi_ready(g1_ready),
        .dbg_key_stage(), .dbg_block_stage(), .dbg_core_key_reg(),
        .dbg_core_round_key_reg(), .dbg_core_state_reg(), .dbg_core_round_reg(),
        .scan_en(sel ? 1'b0 : b_scan_en), .scan_in(b_scan_in), .scan_out(g1_so),
        .locked(locked));

    // ---------------- G4 instance ----------------
    wire g4_wr, g4_wait, g4_ready, g4_so; wire [31:0] g4_rd;
    aes_pcpi_def #(.DEFENSE_LEVEL(4)) u_g4 (
        .clk(clk), .resetn(resetn),
        .pcpi_valid(sel ? b_pcpi_valid : 1'b0), .pcpi_insn(b_pcpi_insn),
        .pcpi_rs1(b_pcpi_rs1), .pcpi_rs2(b_pcpi_rs2),
        .pcpi_wr(g4_wr), .pcpi_rd(g4_rd), .pcpi_wait(g4_wait), .pcpi_ready(g4_ready),
        .dbg_key_stage(), .dbg_block_stage(), .dbg_core_key_reg(),
        .dbg_core_round_key_reg(), .dbg_core_state_reg(), .dbg_core_round_reg(),
        .scan_en(sel ? b_scan_en : 1'b0), .scan_in(b_scan_in), .scan_out(g4_so),
        .locked(locked));

    assign mx_pcpi_wr    = sel ? g4_wr    : g1_wr;
    assign mx_pcpi_rd    = sel ? g4_rd    : g1_rd;
    assign mx_pcpi_wait  = sel ? g4_wait  : g1_wait;
    assign mx_pcpi_ready = sel ? g4_ready : g1_ready;
    assign mx_scan_out   = sel ? g4_so    : g1_so;

    // ---------------- display / status ----------------
    wire busy = b_pcpi_valid | b_scan_en;
    seven_seg_hex #(.CLK_FREQ_HZ(CLK_FREQ_HZ)) u_disp (
        .clk(clk), .resetn(resetn), .value_i(disp_val),
        .an_d0(D0_AN), .seg_d0(D0_SEG), .an_d1(D1_AN), .seg_d1(D1_SEG));

    assign led = {12'b0, busy, sel, lockout, locked};
    assign RGB0 = {1'b0, ~locked, locked};   // R=locked, G=unlocked
    assign RGB1 = {busy, 2'b0};               // B while busy
endmodule
