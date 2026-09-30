// ============================================================================
// board_top.v
//
// Synthesizable top-level for the Digilent Boolean Board (Spartan-7
// XC7S50-CSGA324), demonstrating the FULL project story on real hardware:
// real picorv32 CPU running real firmware over genuine PCPI fetch/decode,
// driving the real AES-128 coprocessor, with a live scan-chain attack/
// defense demo layered on top -- one board, no external toolchain needed
// at bring-up time.
//
// ----------------------------------------------------------------------
// WHY THIS FILE EXISTS SEPARATELY FROM secure_scan_rv_top_v2.v
// ----------------------------------------------------------------------
// secure_scan_rv_top_v2.v (already verified, tb_cpu_driven_aes.v PASS) does
// not expose aes_pcpi's dbg_core_key_reg/dbg_core_state_reg ports -- they're
// left unconnected. Reading the coprocessor's internal key/ciphertext from
// a sibling module via a hierarchical reference into another module's
// internal memory/registers is not reliable synthesizable practice. Rather
// than edit the already-verified secure_scan_rv_top_v2.v, this file mirrors
// its internal wiring EXACTLY (same picorv32 params, same aes_pcpi
// instantiation, same scan_lock_controller) and additionally wires the
// existing debug taps out to board-level registers. No functional RTL is
// different from the verified module -- only previously-unconnected debug
// output ports are now connected.
//
// ----------------------------------------------------------------------
// FIRMWARE
// ----------------------------------------------------------------------
// The exact hand-assembled program from tb_cpu_driven_aes.v (re-verified
// today: real picorv32 fetch/decode/PCPI, ciphertext matches NIST KAT) is
// preloaded into the unified memory. It runs automatically out of reset:
//   LOADKEY x4 (fixed KAT key) -> LOADBLOCK x4 (fixed KAT plaintext)
//   -> ENCRYPT -> READRESULT x4 (SW to memory, for parity with the
//   original testbench) -> EBREAK (asserts trap; CPU halts).
// No UART command parser is implemented in firmware: hand-decoding UART RX
// inside hand-assembled machine code (no cross-compiler toolchain available)
// is fragile for no real payoff on a fixed-KAT demo. Board switches/buttons
// control BOARD-LEVEL behavior (scan dump, lock, display selection) instead
// of CPU input.
//
// ----------------------------------------------------------------------
// WHY KEY/CIPHERTEXT ARE LATCHED, NOT READ LIVE
// ----------------------------------------------------------------------
// A scan dump with scan_in tied to 0 (see scan_dump_controller.v) zeroes
// every register in the scanned segment as a side effect of shifting --
// already proven in tb_scan_chain.v Check 4. So key_disp_reg/ct_disp_reg
// are latched the instant `trap` rises (firmware just finished), BEFORE any
// scan dump can destroy the live aes_core state. The 7-seg/UART "key" and
// "ciphertext" views always show these latches, not the live wires -- this
// means the demo sequence matters: read out key/ciphertext first, THEN run
// a scan dump. (Re-press btn[0] to reset and re-run firmware if you want
// the live display back after a scan dump.)
//
// ----------------------------------------------------------------------
// SWITCH / BUTTON MAP (see board_top.xdc)
// ----------------------------------------------------------------------
//   btn[0] : SYSTEM RESET       (functional domain: CPU + AES datapath)
//   btn[1] : LOCK-DOMAIN RESET  (separate domain -- lock state must survive
//                                a functional reset, per scan_lock_controller.v)
//   btn[2] : SCAN DUMP TRIGGER  (only acts while sw[0] ARM_SCAN is high --
//                                two-step interlock, mirrors "you need
//                                physical access AND deliberate action")
//   btn[3] : UART DUMP TRIGGER  (prints KEY, CIPHERTEXT, and the last SCAN
//                                CAPTURE as three ASCII-hex lines)
//
//   sw[0]  : ARM_SCAN           (must be high for btn[2] to trigger a dump)
//   sw[1]  : UNLOCK             (high = present correct unlock code / stay
//                                unlocked; low = relock, fail-safe default)
//   sw[2]  : DISPLAY_SOURCE     (0 = show latched KEY, 1 = show latched
//                                CIPHERTEXT, on the 7-seg display)
//   sw[4:3]: WORD_SEL[1:0]      (which 32-bit word, 0=MSB..3=LSB, of the
//                                selected 128-bit value the 7-seg shows --
//                                matches the project's own AES_LOADKEY/
//                                READRESULT word-index convention)
//   sw[15:5]: spare, looped to led[15:5] as a switch-wiring sanity check
//
// LEDs: led[0]=trap(cpu done) led[1]=locked led[2]=scan_dump busy
//       led[3]=scan_dump done led[4]=uart busy  led[15:5]=sw[15:5] passthrough
// RGB0: locked status (R=locked, G=unlocked)
// RGB1: B on while a scan dump is in progress
// ============================================================================
`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"

module board_top #(
    parameter integer CLK_FREQ_HZ = 100_000_000,
    parameter integer BAUD        = 115200,
    parameter integer MEM_WORDS   = 1024,
    parameter [31:0]  UNLOCK_CODE = 32'hDEC0DED1,
    // Debounce windows: board-realistic default (~1-2 ms at 100 MHz).
    // Override down (e.g. 20) only for simulation -- do not rely on a small
    // value for real synthesis, mirrors io_conditioning.v's own convention.
    parameter integer DEBOUNCE_CYCLES = 200_000
) (
    input  wire        clk,          // 100 MHz on-board oscillator

    input  wire [15:0] sw,
    output wire [15:0] led,
    input  wire [3:0]  btn,
    output wire [2:0]  RGB0,
    output wire [2:0]  RGB1,

    output wire [3:0]  D0_AN,
    output wire [7:0]  D0_SEG,
    output wire [3:0]  D1_AN,
    output wire [7:0]  D1_SEG,

    input  wire        UART_rxd,     // unused (no RX command parser) -- see header
    output wire        UART_txd
);

    // ------------------------------------------------------------------
    // Reset conditioning, deliberately POLARITY-AGNOSTIC -- do not assume
    // whether btn[0]/btn[1] idle high or low on your specific board.
    //
    //   power_on_reset: releases reset purely from configuration + clk,
    //   zero button dependence -- guarantees the design ALWAYS runs
    //   correctly immediately after programming, no button press needed.
    //
    //   edge_reset_pulse: fires a clean reset pulse on ANY transition of
    //   the button (press or release, either polarity) instead of
    //   assuming a particular idle level means "not pressed." A wrong
    //   polarity guess can therefore never hold the design in permanent
    //   reset -- idle (no transitions) never asserts it, in either wiring
    //   convention.
    //
    // resetn = POR AND edge-pulse: both must be released for the design
    // to run, exactly the AND-of-independent-reset-sources pattern
    // already used project-wide (resetn/lock_resetn as two domains).
    // ------------------------------------------------------------------
    wire por_resetn;
    power_on_reset #(.POR_CYCLES(64)) u_por (.clk(clk), .resetn_o(por_resetn));

    wire resetn_btn, lock_resetn_btn;
    edge_reset_pulse #(.PULSE_CYCLES(64)) u_rst_func (.clk(clk), .btn_raw(btn[0]), .resetn_o(resetn_btn));
    edge_reset_pulse #(.PULSE_CYCLES(64)) u_rst_lock (.clk(clk), .btn_raw(btn[1]), .resetn_o(lock_resetn_btn));

    wire resetn      = por_resetn & resetn_btn;
    wire lock_resetn = por_resetn & lock_resetn_btn;

    // ------------------------------------------------------------------
    // Button/switch conditioning (all reused, already-verified modules).
    // ------------------------------------------------------------------
    wire scan_trig_pulse, uart_trig_pulse;
    btn_debounce_sync #(.DEBOUNCE_CYCLES(DEBOUNCE_CYCLES)) u_btn_scan (
        .clk(clk), .resetn(resetn), .btn_raw(btn[2]), .pulse_o(scan_trig_pulse));
    btn_debounce_sync #(.DEBOUNCE_CYCLES(DEBOUNCE_CYCLES)) u_btn_uart (
        .clk(clk), .resetn(resetn), .btn_raw(btn[3]), .pulse_o(uart_trig_pulse));

    wire [15:0] sw_cond;
    level_debounce_sync #(.WIDTH(16), .DEBOUNCE_CYCLES(DEBOUNCE_CYCLES)) u_sw_cond (
        .clk(clk), .resetn(resetn), .level_raw(sw), .level_o(sw_cond));

    wire arm_scan       = sw_cond[0];
    wire sw_unlock      = sw_cond[1];
    wire display_source = sw_cond[2];
    wire [1:0] word_sel = sw_cond[4:3];

    // ------------------------------------------------------------------
    // Lock control: switch -> pulse translator -> the unmodified,
    // already-verified scan_lock_controller.v.
    // ------------------------------------------------------------------
    wire        locked;
    wire        unlock_valid;
    wire [31:0] unlock_code;
    wire        relock;

    lock_switch_ctrl #(.UNLOCK_CODE(UNLOCK_CODE)) u_lock_sw (
        .clk(clk), .resetn(lock_resetn), .sw_unlock(sw_unlock),
        .unlock_valid_o(unlock_valid), .unlock_code_o(unlock_code), .relock_o(relock));

    scan_lock_controller #(.UNLOCK_CODE(UNLOCK_CODE)) u_lock (
        .clk(clk), .resetn(lock_resetn),
        .unlock_valid(unlock_valid), .unlock_code_i(unlock_code),
        .relock(relock), .locked(locked));

    // ------------------------------------------------------------------
    // CPU + AES coprocessor, wired IDENTICALLY to the verified
    // secure_scan_rv_top_v2.v (SECURE_SCAN=1 body) -- only difference is
    // the dbg_* ports are connected instead of left open, and scan_en/
    // scan_in are driven by scan_dump_controller instead of a top-level
    // port, since the CPU (not a testbench) is the one loading real key
    // material here.
    // ------------------------------------------------------------------
    wire        mem_valid, mem_instr, mem_ready;
    wire [31:0] mem_addr, mem_wdata, mem_rdata;
    wire [3:0]  mem_wstrb;

    wire        pcpi_valid;
    wire [31:0] pcpi_insn, pcpi_rs1, pcpi_rs2;
    wire        pcpi_wr;
    wire [31:0] pcpi_rd;
    wire        pcpi_wait, pcpi_ready;

    wire        trap;

    wire        scan_en, scan_in, scan_out;

    wire [127:0] dbg_key_stage, dbg_block_stage;
    wire [127:0] dbg_core_key_reg, dbg_core_round_key_reg, dbg_core_state_reg;
    wire [3:0]   dbg_core_round_reg;

    picorv32 #(
        .ENABLE_COUNTERS(1), .ENABLE_COUNTERS64(1),
        .ENABLE_REGS_16_31(1), .ENABLE_REGS_DUALPORT(1),
        .CATCH_MISALIGN(1), .CATCH_ILLINSN(1),
        .ENABLE_PCPI(1), .ENABLE_MUL(0), .ENABLE_FAST_MUL(0), .ENABLE_DIV(0),
        .ENABLE_IRQ(0),
        .PROGADDR_RESET(32'h0000_0000), .STACKADDR(32'h0000_0FFC)
    ) u_cpu (
        .clk(clk), .resetn(resetn), .trap(trap),
        .mem_valid(mem_valid), .mem_instr(mem_instr), .mem_ready(mem_ready),
        .mem_addr(mem_addr), .mem_wdata(mem_wdata), .mem_wstrb(mem_wstrb), .mem_rdata(mem_rdata),
        .mem_la_read(), .mem_la_write(), .mem_la_addr(), .mem_la_wdata(), .mem_la_wstrb(),
        .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn), .pcpi_rs1(pcpi_rs1), .pcpi_rs2(pcpi_rs2),
        .pcpi_wr(pcpi_wr), .pcpi_rd(pcpi_rd), .pcpi_wait(pcpi_wait), .pcpi_ready(pcpi_ready),
        .irq(32'h0), .eoi(), .trace_valid(), .trace_data()
    );

    aes_pcpi u_aes_pcpi (
        .clk(clk), .resetn(resetn),
        .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn), .pcpi_rs1(pcpi_rs1), .pcpi_rs2(pcpi_rs2),
        .pcpi_wr(pcpi_wr), .pcpi_rd(pcpi_rd), .pcpi_wait(pcpi_wait), .pcpi_ready(pcpi_ready),
        .dbg_key_stage(dbg_key_stage), .dbg_block_stage(dbg_block_stage),
        .dbg_core_key_reg(dbg_core_key_reg), .dbg_core_round_key_reg(dbg_core_round_key_reg),
        .dbg_core_state_reg(dbg_core_state_reg), .dbg_core_round_reg(dbg_core_round_reg),
        .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out),
        .locked(locked)
    );

    // ------------------------------------------------------------------
    // Unified instruction/data memory, identical pattern to
    // secure_scan_rv_top_v2.v, preloaded with the exact verified program
    // from tb_cpu_driven_aes.v.
    // ------------------------------------------------------------------
    reg [31:0] memory [0:MEM_WORDS-1];
    reg [31:0] mem_rdata_q;
    reg        mem_ready_q;

    initial begin
        memory[0]  = 32'h000000b7; memory[1]  = 32'h00008093;
        memory[2]  = 32'h00010137; memory[3]  = 32'h20310113;
        memory[4]  = 32'h0020802b; memory[5]  = 32'h000000b7;
        memory[6]  = 32'h00108093; memory[7]  = 32'h04050137;
        memory[8]  = 32'h60710113; memory[9]  = 32'h0020802b;
        memory[10] = 32'h000000b7; memory[11] = 32'h00208093;
        memory[12] = 32'h08091137; memory[13] = 32'ha0b10113;
        memory[14] = 32'h0020802b; memory[15] = 32'h000000b7;
        memory[16] = 32'h00308093; memory[17] = 32'h0c0d1137;
        memory[18] = 32'he0f10113; memory[19] = 32'h0020802b;
        memory[20] = 32'h000000b7; memory[21] = 32'h00008093;
        memory[22] = 32'h00112137; memory[23] = 32'h23310113;
        memory[24] = 32'h0020902b; memory[25] = 32'h000000b7;
        memory[26] = 32'h00108093; memory[27] = 32'h44556137;
        memory[28] = 32'h67710113; memory[29] = 32'h0020902b;
        memory[30] = 32'h000000b7; memory[31] = 32'h00208093;
        memory[32] = 32'h8899b137; memory[33] = 32'habb10113;
        memory[34] = 32'h0020902b; memory[35] = 32'h000000b7;
        memory[36] = 32'h00308093; memory[37] = 32'hccddf137;
        memory[38] = 32'heff10113; memory[39] = 32'h0020902b;
        memory[40] = 32'h0000202b; memory[41] = 32'h00001237;
        memory[42] = 32'h80020213; memory[43] = 32'h000000b7;
        memory[44] = 32'h00008093; memory[45] = 32'h0000b1ab;
        memory[46] = 32'h00322023; memory[47] = 32'h000000b7;
        memory[48] = 32'h00108093; memory[49] = 32'h0000b1ab;
        memory[50] = 32'h00322223; memory[51] = 32'h000000b7;
        memory[52] = 32'h00208093; memory[53] = 32'h0000b1ab;
        memory[54] = 32'h00322423; memory[55] = 32'h000000b7;
        memory[56] = 32'h00308093; memory[57] = 32'h0000b1ab;
        memory[58] = 32'h00322623; memory[59] = 32'h00100073;
    end

    wire [$clog2(MEM_WORDS)-1:0] word_addr = mem_addr[$clog2(MEM_WORDS)+1:2];

    always @(posedge clk) begin
        mem_ready_q <= 1'b0;
        if (!resetn) begin
            mem_ready_q <= 1'b0;
        end else if (mem_valid && !mem_ready_q) begin
            mem_ready_q <= 1'b1;
            mem_rdata_q <= memory[word_addr];
            if (mem_wstrb[0]) memory[word_addr][ 7: 0] <= mem_wdata[ 7: 0];
            if (mem_wstrb[1]) memory[word_addr][15: 8] <= mem_wdata[15: 8];
            if (mem_wstrb[2]) memory[word_addr][23:16] <= mem_wdata[23:16];
            if (mem_wstrb[3]) memory[word_addr][31:24] <= mem_wdata[31:24];
        end
    end

    assign mem_ready = mem_ready_q;
    assign mem_rdata = mem_rdata_q;

    // ------------------------------------------------------------------
    // Latch key/ciphertext the instant firmware completes (trap rises),
    // BEFORE any scan dump can zero the live registers. See header note.
    // ------------------------------------------------------------------
    reg [127:0] key_disp_reg, ct_disp_reg;
    reg         trap_q;
    reg         cpu_done;

    always @(posedge clk) begin
        if (!resetn) begin
            trap_q       <= 1'b0;
            cpu_done     <= 1'b0;
            key_disp_reg <= 128'h0;
            ct_disp_reg  <= 128'h0;
        end else begin
            trap_q <= trap;
            if (trap && !trap_q) begin
                key_disp_reg <= dbg_core_key_reg;
                ct_disp_reg  <= dbg_core_state_reg; // ciphertext_o == state_reg_q at DONE
                cpu_done     <= 1'b1;
            end
        end
    end

    // ------------------------------------------------------------------
    // Scan dump controller: takes over scan_en/scan_in on demand.
    // ------------------------------------------------------------------
    localparam integer SCAN_WIDTH = 645;

    wire                     scan_dump_start = arm_scan && scan_trig_pulse;
    wire                     scan_dump_scan_en;
    wire                     scan_dump_scan_in;
    wire                     scan_dump_done;
    wire [SCAN_WIDTH-1:0]    scan_capture;

    scan_dump_controller #(.SCAN_WIDTH(SCAN_WIDTH)) u_scan_dump (
        .clk(clk), .resetn(resetn),
        .start_i(scan_dump_start),
        .scan_en_o(scan_dump_scan_en), .scan_in_o(scan_dump_scan_in),
        .scan_out_i(scan_out),
        .captured_o(scan_capture), .done_o(scan_dump_done)
    );

    assign scan_en = scan_dump_scan_en;
    assign scan_in = scan_dump_scan_in;

    // Last completed scan capture, held stable for display/UART even after
    // done_o deasserts on the next dump start.
    reg [SCAN_WIDTH-1:0] scan_capture_latched;
    always @(posedge clk) begin
        if (!resetn)
            scan_capture_latched <= {SCAN_WIDTH{1'b0}};
        else if (scan_dump_done)
            scan_capture_latched <= scan_capture;
    end

    // ------------------------------------------------------------------
    // 7-segment display: DISPLAY_SOURCE picks KEY or CIPHERTEXT (latched),
    // WORD_SEL picks which 32-bit word (0=MSB word .. 3=LSB word).
    // ------------------------------------------------------------------
    wire [127:0] disp_value128 = display_source ? ct_disp_reg : key_disp_reg;
    wire [31:0]  disp_word =
        (word_sel == 2'd0) ? disp_value128[127:96] :
        (word_sel == 2'd1) ? disp_value128[95:64]  :
        (word_sel == 2'd2) ? disp_value128[63:32]  :
                              disp_value128[31:0];

    seven_seg_hex #(.CLK_FREQ_HZ(CLK_FREQ_HZ)) u_sevenseg (
        .clk(clk), .resetn(resetn), .value_i(disp_word),
        .an_d0(D0_AN), .seg_d0(D0_SEG), .an_d1(D1_AN), .seg_d1(D1_SEG)
    );

    // ------------------------------------------------------------------
    // UART dump: on btn[3], print KEY, CIPHERTEXT, then the last SCAN
    // CAPTURE (padded to a whole nibble), one line each. Sequenced so the
    // three dumps don't collide on the single shared UART line.
    // ------------------------------------------------------------------
    localparam integer SCAN_DUMP_WIDTH = ((SCAN_WIDTH + 3) / 4) * 4; // pad to nibble = 648

    reg  [1:0] uart_seq_state;
    wire       key_dump_busy, ct_dump_busy, scan_dump_busy_tx;
    reg        key_dump_start, ct_dump_start, scandump_tx_start;
        wire txd_key, txd_ct, txd_scan;


    uart_hex_dumper #(.WIDTH(128), .CLK_FREQ_HZ(CLK_FREQ_HZ), .BAUD(BAUD)) u_dump_key (
        .clk(clk), .resetn(resetn), .data_i(key_disp_reg),
        .start_i(key_dump_start), .busy_o(key_dump_busy), .txd(txd_key));

    uart_hex_dumper #(.WIDTH(128), .CLK_FREQ_HZ(CLK_FREQ_HZ), .BAUD(BAUD)) u_dump_ct (
        .clk(clk), .resetn(resetn), .data_i(ct_disp_reg),
        .start_i(ct_dump_start), .busy_o(ct_dump_busy), .txd(txd_ct));

    uart_hex_dumper #(.WIDTH(SCAN_DUMP_WIDTH), .CLK_FREQ_HZ(CLK_FREQ_HZ), .BAUD(BAUD)) u_dump_scan (
        .clk(clk), .resetn(resetn),
        .data_i({{(SCAN_DUMP_WIDTH-SCAN_WIDTH){1'b0}}, scan_capture_latched}),
        .start_i(scandump_tx_start), .busy_o(scan_dump_busy_tx), .txd(txd_scan));

    // Three uart_hex_dumper instances share one physical UART_txd pin: only
    // one is ever actively driving (sequenced below), the others sit idle
    // (idle level = 1). A simple AND of the three idle-safe outputs works
    // because idle txd is always 1 and exactly one instance transmits at a
    // time in this sequence.
    assign UART_txd = txd_key & txd_ct & txd_scan;

    localparam U_IDLE = 2'd0, U_KEY = 2'd1, U_CT = 2'd2, U_SCAN = 2'd3;

    always @(posedge clk) begin
        key_dump_start    <= 1'b0;
        ct_dump_start     <= 1'b0;
        scandump_tx_start <= 1'b0;
        if (!resetn) begin
            uart_seq_state <= U_IDLE;
        end else begin
            case (uart_seq_state)
                U_IDLE: begin
                    if (uart_trig_pulse && !key_dump_busy && !ct_dump_busy && !scan_dump_busy_tx) begin
                        key_dump_start <= 1'b1;
                        uart_seq_state <= U_KEY;
                    end
                end
                U_KEY: if (!key_dump_busy && !key_dump_start) begin
                    ct_dump_start  <= 1'b1;
                    uart_seq_state <= U_CT;
                end
                U_CT: if (!ct_dump_busy && !ct_dump_start) begin
                    scandump_tx_start <= 1'b1;
                    uart_seq_state    <= U_SCAN;
                end
                U_SCAN: if (!scan_dump_busy_tx && !scandump_tx_start) begin
                    uart_seq_state <= U_IDLE;
                end
                default: uart_seq_state <= U_IDLE;
            endcase
        end
    end

    // ------------------------------------------------------------------
    // LEDs / RGB status
    // ------------------------------------------------------------------
    assign led[0]     = cpu_done;
    assign led[1]     = locked;
    assign led[2]     = scan_dump_scan_en;              // scan dump in progress
    assign led[3]     = scan_dump_done;
    assign led[4]     = key_dump_busy | ct_dump_busy | scan_dump_busy_tx;
    assign led[15:5]  = sw_cond[15:5];                   // wiring sanity check

    assign RGB0[0] = locked;      // red   = locked
    assign RGB0[1] = ~locked;     // green = unlocked
    assign RGB0[2] = 1'b0;
    assign RGB1[0] = 1'b0;
    assign RGB1[1] = 1'b0;
    assign RGB1[2] = scan_dump_scan_en; // blue while a scan dump is running

endmodule