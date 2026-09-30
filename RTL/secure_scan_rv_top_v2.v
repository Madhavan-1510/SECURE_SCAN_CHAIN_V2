// ============================================================================
// secure_scan_rv_top_v2.v
//
// Phase 9-closure top-level. Supersedes secure_scan_rv_top.v for anything
// involving scan, lock, or an actually-runnable program, because
// secure_scan_rv_top.v (Phase 2/3) has neither:
//
//   - No scan_en/scan_in/scan_out/locked anywhere in its port list or its
//     aes_pcpi instantiation -- it predates Phase 8/9. Synthesizing it as-is
//     produces a bitstream with no scan defense in the hierarchy at all.
//   - No instruction/data memory -- mem_valid/mem_addr/... are top-level
//     ports with nothing behind them, so the CPU has never had anything to
//     actually fetch.
//
// This file fixes both, and is the first top-level in the project where the
// real picorv32 core drives aes_pcpi through genuine fetch -> decode -> PCPI
// handshake, rather than a testbench pretending to be the CPU.
//
// SECURE_SCAN parameter:
//   1 (default) -- scan_lock_controller is instantiated; `locked` comes from
//                  it and defaults fail-safe locked=1 out of reset, matching
//                  Phase 8/9.
//   0           -- no lock controller is instantiated at all; `locked` is
//                  tied combinationally to 0. This is the genuine
//                  "undefended baseline" build for a fair Phase 10 LUT/FF
//                  comparison -- not just the defended build with the lock
//                  disabled, but the lock hardware physically absent.
//
// Memory model:
//   Single, unified, word-addressed synchronous memory (instruction and
//   data share one address space, exactly like the picorv32 project's own
//   reference testbench memory). One-cycle response latency; picorv32
//   tolerates any fixed or variable memory latency, so this is a safe,
//   standard choice. MEM_WORDS sizes it; MEM_INIT_FILE, if non-empty, is
//   passed to $readmemh to preload it -- this is synthesizable in Vivado
//   (used for BRAM initialization) as well as simulatable in Icarus.
// ============================================================================
`timescale 1ns/1ps

module secure_scan_rv_top_v2 #(
    parameter [31:0] PROGADDR_RESET = 32'h0000_0000,
    parameter [31:0] STACKADDR      = 32'h0000_0FFC,
    parameter        SECURE_SCAN    = 0,
    parameter integer MEM_WORDS     = 1024,
    parameter         MEM_INIT_FILE = "",
    parameter [31:0]  UNLOCK_CODE   = 32'hDEC0DED1
) (
    input  wire        clk,
    input  wire        resetn,        // resets CPU + AES datapath
    input  wire        lock_resetn,   // separate reset domain for the lock
                                       // controller only (Phase 8 rationale:
                                       // a lock/unlock config bit should not
                                       // evaporate just because the AES
                                       // core's functional state is reset)

    output wire        trap,

    // Whole-coprocessor scan interface -- genuinely exposed this time.
    input  wire        scan_en,
    input  wire        scan_in,
    output wire        scan_out,

    // Lock control (only meaningful when SECURE_SCAN=1; harmless no-ops
    // otherwise since `locked` is tied to 0 in that build).
    input  wire        unlock_valid,
    input  wire [31:0] unlock_code_i,
    input  wire        relock,
    output wire        locked
);

    // ------------------------------------------------------------------
    // CPU <-> PCPI wiring (identical contract to secure_scan_rv_top.v)
    // ------------------------------------------------------------------
    wire        mem_valid, mem_instr, mem_ready;
    wire [31:0] mem_addr, mem_wdata, mem_rdata;
    wire [3:0]  mem_wstrb;

    wire        pcpi_valid;
    wire [31:0] pcpi_insn;
    wire [31:0] pcpi_rs1;
    wire [31:0] pcpi_rs2;
    wire        pcpi_wr;
    wire [31:0] pcpi_rd;
    wire        pcpi_wait;
    wire        pcpi_ready;

    picorv32 #(
        .ENABLE_COUNTERS     (1),
        .ENABLE_COUNTERS64   (1),
        .ENABLE_REGS_16_31   (1),
        .ENABLE_REGS_DUALPORT(1),
        .CATCH_MISALIGN      (1),
        .CATCH_ILLINSN       (1),
        .ENABLE_PCPI         (1),
        .ENABLE_MUL          (0),
        .ENABLE_FAST_MUL     (0),
        .ENABLE_DIV          (0),
        .ENABLE_IRQ          (0),
        .PROGADDR_RESET      (PROGADDR_RESET),
        .STACKADDR           (STACKADDR)
    ) u_cpu (
        .clk       (clk),
        .resetn    (resetn),
        .trap      (trap),

        .mem_valid (mem_valid),
        .mem_instr (mem_instr),
        .mem_ready (mem_ready),
        .mem_addr  (mem_addr),
        .mem_wdata (mem_wdata),
        .mem_wstrb (mem_wstrb),
        .mem_rdata (mem_rdata),

        .mem_la_read (), .mem_la_write(), .mem_la_addr(),
        .mem_la_wdata(), .mem_la_wstrb(),

        .pcpi_valid(pcpi_valid),
        .pcpi_insn (pcpi_insn),
        .pcpi_rs1  (pcpi_rs1),
        .pcpi_rs2  (pcpi_rs2),
        .pcpi_wr   (pcpi_wr),
        .pcpi_rd   (pcpi_rd),
        .pcpi_wait (pcpi_wait),
        .pcpi_ready(pcpi_ready),

        .irq(32'h0), .eoi(),
        .trace_valid(), .trace_data()
    );

    aes_pcpi u_aes_pcpi (
        .clk       (clk),
        .resetn    (resetn),
        .pcpi_valid(pcpi_valid),
        .pcpi_insn (pcpi_insn),
        .pcpi_rs1  (pcpi_rs1),
        .pcpi_rs2  (pcpi_rs2),
        .pcpi_wr   (pcpi_wr),
        .pcpi_rd   (pcpi_rd),
        .pcpi_wait (pcpi_wait),
        .pcpi_ready(pcpi_ready),

        .dbg_key_stage(), .dbg_block_stage(),
        .dbg_core_key_reg(), .dbg_core_round_key_reg(),
        .dbg_core_state_reg(), .dbg_core_round_reg(),

        .scan_en (scan_en),
        .scan_in (scan_in),
        .scan_out(scan_out),
        .locked  (locked)
    );

    // ------------------------------------------------------------------
    // Lock controller -- physically present only when SECURE_SCAN=1.
    // ------------------------------------------------------------------
    generate
        if (SECURE_SCAN) begin : g_secure
            scan_lock_controller #(.UNLOCK_CODE(UNLOCK_CODE)) u_lock (
                .clk(clk), .resetn(lock_resetn),
                .unlock_valid(unlock_valid),
                .unlock_code_i(unlock_code_i),
                .relock(relock),
                .locked(locked)
            );
        end else begin : g_baseline
            // Genuine undefended baseline: no lock hardware exists at all,
            // not just "disabled" -- this is what Phase 10's LUT/FF
            // comparison must be built from for an honest overhead number.
            assign locked = 1'b0;
        end
    endgenerate

    // ------------------------------------------------------------------
    // Unified instruction/data memory. Single-port, word-addressed,
    // one-cycle response -- same pattern as picorv32's own reference
    // testbench memory model. $readmemh is synthesizable in Vivado for
    // BRAM initialization, so this same file works for both simulation
    // and the eventual FPGA build.
    // ------------------------------------------------------------------
    reg [31:0] memory [0:MEM_WORDS-1];
    reg [31:0] mem_rdata_q;
    reg        mem_ready_q;

    generate
        if (MEM_INIT_FILE != "") begin : g_init
            initial $readmemh(MEM_INIT_FILE, memory);
        end
    endgenerate

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

endmodule
