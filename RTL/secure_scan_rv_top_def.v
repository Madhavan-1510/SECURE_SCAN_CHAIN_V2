// ============================================================================
// secure_scan_rv_top_def.v  (Paper 2, Phase 5)
//
// Same CPU + AES coprocessor + behavioural memory as secure_scan_rv_top_v2.v,
// with the defense variant and the lock controller selected by parameter.
// secure_scan_rv_top_v2.v is left untouched as the Paper 1 baseline.
//
// DEFENSE_LEVEL:
//   0     = original aes_pcpi/aes_core (Paper 1 datapath, G0/G1 by lock choice)
//   1..5  = aes_pcpi_def with that DEFENSE_LEVEL (1=G1, 2=G2, 3=G3, 4=G4, 5=G2R)
// LOCK_VERSION:
//   0 = no lock, `locked` tied 0 (undefended G0 when DEFENSE_LEVEL=0)
//   1 = scan_lock_controller    (Paper 1: static UNLOCK_CODE, no limiter)
//   2 = scan_lock_controller_v2 (L1: secret_i/secret_valid_i, lockout, boot delay)
// secret_i / secret_valid_i / lockout_o are used only when LOCK_VERSION=2
// (lockout_o reads 0 otherwise); unlock_code_i / unlock_valid / relock are
// shared by both lock versions.
// ============================================================================
`timescale 1ns/1ps

module secure_scan_rv_top_def #(
    parameter [31:0]  PROGADDR_RESET    = 32'h0000_0000,
    parameter [31:0]  STACKADDR         = 32'h0000_0FFC,
    parameter integer DEFENSE_LEVEL     = 4,
    parameter integer LOCK_VERSION      = 2,
    parameter integer MEM_WORDS         = 1024,
    parameter         MEM_INIT_FILE     = "",
    parameter [31:0]  UNLOCK_CODE       = 32'hDEC0DED1,   // LOCK_VERSION=1 only
    parameter integer MAX_FAILS         = 3,              // LOCK_VERSION=2 only
    parameter integer LOCKOUT_CYCLES    = 100_000_000,
    parameter integer BOOT_DELAY_CYCLES = 100_000_000,
    parameter [0:0]   HARD_LOCKOUT      = 1'b0
) (
    input  wire        clk,
    input  wire        resetn,        // resets CPU + AES datapath
    input  wire        lock_resetn,   // separate reset domain for the lock

    output wire        trap,

    input  wire        scan_en,
    input  wire        scan_in,
    output wire        scan_out,

    input  wire        unlock_valid,
    input  wire [31:0] unlock_code_i,
    input  wire        relock,
    input  wire [31:0] secret_i,
    input  wire        secret_valid_i,
    output wire        locked,
    output wire        lockout_o
);

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

    generate
        if (DEFENSE_LEVEL == 0) begin : g_aes_orig
            aes_pcpi u_aes_pcpi (
                .clk(clk), .resetn(resetn),
                .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn),
                .pcpi_rs1(pcpi_rs1), .pcpi_rs2(pcpi_rs2),
                .pcpi_wr(pcpi_wr), .pcpi_rd(pcpi_rd),
                .pcpi_wait(pcpi_wait), .pcpi_ready(pcpi_ready),
                .dbg_key_stage(), .dbg_block_stage(),
                .dbg_core_key_reg(), .dbg_core_round_key_reg(),
                .dbg_core_state_reg(), .dbg_core_round_reg(),
                .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out),
                .locked(locked)
            );
        end else begin : g_aes_def
            aes_pcpi_def #(.DEFENSE_LEVEL(DEFENSE_LEVEL)) u_aes_pcpi (
                .clk(clk), .resetn(resetn),
                .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn),
                .pcpi_rs1(pcpi_rs1), .pcpi_rs2(pcpi_rs2),
                .pcpi_wr(pcpi_wr), .pcpi_rd(pcpi_rd),
                .pcpi_wait(pcpi_wait), .pcpi_ready(pcpi_ready),
                .dbg_key_stage(), .dbg_block_stage(),
                .dbg_core_key_reg(), .dbg_core_round_key_reg(),
                .dbg_core_state_reg(), .dbg_core_round_reg(),
                .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out),
                .locked(locked)
            );
        end

        if (LOCK_VERSION == 1) begin : g_lock_v1
            scan_lock_controller #(.UNLOCK_CODE(UNLOCK_CODE)) u_lock (
                .clk(clk), .resetn(lock_resetn),
                .unlock_valid(unlock_valid),
                .unlock_code_i(unlock_code_i),
                .relock(relock),
                .locked(locked)
            );
            assign lockout_o = 1'b0;
        end else if (LOCK_VERSION == 2) begin : g_lock_v2
            scan_lock_controller_v2 #(
                .MAX_FAILS(MAX_FAILS), .LOCKOUT_CYCLES(LOCKOUT_CYCLES),
                .BOOT_DELAY_CYCLES(BOOT_DELAY_CYCLES), .HARD_LOCKOUT(HARD_LOCKOUT)
            ) u_lock (
                .clk(clk), .resetn(lock_resetn),
                .unlock_valid(unlock_valid),
                .unlock_code_i(unlock_code_i),
                .secret_i(secret_i),
                .secret_valid_i(secret_valid_i),
                .relock(relock),
                .locked(locked),
                .lockout_o(lockout_o)
            );
        end else begin : g_no_lock
            assign locked    = 1'b0;
            assign lockout_o = 1'b0;
        end
    endgenerate

    // ---------------------------------------------------------------
    // Behavioural memory: identical to secure_scan_rv_top_v2.v.
    // ---------------------------------------------------------------
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
