// ============================================================================
// secure_scan_rv_top.v
//
// Purpose:
//   Phase 2/3 milestone: wire the AES-128 PCPI coprocessor to a real,
//   unmodified picorv32 core. No scan chain yet (that is Phase 5/6) -- this
//   module's only job is to prove the CPU + PCPI + AES integration
//   elaborates and simulates correctly.
//
// PCPI wiring notes:
//   - ENABLE_PCPI=1 is REQUIRED on the picorv32 instance, or WITH_PCPI is
//     false internally and the pcpi_* ports are never driven meaningfully
//     (instr_trap would not depend on WITH_PCPI, and no PCPI transaction
//     would ever be attempted).
//   - We leave ENABLE_MUL/ENABLE_DIV/ENABLE_FAST_MUL at 0 for this milestone
//     to keep the PCPI port dedicated to aes_pcpi with no internal-vs-
//     external PCPI arbitration to reason about. (picorv32's pcpi_int_*
//     muxing logic in the core already shows how you'd OR multiple PCPI
//     responders together if MUL/DIV were also enabled -- same pattern
//     would need to be replicated for external ports if we ever add a
//     second external PCPI device. Only one external PCPI device is
//     supported by the port list as given.)
//   - CATCH_ILLINSN=1 is required for the pcpi_timeout safety net to exist
//     at all; keep it enabled.
// ============================================================================
`timescale 1ns/1ps

module secure_scan_rv_top #(
    parameter [31:0] PROGADDR_RESET = 32'h0000_0000,
    parameter [31:0] STACKADDR      = 32'h0000_1000
) (
    input  wire        clk,
    input  wire         resetn,

    // Simple synchronous memory interface (instruction + data), intended
    // to be connected to a behavioral instruction/data RAM in simulation,
    // or a BRAM-based memory controller on FPGA. AES coprocessor state is
    // NEVER placed in this memory -- see aes_pcpi.v / aes_core.v.
    output wire        mem_valid,
    output wire        mem_instr,
    input  wire        mem_ready,
    output wire [31:0] mem_addr,
    output wire [31:0] mem_wdata,
    output wire [ 3:0] mem_wstrb,
    input  wire [31:0] mem_rdata,

    output wire        trap
);

    wire        pcpi_valid;
    wire [31:0] pcpi_insn;
    wire [31:0] pcpi_rs1;
    wire [31:0] pcpi_rs2;
    wire        pcpi_wr;
    wire [31:0] pcpi_rd;
    wire        pcpi_wait;
    wire        pcpi_ready;

    // Scan-map debug taps (unused until Phase 5/6 scan chain is added)
    wire [127:0] dbg_key_stage, dbg_block_stage;
    wire [127:0] dbg_core_key_reg, dbg_core_round_key_reg, dbg_core_state_reg;
    wire [3:0]   dbg_core_round_reg;

    picorv32 #(
        .ENABLE_COUNTERS   (1),
        .ENABLE_COUNTERS64 (1),
        .ENABLE_REGS_16_31 (1),
        .ENABLE_REGS_DUALPORT(1),
        .CATCH_MISALIGN    (1),
        .CATCH_ILLINSN     (1),   // required: enables the pcpi_timeout safety net
        .ENABLE_PCPI       (1),   // required: routes unrecognized instrs to our PCPI port
        .ENABLE_MUL        (0),
        .ENABLE_FAST_MUL   (0),
        .ENABLE_DIV        (0),
        .ENABLE_IRQ        (0),   // keep custom-0 (0001011) fully unused; we use custom-1
        .PROGADDR_RESET    (PROGADDR_RESET),
        .STACKADDR         (STACKADDR)
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

        .mem_la_read (),
        .mem_la_write(),
        .mem_la_addr (),
        .mem_la_wdata(),
        .mem_la_wstrb(),

        .pcpi_valid(pcpi_valid),
        .pcpi_insn (pcpi_insn),
        .pcpi_rs1  (pcpi_rs1),
        .pcpi_rs2  (pcpi_rs2),
        .pcpi_wr   (pcpi_wr),
        .pcpi_rd   (pcpi_rd),
        .pcpi_wait (pcpi_wait),
        .pcpi_ready(pcpi_ready),

        .irq(32'h0),
        .eoi(),

        .trace_valid(),
        .trace_data ()
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

        .dbg_key_stage         (dbg_key_stage),
        .dbg_block_stage       (dbg_block_stage),
        .dbg_core_key_reg      (dbg_core_key_reg),
        .dbg_core_round_key_reg(dbg_core_round_key_reg),
        .dbg_core_state_reg    (dbg_core_state_reg),
        .dbg_core_round_reg    (dbg_core_round_reg)
    );

endmodule
