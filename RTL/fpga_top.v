// ============================================================================
// fpga_top.v
//
// Synthesizable top-level for the on-chip scan attack/defense demonstration
// (Stage C/D of the project's FPGA plan, secure1.md Sections 21-24).
//
// Design decision (documented, not assumed): this bitstream targets the
// SELF-CONTAINED ATTACK/DEFENSE DEMO (scan_attack_harness.v), not the
// general-purpose CPU-driven path (secure_scan_rv_top_v2.v). Both are real
// and both are simulation-verified (tb_cpu_driven_aes.v / tb_scan_attack_
// harness.v), but they demonstrate different things and should not be
// merged into one bitstream:
//   - secure_scan_rv_top_v2.v needs a loaded program image and only proves
//     "the real CPU can drive the coprocessor" -- valuable, but not a
//     live demo of the security result itself.
//   - scan_attack_harness.v needs no program, no memory image, and no
//     toolchain: press a button, watch LEDs show either the recovered key
//     (unlocked) or all-zeros (locked). This directly demonstrates the
//     paper's central result with the simplest possible bring-up path, so
//     it is the right choice for the first physical bitstream.
// secure_scan_rv_top_v2.v remains available as a second, separate top-level
// for a future CPU-driven bitstream; nothing about that decision is
// foreclosed by this file.
//
// What this file adds on top of the already-verified scan_attack_harness.v
// (RTL unchanged, proven correct in simulation this session -- see
// tb_scan_attack_harness.v): the physical-I/O front end that a real FPGA
// board needs and a testbench does not.
//   - btn_start_raw is a real, bouncy, asynchronous pushbutton -> conditioned
//     into a single clean one-cycle pulse via btn_debounce_sync.
//   - sw_unlock_raw / sel_byte_raw are real slide/DIP switches -> conditioned
//     into stable debounced levels via level_debounce_sync.
//   - resetn_raw / lock_resetn_raw are real, asynchronous reset buttons ->
//     conditioned via reset_sync (async assert, sync deassert), preserving
//     secure_scan_rv_top_v2.v's existing two-reset-domain design intent
//     (a lock/unlock bit must not evaporate just because the functional
//     AES datapath is reset -- see scan_lock_controller.v).
//
// DEBOUNCE_CYCLES defaults are simulation-friendly (see io_conditioning.v).
// For real synthesis, override both to a value giving ~1-2 ms of settle
// time at the target board clock (e.g. DEBOUNCE_CYCLES=200_000 at 100 MHz).
// ============================================================================
`timescale 1ns/1ps

module fpga_top #(
    parameter integer BTN_DEBOUNCE_CYCLES = 20,   // simulation default; raise for real hardware
    parameter integer SW_DEBOUNCE_CYCLES  = 20,   // simulation default; raise for real hardware
    parameter [31:0]  UNLOCK_CODE         = 32'hDEC0DED1
) (
    input  wire       clk,             // board clock, already conditioned
                                        // (crystal/oscillator or MMCM output --
                                        // clock generation itself is out of
                                        // scope for this file)

    input  wire       resetn_raw,      // physical reset button, async, active-low
    input  wire       lock_resetn_raw, // physical lock-domain reset button,
                                        // async, active-low, SEPARATE from
                                        // resetn_raw (see header note)

    input  wire       btn_start_raw,   // physical momentary pushbutton,
                                        // async, active-high, bouncy
    input  wire       sw_unlock_raw,   // physical slide/toggle switch,
                                        // async, active-high
    input  wire [6:0] sel_byte_raw,    // physical DIP switches / slide
                                        // switches selecting which of the
                                        // 81 captured bytes to display

    output wire [7:0] led_out,         // selected captured byte
    output wire       led_done,        // attack/capture cycle complete
    output wire       led_locked       // current lock state (1=locked)
);

    // ------------------------------------------------------------------
    // Reset conditioning: async assert, sync deassert, two independent
    // domains (functional vs. lock), exactly mirroring
    // secure_scan_rv_top_v2.v's existing resetn/lock_resetn split.
    // ------------------------------------------------------------------
    wire resetn;
    wire lock_resetn;

    reset_sync u_reset_sync_func (
        .clk        (clk),
        .arstn_raw  (resetn_raw),
        .resetn_sync(resetn)
    );

    reset_sync u_reset_sync_lock (
        .clk        (clk),
        .arstn_raw  (lock_resetn_raw),
        .resetn_sync(lock_resetn)
    );

    // ------------------------------------------------------------------
    // Button conditioning: btn_start_raw -> one clean synchronous pulse.
    // This is the ONLY thing standing between real board I/O and the
    // exact synchronous btn_start contract scan_attack_harness.v was
    // built and verified against -- the harness itself is untouched.
    // ------------------------------------------------------------------
    wire btn_start_pulse;

    btn_debounce_sync #(
        .DEBOUNCE_CYCLES(BTN_DEBOUNCE_CYCLES)
    ) u_btn_start_cond (
        .clk    (clk),
        .resetn (resetn),
        .btn_raw(btn_start_raw),
        .pulse_o(btn_start_pulse)
    );

    // ------------------------------------------------------------------
    // Switch conditioning: sw_unlock_raw and sel_byte_raw are level
    // signals (not momentary), so they get debounced levels, not pulses.
    // ------------------------------------------------------------------
    wire sw_unlock_cond;
    wire [6:0] sel_byte_cond;

    level_debounce_sync #(
        .WIDTH(1),
        .DEBOUNCE_CYCLES(SW_DEBOUNCE_CYCLES)
    ) u_sw_unlock_cond (
        .clk       (clk),
        .resetn    (resetn),
        .level_raw (sw_unlock_raw),
        .level_o   (sw_unlock_cond)
    );

    level_debounce_sync #(
        .WIDTH(7),
        .DEBOUNCE_CYCLES(SW_DEBOUNCE_CYCLES)
    ) u_sel_byte_cond (
        .clk       (clk),
        .resetn    (resetn),
        .level_raw (sel_byte_raw),
        .level_o   (sel_byte_cond)
    );

    // ------------------------------------------------------------------
    // DUT: the already-verified, unmodified attack/defense harness.
    // ------------------------------------------------------------------
    scan_attack_harness #(
        .UNLOCK_CODE(UNLOCK_CODE)
    ) u_harness (
        .clk        (clk),
        .resetn     (resetn),
        .lock_resetn(lock_resetn),
        .btn_start  (btn_start_pulse),
        .sw_unlock  (sw_unlock_cond),
        .sel_byte   (sel_byte_cond),
        .led_out    (led_out),
        .led_done   (led_done),
        .led_locked (led_locked)
    );

endmodule