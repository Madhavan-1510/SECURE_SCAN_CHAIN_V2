// ============================================================================
// tb_fpga_top.v
//
// Verifies fpga_top.v, i.e. the physical-I/O conditioning front-end PLUS
// the already-verified scan_attack_harness.v behind it. Two things must be
// shown that tb_scan_attack_harness.v alone cannot show, because that
// testbench drives clean synchronous stimulus directly:
//
//   1. A REALISTICALLY BOUNCY physical button (multiple spurious
//      transitions within a short window, then settling) must still result
//      in exactly ONE attack/capture cycle -- not zero (debounced away
//      entirely) and not several (each bounce misread as a separate press).
//   2. With that bouncy stimulus, the harness must still reproduce both the
//      LOCKED (key not recoverable) and UNLOCKED (key recoverable, matches
//      KAT) results, exactly as tb_scan_attack_harness.v already proved
//      with clean stimulus -- i.e. the conditioning front-end is
//      transparent to correct behavior, not just "harmless."
//
// DEBOUNCE_CYCLES is overridden small here purely so this bounce-injection
// test completes in a reasonable number of simulated cycles; this does not
// change the RTL's structure, only its instantiation parameters, exactly
// as intended (see io_conditioning.v header).
// ============================================================================
`timescale 1ns/1ps

module tb_fpga_top;

    localparam integer BTN_DEBOUNCE_CYCLES = 8;
    localparam integer SW_DEBOUNCE_CYCLES  = 8;

    reg clk = 0;
    reg resetn_raw = 0;
    reg lock_resetn_raw = 0;
    reg btn_start_raw = 0;
    reg sw_unlock_raw = 0;
    reg [6:0] sel_byte_raw = 0;

    wire [7:0] led_out;
    wire led_done, led_locked;

    localparam [127:0] KEY = 128'h000102030405060708090A0B0C0D0E0F;

    fpga_top #(
        .BTN_DEBOUNCE_CYCLES(BTN_DEBOUNCE_CYCLES),
        .SW_DEBOUNCE_CYCLES(SW_DEBOUNCE_CYCLES)
    ) dut (
        .clk(clk),
        .resetn_raw(resetn_raw),
        .lock_resetn_raw(lock_resetn_raw),
        .btn_start_raw(btn_start_raw),
        .sw_unlock_raw(sw_unlock_raw),
        .sel_byte_raw(sel_byte_raw),
        .led_out(led_out),
        .led_done(led_done),
        .led_locked(led_locked)
    );

    always #5 clk = ~clk;
    integer errors = 0;

    // Count how many times the conditioned pulse actually fires, by
    // watching the conditioned btn_start_pulse signal directly (the exact
    // output of the debounce front-end that drives the harness). This is
    // hierarchical observation for VERIFICATION purposes only (checking
    // "exactly one clean pulse was produced per physical press"), not part
    // of the attack itself. NOTE: counting FSM state transitions instead
    // (e.g. "exits from S_IDLE") is the WRONG check here -- the harness's
    // own S_DONE state legitimately re-triggers a fresh attack cycle
    // directly on the next btn_start pulse without passing back through
    // S_IDLE (see scan_attack_harness.v's S_DONE case), so an IDLE-exit
    // counter under-counts genuine, correctly-handled second presses.
    integer idle_exits;
    always @(posedge clk) begin
        if (!resetn_raw)
            idle_exits = 0;
        else if (dut.btn_start_pulse)
            idle_exits = idle_exits + 1;
    end

    // Drives a deliberately bouncy press: several fast, noisy transitions
    // within a window shorter than the debounce filter, then settles high
    // for a long, clean hold -- exactly the real-world contact-bounce
    // profile the debounce logic exists to reject.
    task bouncy_press;
        begin
            btn_start_raw = 1'b1; #3;
            btn_start_raw = 1'b0; #2;
            btn_start_raw = 1'b1; #4;
            btn_start_raw = 1'b0; #1;
            btn_start_raw = 1'b1; #3;
            btn_start_raw = 1'b0; #2;
            // settle: held solidly high, long enough to clear the debounce
            // window many times over
            btn_start_raw = 1'b1;
            repeat (40) @(posedge clk);
            // bouncy release
            btn_start_raw = 1'b0; #3;
            btn_start_raw = 1'b1; #2;
            btn_start_raw = 1'b0;
            repeat (10) @(posedge clk);
        end
    endtask

    task read_key_bytes(output [127:0] key_out);
        integer b;
        begin
            for (b = 0; b < 16; b = b + 1) begin
                sel_byte_raw = b;
                repeat (SW_DEBOUNCE_CYCLES + 4) @(posedge clk); // let switch debounce settle
                key_out[127-8*b -: 8] = led_out;
            end
        end
    endtask

    reg [127:0] recovered;
    integer snapshot;

    initial begin
        resetn_raw = 0; lock_resetn_raw = 0;
        repeat (5) @(posedge clk);
        resetn_raw = 1; lock_resetn_raw = 1;
        repeat (5) @(posedge clk);

        // ---- Case 1: LOCKED (fail-safe default), bouncy button press ----
        sw_unlock_raw = 0;
        repeat (SW_DEBOUNCE_CYCLES + 4) @(posedge clk); // let sw_unlock debounce settle low
        snapshot = idle_exits;
        bouncy_press;
        wait (led_done == 1'b1);
        @(posedge clk); #1;

        if ((idle_exits - snapshot) !== 1) begin
            $display("FAIL: bouncy press produced %0d conditioned pulses (expected exactly 1) -- debounce not collapsing bounce correctly", idle_exits - snapshot);
            errors = errors + 1;
        end else begin
            $display("PASS: bouncy physical button press correctly collapsed to exactly 1 conditioned pulse");
        end

        if (led_locked !== 1'b1) begin
            $display("FAIL: fpga_top did not show locked=1 in default case");
            errors = errors + 1;
        end
        read_key_bytes(recovered);
        $display("LOCKED case (via bouncy button): captured key window = %032h (expect all-zero)", recovered);
        if (recovered === {128{1'b0}}) begin
            $display("PASS: fpga_top reproduces LOCKED defense result through the real I/O front-end");
        end else begin
            $display("FAIL: fpga_top shows key recoverable while locked!");
            errors = errors + 1;
        end

        // ---- Case 2: UNLOCKED, bouncy button press again ----
        sw_unlock_raw = 1;
        repeat (SW_DEBOUNCE_CYCLES + 4) @(posedge clk); // let sw_unlock debounce settle high
        snapshot = idle_exits;
        bouncy_press;
        wait (led_done == 1'b1);
        @(posedge clk); #1;

        if ((idle_exits - snapshot) !== 1) begin
            $display("FAIL: second bouncy press produced %0d conditioned pulses (expected exactly 1)", idle_exits - snapshot);
            errors = errors + 1;
        end else begin
            $display("PASS: second bouncy press also correctly collapsed to exactly 1 conditioned pulse");
        end

        if (led_locked !== 1'b0) begin
            $display("FAIL: fpga_top did not show locked=0 after unlock");
            errors = errors + 1;
        end
        read_key_bytes(recovered);
        $display("UNLOCKED case (via bouncy button): captured key window = %032h (expect real KEY)", recovered);
        if (recovered === KEY) begin
            $display("PASS: fpga_top reproduces UNLOCKED baseline result through the real I/O front-end");
        end else begin
            $display("FAIL: fpga_top did not recover the real key while unlocked");
            errors = errors + 1;
        end

        if (errors == 0)
            $display("TESTBENCH: ALL TESTS PASSED");
        else
            $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $finish;
    end

    initial begin
        #2000000;
        $display("RESULT: GLOBAL TIMEOUT");
        $finish;
    end

endmodule