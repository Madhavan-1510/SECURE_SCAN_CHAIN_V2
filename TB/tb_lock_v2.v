`timescale 1ns/1ps
// ============================================================================
// tb_lock_v2.v -- Paper 2 Phase 2, unit test of scan_lock_controller_v2.v (L1).
//
// Cycle semantics under test (from the RTL header, re-derived here, not assumed):
//   * after resetn rises, the first BOOT_DELAY_CYCLES clock edges ignore
//     unlock_valid; the next edge evaluates it.
//   * MAX_FAILS consecutive wrong evaluated codes start a lockout; the next
//     LOCKOUT_CYCLES edges ignore unlock_valid (not evaluated, not counted,
//     do not extend the lockout); the edge after that evaluates.
//   * HARD_LOCKOUT=1: lockout is permanent until resetn.
//   * relock beats a simultaneous unlock; reset re-locks (fail-safe).
//
// All stimulus changes on negedge clk (no same-edge race with the DUT).
// Parameters used by the main DUT are deliberately small so tests are fast:
//   MAX_FAILS=3 LOCKOUT_CYCLES=50 BOOT_DELAY_CYCLES=20
// Attacker-cost helpers (atk_cost / atk_cost_rst) use their own parameters.
// ============================================================================

// ---------------------------------------------------------------------------
// Autonomous attacker that guesses sequentially 0,1,2,... and knows lockout_o.
// It only advances the guess on an EVALUATED attempt. Measures posedges from
// reset release until locked==0.  Waits out every lockout.
// ---------------------------------------------------------------------------
module atk_cost #(
    parameter integer MF = 3, parameter integer LO = 1000, parameter integer BD = 1000,
    parameter [31:0] SECRET = 32'd40
) (
    input  wire clk,
    output reg  done,
    output integer cycles,
    output integer evals
);
    reg resetn = 0, uv = 0; reg [31:0] code = 0;
    wire locked, lockout;
    scan_lock_controller_v2 #(.MAX_FAILS(MF), .LOCKOUT_CYCLES(LO), .BOOT_DELAY_CYCLES(BD), .HARD_LOCKOUT(1'b0)) d (
        .clk(clk), .resetn(resetn), .unlock_valid(uv), .unlock_code_i(code),
        .secret_i(SECRET), .secret_valid_i(1'b1), .relock(1'b0), .locked(locked), .lockout_o(lockout));
    reg [31:0] g = 0; reg started = 0; integer n_reset = 0;
    initial begin done = 0; cycles = 0; evals = 0; end
    always @(negedge clk) begin
        if (!resetn) begin
            n_reset = n_reset + 1;
            if (n_reset == 4) begin resetn = 1; started = 1; end
        end else if (started && !done) begin
            // sample outcome of the previous posedge
            if (!locked) done = 1;
            else begin
                // decide what to present for the NEXT posedge
                if (!lockout) begin uv = 1; code = g; end
                else begin uv = 1; code = g; end   // attacker presents; ignored if lockout
            end
        end
    end
    // count posedges since release; advance guess only if it was evaluated
    reg prev_lockout = 1;
    always @(posedge clk) begin
        if (resetn && started && !done) begin
            cycles = cycles + 1;
            if (uv && locked && !lockout) begin evals = evals + 1; g = g + 1; end
        end
    end
endmodule

// ---------------------------------------------------------------------------
// Reset-cycling attacker: after MF evaluated failures (which would trigger a
// lockout) it pulses resetn low for RST_CYCLES edges instead of waiting.
// Reset clears the fail counter and the lockout, but re-arms the boot delay.
// Counts every posedge from first release (including reset-low edges).
// ---------------------------------------------------------------------------
module atk_cost_rst #(
    parameter integer MF = 3, parameter integer LO = 1000, parameter integer BD = 1000,
    parameter integer RST_CYCLES = 2, parameter [31:0] SECRET = 32'd40
) (
    input  wire clk,
    output reg  done,
    output integer cycles,
    output integer resets
);
    reg resetn = 0, uv = 0; reg [31:0] code = 0;
    wire locked, lockout;
    scan_lock_controller_v2 #(.MAX_FAILS(MF), .LOCKOUT_CYCLES(LO), .BOOT_DELAY_CYCLES(BD), .HARD_LOCKOUT(1'b0)) d (
        .clk(clk), .resetn(resetn), .unlock_valid(uv), .unlock_code_i(code),
        .secret_i(SECRET), .secret_valid_i(1'b1), .relock(1'b0), .locked(locked), .lockout_o(lockout));
    reg [31:0] g = 0; reg started = 0; integer n_reset = 0, fails_local = 0, rst_left = 0;
    initial begin done = 0; cycles = 0; resets = 0; end
    always @(negedge clk) begin
        if (!started) begin
            n_reset = n_reset + 1;
            if (n_reset == 4) begin resetn = 1; started = 1; end
        end else if (!done) begin
            if (!locked) done = 1;
            else if (rst_left > 0) begin
                rst_left = rst_left - 1;
                if (rst_left == 0) resetn = 1;
            end else if (fails_local >= MF) begin
                resetn = 0; rst_left = RST_CYCLES; fails_local = 0; resets = resets + 1;
            end else begin uv = 1; code = g; end
        end
    end
    always @(posedge clk) begin
        if (started && !done) begin
            cycles = cycles + 1;
            if (resetn && uv && locked && !lockout) begin
                g = g + 1;
                if (code != SECRET) fails_local = fails_local + 1;
            end
        end
    end
endmodule

module tb_lock_v2;
    reg clk = 0;
    always #5 clk = ~clk;

    localparam integer MF = 3, LO = 50, BD = 20;
    localparam [31:0] SECRET = 32'hA5C31F7E;
    localparam [31:0] V1_DEFAULT = 32'hDEC0DED1;

    integer errors = 0;
    task check(input cond, input [2047:0] msg);
        begin
            if (!cond) begin $display("FAIL: %0s", msg); errors = errors + 1; end
            else       $display("PASS: %0s", msg);
        end
    endtask

    // ---------------- main DUT (soft lockout) ----------------
    reg resetn = 0, uv = 0, sv = 1, rl = 0; reg [31:0] code = 0;
    wire locked, lockout;
    scan_lock_controller_v2 #(.MAX_FAILS(MF), .LOCKOUT_CYCLES(LO), .BOOT_DELAY_CYCLES(BD), .HARD_LOCKOUT(1'b0)) d (
        .clk(clk), .resetn(resetn), .unlock_valid(uv), .unlock_code_i(code),
        .secret_i(SECRET), .secret_valid_i(sv), .relock(rl), .locked(locked), .lockout_o(lockout));

    // ---------------- HARD lockout DUT ----------------
    reg h_resetn = 0, h_uv = 0; reg [31:0] h_code = 0;
    wire h_locked, h_lockout;
    scan_lock_controller_v2 #(.MAX_FAILS(MF), .LOCKOUT_CYCLES(LO), .BOOT_DELAY_CYCLES(BD), .HARD_LOCKOUT(1'b1)) dh (
        .clk(clk), .resetn(h_resetn), .unlock_valid(h_uv), .unlock_code_i(h_code),
        .secret_i(SECRET), .secret_valid_i(1'b1), .relock(1'b0), .locked(h_locked), .lockout_o(h_lockout));

    // ---------------- attacker-cost helpers ----------------
    wire a1_done, a2_done, r1_done, r2_done, r3_done;
    wire [31:0] a1_cyc, a1_ev, a2_cyc, a2_ev, r1_cyc, r1_rs, r2_cyc, r2_rs, r3_cyc;
    atk_cost #(.MF(3), .LO(1000), .BD(1000), .SECRET(32'd40))  a1 (.clk(clk), .done(a1_done), .cycles(a1_cyc), .evals(a1_ev));
    atk_cost #(.MF(5), .LO(200),  .BD(300),  .SECRET(32'd123)) a2 (.clk(clk), .done(a2_done), .cycles(a2_cyc), .evals(a2_ev));
    atk_cost_rst #(.MF(3), .LO(1000), .BD(1000), .RST_CYCLES(2), .SECRET(32'd40)) r1 (.clk(clk), .done(r1_done), .cycles(r1_cyc), .resets(r1_rs));
    atk_cost_rst #(.MF(3), .LO(1000), .BD(100),  .RST_CYCLES(2), .SECRET(32'd40)) r2 (.clk(clk), .done(r2_done), .cycles(r2_cyc), .resets(r2_rs));
    atk_cost #(.MF(3), .LO(1000), .BD(100), .SECRET(32'd40)) a3 (.clk(clk), .done(r3_done), .cycles(r3_cyc), .evals());

    // ---------------- helpers ----------------
    task do_reset;
        begin
            @(negedge clk); resetn = 0; uv = 0; rl = 0; sv = 1;
            repeat (3) @(negedge clk);
            resetn = 1;               // released at a negedge; next posedge is edge index 0
        end
    endtask

    // present one attempt on the next posedge, then sample at the following negedge
    task attempt(input [31:0] c);
        begin uv = 1; code = c; @(negedge clk); uv = 0; end
    endtask
    task idle(input integer n);
        begin uv = 0; repeat (n) @(negedge clk); end
    endtask

    integer k, first_ok, ign_count;
    reg any_unlock;

    initial begin
        // ------------------------------------------------------------------
        $display("=== T1: fail-safe out of reset ===");
        do_reset;
        // reset already released; sample right after release edge would be too late, so
        // re-check during reset:
        @(negedge clk); resetn = 0; @(negedge clk); @(negedge clk);
        check(locked === 1'b1, "T1 locked=1 while in reset");
        check(lockout === 1'b1, "T1 lockout_o=1 while in reset (boot delay armed)");
        resetn = 1;

        // ------------------------------------------------------------------
        $display("=== T2: boot delay -- correct code every cycle, find first accepted edge ===");
        do_reset;
        first_ok = -1;
        uv = 1; code = SECRET;
        for (k = 0; k < BD + 10; k = k + 1) begin
            @(negedge clk);          // edge k has occurred
            if (!locked && first_ok < 0) first_ok = k;
        end
        uv = 0;
        $display("  first accepted edge index = %0d (BOOT_DELAY_CYCLES=%0d)", first_ok, BD);
        check(first_ok === BD, "T2 first BD edges ignore the correct code; edge index BD is the first evaluated");

        // ------------------------------------------------------------------
        $display("=== T3: v1 public default code rejected ===");
        do_reset; idle(BD + 2);
        attempt(V1_DEFAULT); idle(1);
        check(locked === 1'b1, "T3 DEC0DED1 rejected by v2 (no public default)");

        $display("=== T4: secret_valid_i=0 blocks the right code ===");
        do_reset; idle(BD + 2); sv = 0;
        attempt(SECRET); idle(1);
        check(locked === 1'b1, "T4 correct code with secret_valid_i=0 does not unlock");
        sv = 1;

        // ------------------------------------------------------------------
        $display("=== T5: lockout timing, ignored attempts not counted, no extension ===");
        do_reset; idle(BD + 2);
        attempt(32'h1); attempt(32'h2);
        check(lockout === 1'b0, "T5 lockout not active after MAX_FAILS-1 wrong codes");
        attempt(32'h3);                       // 3rd wrong -> lockout starts
        check(lockout === 1'b1 && locked === 1'b1, "T5 lockout active right after MAX_FAILS-th wrong code");
        // hammer wrong codes for 30 edges of the lockout, then present the correct code every edge
        for (k = 0; k < 30; k = k + 1) attempt(32'hDEAD0000 + k);
        first_ok = -1; uv = 1; code = SECRET;
        for (k = 0; k < LO + 10; k = k + 1) begin
            @(negedge clk);
            if (!locked && first_ok < 0) first_ok = k;
        end
        uv = 0;
        // 30 hammer edges consumed part of the lockout: first_ok counted from after them
        $display("  correct code accepted %0d edges after 30 hammer edges; expected LO-30=%0d", first_ok, LO - 30);
        check(first_ok === LO - 30, "T5 hammering during lockout neither extends it nor counts: unlock at exactly LO edges after lockout start");

        // ignored attempts must not count: after expiry, MAX_FAILS-1 wrong codes must NOT re-lock out
        do_reset; idle(BD + 2);
        attempt(32'h1); attempt(32'h2); attempt(32'h3);            // lockout
        for (k = 0; k < LO; k = k + 1) attempt(32'hBAD00000 + k); // exactly LO edges, all ignored
        // lockout has just expired; fail counter should be 0 (cleared at trigger, ignored attempts uncounted)
        attempt(32'h11); attempt(32'h12);
        check(lockout === 1'b0, "T5 after expiry, 2 wrong codes do not immediately re-lock out (ignored attempts were not counted)");
        attempt(32'h13);
        check(lockout === 1'b1, "T5 third wrong code after expiry starts a new lockout");

        // ------------------------------------------------------------------
        $display("=== T6: success clears fail counter ===");
        do_reset; idle(BD + 2);
        attempt(32'h1); attempt(32'h2);
        attempt(SECRET); idle(1);
        check(locked === 1'b0, "T6 correct code after 2 wrong codes unlocks");
        rl = 1; @(negedge clk); rl = 0; @(negedge clk);
        check(locked === 1'b1, "T6 relock works");
        attempt(32'h5); attempt(32'h6);
        check(lockout === 1'b0, "T6 counter was cleared by the success: 2 more wrong codes do not lock out");
        attempt(32'h7);
        check(lockout === 1'b1, "T6 third wrong code after success locks out");

        // ------------------------------------------------------------------
        $display("=== T7: wrong codes while unlocked trigger nothing ===");
        do_reset; idle(BD + 2);
        attempt(SECRET); idle(1);
        check(locked === 1'b0, "T7 unlocked");
        for (k = 0; k < 10; k = k + 1) attempt(32'h77000000 + k);
        check(locked === 1'b0 && lockout === 1'b0, "T7 10 wrong codes while unlocked: still unlocked, no lockout");

        // ------------------------------------------------------------------
        $display("=== T8: relock beats simultaneous correct unlock ===");
        do_reset; idle(BD + 2);
        rl = 1; uv = 1; code = SECRET; @(negedge clk); rl = 0; uv = 0; @(negedge clk);
        check(locked === 1'b1, "T8 relock + correct code on the same edge: stays locked");

        // ------------------------------------------------------------------
        $display("=== T9: reset while unlocked re-locks ===");
        do_reset; idle(BD + 2);
        attempt(SECRET); idle(1);
        check(locked === 1'b0, "T9 unlocked before reset");
        resetn = 0; @(negedge clk); @(negedge clk);
        check(locked === 1'b1, "T9 reset re-locks (fail-safe)");
        resetn = 1;

        // ------------------------------------------------------------------
        $display("=== T10: HARD_LOCKOUT ===");
        @(negedge clk); h_resetn = 0; repeat (3) @(negedge clk); h_resetn = 1;
        repeat (BD + 2) @(negedge clk);
        h_uv = 1; h_code = 32'h1; @(negedge clk); h_code = 32'h2; @(negedge clk); h_code = 32'h3; @(negedge clk);
        h_code = SECRET; any_unlock = 0;
        for (k = 0; k < 500; k = k + 1) begin @(negedge clk); if (!h_locked) any_unlock = 1; end
        h_uv = 0;
        check(h_lockout === 1'b1 && any_unlock === 1'b0, "T10 HARD: correct code rejected for 500 cycles after lockout (permanent until reset)");
        h_resetn = 0; repeat (3) @(negedge clk); h_resetn = 1;
        repeat (BD + 2) @(negedge clk);
        h_uv = 1; h_code = SECRET; @(negedge clk); h_uv = 0; @(negedge clk);
        check(h_locked === 1'b0, "T10 HARD: reset clears the hard lockout; correct code then unlocks");

        // ------------------------------------------------------------------
        $display("=== T11: measured attacker cost vs closed-form BD+(N+1)+floor(N/MF)*LO ===");
        wait (a1_done && a2_done && r1_done && r2_done && r3_done);
        $display("  cfg1 MF=3 LO=BD=1000 secret=40 : measured %0d cycles (%0d evaluated guesses), formula %0d", a1_cyc, a1_ev, 1000 + 41 + (40/3)*1000);
        check(a1_cyc === 1000 + 41 + (40/3)*1000, "T11 cfg1 attacker cost equals formula exactly");
        $display("  cfg2 MF=5 LO=200 BD=300 secret=123 : measured %0d cycles (%0d evaluated), formula %0d", a2_cyc, a2_ev, 300 + 124 + (123/5)*200);
        check(a2_cyc === 300 + 124 + (123/5)*200, "T11 cfg2 attacker cost equals formula exactly");
        $display("  reset-cycling, BD=LO=1000: %0d cycles with %0d resets  (waiting attacker: %0d)", r1_cyc, r1_rs, a1_cyc);
        check(r1_cyc >= a1_cyc, "T11 reset-cycling is not cheaper than waiting when BOOT_DELAY >= LOCKOUT");
        $display("  reset-cycling, BD=100<LO=1000: %0d cycles with %0d resets  (waiting attacker: %0d)", r2_cyc, r2_rs, r3_cyc);
        check(r2_cyc < r3_cyc, "T11 negative control: with BOOT_DELAY < LOCKOUT reset-cycling IS cheaper (why the rule exists)");

        $display("================================================================");
        if (errors == 0) $display("TESTBENCH: ALL TESTS PASSED");
        else             $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $finish;
    end

    initial begin #50000000; $display("RESULT: GLOBAL TIMEOUT"); $finish; end
endmodule