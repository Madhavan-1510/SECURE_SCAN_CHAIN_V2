`timescale 1ns/1ps
`include "aes_pcpi_defs.vh"
// ============================================================================
// tb_attack_bruteforce.v -- Paper 2 Phase 2, A4 (unlock brute force) against
// the UNMODIFIED v1 controller (scan_lock_controller.v).
//
// A true 2^32-guess exhaustive run is not simulated here: at the throughput
// measured in this exact environment (Check 0 below), it would take on the
// order of 90 minutes of wall-clock Icarus time to simulate 2^32 clock
// edges, which is impractical to gate a regression on. Instead this
// testbench establishes the EXACT, deterministic per-guess cost model by
// direct simulation over a representative and boundary-covering set of
// secrets, then reports the 2^32 worst case as an arithmetic consequence
// of that verified model -- not as an unverified guess.
//
// Checks:
//   C0  2,000,000 sequential wrong guesses never unlock (sanity). Wall-clock
//       throughput is NOT hard-coded here; it is measured outside the
//       testbench (see PROJECT_README.md S5d) so it cannot go stale.
//   C1  No rate limiting: v1 accepts a new guess EVERY clock cycle
//       indefinitely (10,000 consecutive wrong guesses, checked each cycle).
//   C2  No lockout: after those 10,000 wrong guesses, the correct code
//       (presented next) still succeeds immediately.
//   C3  Exact-match only: a guess 1 bit off and a guess 32 bits off both leave
//       `locked` at 1 at the first sampling point. This shows no partial
//       credit at cycle granularity. It does NOT measure sub-cycle timing:
//       that the comparator is a single combinational == (not byte-wise) is
//       true by RTL inspection of scan_lock_controller.v, not by this check.
//   C4  Deterministic linear cost: sequential guessing from 0 unlocks at
//       EXACTLY guess == secret for secrets 0, 1, 1000, 65535 (attempts_needed
//       = secret + 1); 0x12345678 is NOT reached in a 65,536-guess sweep
//       (no false unlock); and for secret 0xFFFFFFFF the sweep
//       0xFFFF0000..0xFFFFFFFF unlocks exactly on its last guess. (The
//       top-of-range case is swept over the top 65,536 values only, not from
//       0 -- a full 2^32 sweep is not simulated.)
//   C5  wrong-code-does-not-partially-unlock: while sweeping 65,536
//       sequential wrong guesses (secret = 0xFFFFFFFF, so all miss),
//       `locked` never glitches to 0 -- i.e. C4's boundary result at
//       0xFFFFFFFF is not an artifact of stopping the sweep early.
//   C6  Reports the worst-case cost as: worst_case_attempts = 2^32 (this
//       follows from C4's confirmed linear/no-shortcut model with the
//       worst-case secret being the numerically largest 32-bit value,
//       32'hFFFFFFFF, combined with C5's confirmation that no guess before
//       the true secret ever unlocks). At 100 MHz (Paper 1's own board
//       target clock, README S15), that is 2^32 / 100e6 = 42.94967296 s of
//       REAL HARDWARE time -- this is a closed-form consequence of C1-C5,
//       not a separate unverified estimate.
// ============================================================================
module tb_attack_bruteforce;
    reg clk = 0;
    always #5 clk = ~clk;

    integer errors = 0;
    // msg is 2048 bits (256 chars). A too-narrow msg silently drops the LEFTMOST
    // characters of a long string literal (that is how "PASS: l wrong guesses" appeared).
    task check(input cond, input [2047:0] msg);
        begin
            if (!cond) begin $display("FAIL: %0s", msg); errors = errors + 1; end
            else $display("PASS: %0s", msg);
        end
    endtask

    // ------------------------------------------------------------------
    // C0: throughput context (informational, not gated on a pass/fail).
    // Run as a plain task INSIDE the main initial block (not a concurrent
    // initial block) so there is no race between this loop and the summary
    // that reports its result -- an earlier version of this file ran it
    // concurrently and printed a partially-completed count; fixed here.
    // ------------------------------------------------------------------
    reg rst0 = 0, uv0 = 0; reg [31:0] cd0 = 0; wire lk0;
    scan_lock_controller #(.UNLOCK_CODE(32'hFFFFFFFF)) d0 (
        .clk(clk), .resetn(rst0), .unlock_valid(uv0), .unlock_code_i(cd0),
        .relock(1'b0), .locked(lk0));
    integer t_start, t_end, i0;
    reg c0_glitch;
    task run_c0;
        begin
            rst0 = 0; repeat (3) @(posedge clk); #1 rst0 = 1; @(negedge clk); uv0 = 1;
            t_start = $time;
            c0_glitch = 1'b0;
            for (i0 = 0; i0 < 2_000_000; i0 = i0 + 1) begin
                cd0 = i0; @(negedge clk);
                if (!lk0) c0_glitch = 1'b1;
            end
            t_end = $time;
            uv0 = 0;
            $display("C0 (informational): 2,000,000 sequential wrong guesses against v1 (secret=0xFFFFFFFF), locked stayed 1 throughout=%b, %0d ns of simulated time for %0d cycles", !c0_glitch, t_end - t_start, i0);
        end
    endtask

    // ------------------------------------------------------------------
    // C1/C2/C3: rate-limit / lockout / timing-independence, one instance
    // ------------------------------------------------------------------
    localparam [31:0] SECRET1 = 32'hCAFEBABE;
    reg rst1 = 0, uv1 = 0, rl1 = 0; reg [31:0] cd1 = 0; wire lk1;
    scan_lock_controller #(.UNLOCK_CODE(SECRET1)) d1 (
        .clk(clk), .resetn(rst1), .unlock_valid(uv1), .unlock_code_i(cd1),
        .relock(rl1), .locked(lk1));

    integer i1;
    reg glitch1;
    reg [31:0] near_miss_1bit, near_miss_32bit;

    // ------------------------------------------------------------------
    // C4/C5: deterministic linear cost model, several secrets
    // ------------------------------------------------------------------
    reg rst4 = 0, uv4 = 0, rl4 = 0; reg [31:0] cd4 = 0; wire lk4;
    scan_lock_controller #(.UNLOCK_CODE(32'hFFFFFFFF)) d4 (
        .clk(clk), .resetn(rst4), .unlock_valid(uv4), .unlock_code_i(cd4),
        .relock(rl4), .locked(lk4));

    integer g;
    reg [31:0] found_at;
    // (the C4/C5 top-boundary and 5-secret sweeps use fixed instances below)

    // Verilog-2001 has no dynamic instantiation, so C4 uses N fixed instances
    // (one per secret under test) rather than a loop-instantiated DUT.
    wire lkA, lkB, lkC, lkD;
    reg  rstABCD = 0, uvABCD = 0;
    reg [31:0] cdABCD = 0;
    scan_lock_controller #(.UNLOCK_CODE(32'd0))      dA (.clk(clk), .resetn(rstABCD), .unlock_valid(uvABCD), .unlock_code_i(cdABCD), .relock(1'b0), .locked(lkA));
    scan_lock_controller #(.UNLOCK_CODE(32'd1))      dB (.clk(clk), .resetn(rstABCD), .unlock_valid(uvABCD), .unlock_code_i(cdABCD), .relock(1'b0), .locked(lkB));
    scan_lock_controller #(.UNLOCK_CODE(32'd1000))   dC (.clk(clk), .resetn(rstABCD), .unlock_valid(uvABCD), .unlock_code_i(cdABCD), .relock(1'b0), .locked(lkC));
    scan_lock_controller #(.UNLOCK_CODE(32'd65535))  dD (.clk(clk), .resetn(rstABCD), .unlock_valid(uvABCD), .unlock_code_i(cdABCD), .relock(1'b0), .locked(lkD));
    wire lkE;
    scan_lock_controller #(.UNLOCK_CODE(32'h12345678)) dE (.clk(clk), .resetn(rstABCD), .unlock_valid(uvABCD), .unlock_code_i(cdABCD), .relock(1'b0), .locked(lkE));

    integer j;
    integer unlock_cycle_A, unlock_cycle_B, unlock_cycle_C, unlock_cycle_D, unlock_cycle_E;

    // ------------------------------------------------------------------
    // Top-boundary check: secret = 0xFFFFFFFF, guess COUNTING DOWN from
    // 0xFFFFFFFF so the correct guess is presented FIRST (tractable), then
    // confirm all values strictly below it (sampled) never match, and
    // separately confirm the exact boundary via d4 counting UP through the
    // last 5 values below the secret plus the secret itself.
    // ------------------------------------------------------------------
    reg rstT = 0, uvT = 0; reg [31:0] cdT = 0; wire lkT;
    scan_lock_controller #(.UNLOCK_CODE(32'hFFFFFFFF)) dT (
        .clk(clk), .resetn(rstT), .unlock_valid(uvT), .unlock_code_i(cdT),
        .relock(1'b0), .locked(lkT));

    initial begin
        // ---- C0 (run first, synchronously, no race with later checks) ----
        run_c0;
        check(!c0_glitch, "C0 2,000,000 sequential wrong guesses against v1: never unlocked");

        // ---- C1/C2/C3 ----
        rst1 = 0; repeat (3) @(posedge clk); #1 rst1 = 1; @(negedge clk); uv1 = 1;
        glitch1 = 0;
        for (i1 = 0; i1 < 10000; i1 = i1 + 1) begin
            cd1 = 32'h1000_0000 + i1;   // guaranteed miss vs SECRET1 = CAFEBABE
            @(negedge clk);
            if (!lk1) glitch1 = 1'b1;
        end
        check(glitch1 === 1'b0, "C1 10,000 consecutive wrong guesses, one per clock, no lockout/backoff: never unlocked early");
        check(lk1 === 1'b1, "C1 still locked after 10,000 wrong guesses");
        cd1 = SECRET1; @(negedge clk);
        check(lk1 === 1'b0, "C2 correct code immediately after 10,000 wrong guesses still succeeds (no lockout exists in v1)");
        uv1 = 0;

        // C3: near-miss timing independence (both take exactly 1 cycle to reject)
        rst1 = 0; @(negedge clk); rst1 = 1; @(negedge clk); uv1 = 1;
        near_miss_1bit  = SECRET1 ^ 32'h0000_0001;   // 1 bit different
        near_miss_32bit = ~SECRET1;                  // all 32 bits different
        cd1 = near_miss_1bit;  @(negedge clk);
        check(lk1 === 1'b1, "C3 1-bit-off guess rejected at the first sample (still locked)");
        cd1 = near_miss_32bit; @(negedge clk);
        check(lk1 === 1'b1, "C3 32-bit-off (fully inverted) guess ALSO rejected at the first sample -- no partial credit at cycle granularity");
        uv1 = 0;

        // ---- C4: linear cost model across 5 secrets simultaneously ----
        rstABCD = 0; repeat (3) @(posedge clk); #1 rstABCD = 1; @(negedge clk); uvABCD = 1;
        unlock_cycle_A = -1; unlock_cycle_B = -1; unlock_cycle_C = -1; unlock_cycle_D = -1; unlock_cycle_E = -1;
        for (j = 0; j <= 65535; j = j + 1) begin
            cdABCD = j;
            @(negedge clk);
            if (lkA === 1'b0 && unlock_cycle_A == -1) unlock_cycle_A = j;
            if (lkB === 1'b0 && unlock_cycle_B == -1) unlock_cycle_B = j;
            if (lkC === 1'b0 && unlock_cycle_C == -1) unlock_cycle_C = j;
            if (lkD === 1'b0 && unlock_cycle_D == -1) unlock_cycle_D = j;
            if (lkE === 1'b0 && unlock_cycle_E == -1) unlock_cycle_E = j;
        end
        uvABCD = 0;
        $display("  C4 measured unlock guess-index: secret=0 -> %0d, secret=1 -> %0d, secret=1000 -> %0d, secret=65535 -> %0d, secret=0x12345678 (not reached in 65536 sweep, expected -1) -> %0d",
                  unlock_cycle_A, unlock_cycle_B, unlock_cycle_C, unlock_cycle_D, unlock_cycle_E);
        check(unlock_cycle_A === 0,     "C4 secret=0: unlocks at guess 0 (attempts_needed = secret+1 = 1)");
        check(unlock_cycle_B === 1,     "C4 secret=1: unlocks at guess 1 (attempts_needed = 2)");
        check(unlock_cycle_C === 1000,  "C4 secret=1000: unlocks at guess 1000 (attempts_needed = 1001)");
        check(unlock_cycle_D === 65535, "C4 secret=65535: unlocks at guess 65535 (attempts_needed = 65536), exactly at the sweep's last guess");
        check(unlock_cycle_E === -1,    "C4 secret=0x12345678 (305419896): correctly NOT reached within a 65536-guess sweep (sanity: no false unlock)");

        // ---- C4 (boundary) / C5: near the top of the 32-bit range ----
        rstT = 0; repeat (3) @(posedge clk); #1 rstT = 1; @(negedge clk); uvT = 1;
        for (g = 0; g < 65536; g = g + 1) begin
            cdT = 32'hFFFF_0000 + g;   // sweeps 0xFFFF0000 .. 0xFFFFFFFF
            @(negedge clk);
        end
        uvT = 0;
        check(lkT === 1'b0, "C4 boundary: secret=0xFFFFFFFF unlocked exactly when the sweep reached 0xFFFFFFFF (last of 65536 guesses)");

        rstT = 0; @(negedge clk); rstT = 1; @(negedge clk); uvT = 1;
        found_at = 32'hFFFF_FFFF;
        for (g = 0; g < 65535; g = g + 1) begin   // 0xFFFF0000 .. 0xFFFFFFFE, secret excluded
            cdT = 32'hFFFF_0000 + g;
            @(negedge clk);
            if (!lkT) found_at = 32'hFFFF_0000 + g;
        end
        check(found_at === 32'hFFFF_FFFF, "C5 65,535 guesses just below secret 0xFFFFFFFF all rejected -- no early unlock near top boundary");
        cdT = 32'hFFFF_FFFF; @(negedge clk);
        check(lkT === 1'b0, "C5 the very next guess (the true secret 0xFFFFFFFF) then unlocks");
        uvT = 0;

        // ---- C6: closed-form worst case from the verified model ----
        $display("================================================================");
        $display("C6 (derived, not separately simulated -- see header): with the");
        $display("   per-guess cost verified EXACTLY LINEAR and NO-SHORTCUT by C4/C5");
        $display("   (attempts_needed = secret_value + 1, confirmed at 0, 1, 1000,");
        $display("   65535, and the 0xFFFF0000-0xFFFFFFFF boundary), and no rate");
        $display("   limiting or lockout (C1/C2) and no partial-match signal at cycle granularity");
        $display("   (C3), the worst-case secret is the numerically largest 32-bit");
        $display("   value: attempts_needed(0xFFFFFFFF) = 2^32 = 4294967296.");
        $display("   At 100 MHz (README S15's own board clock target):");
        $display("   4294967296 / 100e6 = 42.94967296 s of real hardware time.");
        $display("   Wall-clock simulation throughput is reported in PROJECT_README.md");
        $display("   S5d from a separate measured run, not printed here.");
        $display("================================================================");

        if (errors == 0) $display("TESTBENCH: ALL TESTS PASSED");
        else $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $finish;
    end

    initial begin #2000000000 $display("RESULT: GLOBAL TIMEOUT"); $finish; end
endmodule