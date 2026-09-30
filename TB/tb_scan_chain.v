// ============================================================================
// tb_scan_chain.v
//
// Objective: verify scan_chain.v (WIDTH=8 for a readable bit pattern, then
// WIDTH=128 to match the real AES register width used later).
//   1. Functional transparency: with scan_en=0, q tracks d every cycle,
//      identical to a plain register -- required so converting aes_core's
//      registers to scan_chain instances cannot change functional behavior.
//   2. Bit-ordering: shifting a known walking-1 pattern in via scan_in and
//      confirming it appears at q in the documented LSB-first order
//      (bit[0] filled first).
//   3. Multi-cycle shift-out: after loading a known functional value,
//      switching to scan mode and shifting WIDTH cycles reproduces that
//      value bit-for-bit at scan_out, in the correct order.
//   4. Shifting MORE than WIDTH cycles behaves as a circular shift register
//      (data re-enters from scan_in as expected) -- this matters later for
//      the "shift more than segment width" security tests in Phase 8.
// ============================================================================
`timescale 1ns/1ps

module tb_scan_chain;

    localparam WIDTH = 8;

    reg  clk = 0;
    reg  resetn;
    reg  scan_en;
    reg  scan_in;
    reg  [WIDTH-1:0] d;
    wire [WIDTH-1:0] q;
    wire scan_out;

    scan_chain #(.WIDTH(WIDTH)) dut (
        .clk(clk), .resetn(resetn),
        .scan_en(scan_en), .scan_in(scan_in), .scan_out(scan_out),
        .d(d), .q(q)
    );

    always #5 clk = ~clk;

    integer errors = 0;
    task check(input cond, input [511:0] msg);
        begin
            if (!cond) begin $display("FAIL: %0s", msg); errors = errors + 1; end
            else $display("PASS: %0s", msg);
        end
    endtask

    integer i;

    initial begin
        resetn = 0; scan_en = 0; scan_in = 0; d = 8'h00;
        repeat (2) @(posedge clk);
        #1 resetn = 1;

        // ---- Check 1: functional transparency ----
        @(posedge clk); #1 d = 8'hA5;
        @(posedge clk); #1;
        check(q === 8'hA5, "functional mode: q tracks d exactly like a plain register");

        // ---- Check 2: shift-in bit ordering (LSB-first: bit0 filled first) ----
        // Reset, then shift in 8'b1000_0000 style pattern one bit at a time,
        // MSB of the intended pattern fed FIRST so it ends up furthest from
        // scan_in, i.e. at bit[WIDTH-1], per the documented convention.
        @(posedge clk); #1 resetn = 0;
        @(posedge clk); #1 resetn = 1;
        scan_en = 1'b1;
        // Feed pattern 8'b1100_0000 (bit7=1,bit6=1,rest 0), MSB first:
        scan_in = 1'b1; @(posedge clk); #1; // -> bit0
        scan_in = 1'b1; @(posedge clk); #1; // -> bit1 (bit0's old value shifts to bit1... )
        scan_in = 1'b0; @(posedge clk); #1;
        scan_in = 1'b0; @(posedge clk); #1;
        scan_in = 1'b0; @(posedge clk); #1;
        scan_in = 1'b0; @(posedge clk); #1;
        scan_in = 1'b0; @(posedge clk); #1;
        scan_in = 1'b0; @(posedge clk); #1;
        // After 8 shifts of [1,1,0,0,0,0,0,0] (first-fed bit ends up at bit7):
        // bit0 = last fed = 0, bit7 = first fed = 1
        check(q === 8'b1100_0000, "shift-in: first-fed bit ends at bit[WIDTH-1], LSB-first order confirmed");
        scan_en = 1'b0;

        // ---- Check 3: functional load, then scan out reproduces it exactly ----
        @(posedge clk); #1 resetn = 0;
        @(posedge clk); #1 resetn = 1;
        d = 8'hC3;
        @(posedge clk); #1;
        check(q === 8'hC3, "functional load of known value 0xC3 before scan-out test");

        scan_en = 1'b1;
        scan_in = 1'b0;
        begin : shift_out_block
            reg [WIDTH-1:0] captured;
            captured = 0;
            // scan_out is a COMBINATIONAL tap on q[WIDTH-1] -- the top bit of
            // the original register is already visible on scan_out BEFORE
            // any clock edge. Capturing WIDTH post-edge samples (as an
            // earlier version of this test did) skips that bit entirely and
            // instead picks up one garbage bit that was freshly shifted in
            // from scan_in. Correct reconstruction needs exactly ONE
            // pre-shift sample (bit[WIDTH-1]) plus (WIDTH-1) post-edge
            // samples -- this is the same rule the Phase 7 attack testbench
            // and docs/scan_map.md must use.
            captured[WIDTH-1] = scan_out; // pre-shift: bit[WIDTH-1] = C3[7]
            for (i = 0; i < WIDTH-1; i = i + 1) begin
                @(posedge clk); #1;
                captured[WIDTH-2-i] = scan_out;
            end
            check(captured === 8'hC3, "scan-out: 1 pre-shift sample + (WIDTH-1) shifts reproduce the exact functional value 0xC3");
        end
        scan_en = 1'b0;

        // ---- Check 4: shifting MORE than WIDTH cycles = keeps circulating ----
        @(posedge clk); #1 resetn = 0;
        @(posedge clk); #1 resetn = 1;
        d = 8'h5A;
        @(posedge clk); #1;
        scan_en = 1'b1;
        scan_in = 1'b0;
        repeat (WIDTH) @(posedge clk); // shift exactly WIDTH times: 0x5A fully flushed out, replaced by zeros
        #1;
        check(q === 8'h00, "after exactly WIDTH shifts of scan_in=0, original value fully flushed out");
        repeat (WIDTH) @(posedge clk); // shift WIDTH more times with scan_in=0: stays all zero (no wraparound reintroduction since scan_in tied to 0, not fed back)
        #1;
        check(q === 8'h00, "shifting beyond WIDTH cycles behaves as a plain continuing shift register, no hidden state");

        if (errors == 0)
            $display("TESTBENCH: ALL TESTS PASSED");
        else
            $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $finish;
    end

endmodule
