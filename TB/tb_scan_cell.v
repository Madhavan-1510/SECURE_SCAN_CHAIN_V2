// ============================================================================
// tb_scan_cell.v
//
// Objective: verify scan_cell.v in isolation.
//   1. Functional mode (scan_en=0): q follows d, one cycle of latency.
//   2. Scan mode (scan_en=1): q follows scan_in, NOT d -- proves scan mode
//      truly overrides functional update, not just "also" applies it.
//   3. Mode switching mid-stream: functional value is correctly captured,
//      then scan shifts a different, unrelated pattern through without
//      corrupting neighboring behavior.
//   4. Reset dominates both modes.
// ============================================================================
`timescale 1ns/1ps

module tb_scan_cell;

    reg  clk = 0;
    reg  resetn;
    reg  scan_en;
    reg  scan_in;
    reg  d;
    wire q, scan_out;

    scan_cell #(.RESET_VALUE(1'b0)) dut (
        .clk(clk), .resetn(resetn),
        .scan_en(scan_en), .scan_in(scan_in),
        .d(d), .q(q), .scan_out(scan_out)
    );

    always #5 clk = ~clk;

    integer errors = 0;

    task check(input cond, input [255:0] msg);
        begin
            if (!cond) begin
                $display("FAIL: %0s", msg);
                errors = errors + 1;
            end else begin
                $display("PASS: %0s", msg);
            end
        end
    endtask

    initial begin
        resetn = 0; scan_en = 0; scan_in = 0; d = 0;
        repeat (2) @(posedge clk);
        #1 check(q === 1'b0, "reset drives q to RESET_VALUE (0)");

        // ---- Check 1: functional mode follows d ----
        #1 resetn = 1;
        @(posedge clk); #1 d = 1'b1;
        @(posedge clk); #1;
        check(q === 1'b1, "functional mode: q follows d (0->1)");

        @(posedge clk); #1 d = 1'b0;
        @(posedge clk); #1;
        check(q === 1'b0, "functional mode: q follows d (1->0)");

        // ---- Check 2: scan mode overrides d ----
        @(posedge clk); #1;
        d = 1'b0;         // functional input says "stay 0"
        scan_in = 1'b1;   // scan input says "become 1"
        scan_en = 1'b1;
        @(posedge clk); #1;
        check(q === 1'b1, "scan mode: q follows scan_in even though d=0 (override proven)");
        check(scan_out === 1'b1, "scan_out mirrors q");

        // shift a second bit through
        scan_in = 1'b0;
        @(posedge clk); #1;
        check(q === 1'b0, "scan mode: second shifted bit correctly captured");

        // ---- Check 3: return to functional mode, previous scanned value is q's new base ----
        scan_en = 1'b0;
        d = 1'b1;
        @(posedge clk); #1;
        check(q === 1'b1, "functional mode resumes cleanly after scan mode ends");

        // ---- Check 4: reset dominates scan mode too ----
        scan_en = 1'b1;
        scan_in = 1'b1;
        resetn = 1'b0;
        @(posedge clk); #1;
        check(q === 1'b0, "reset overrides scan mode (q forced to RESET_VALUE)");

        if (errors == 0)
            $display("TESTBENCH: ALL TESTS PASSED");
        else
            $display("TESTBENCH: %0d TEST(S) FAILED", errors);

        $finish;
    end

endmodule
