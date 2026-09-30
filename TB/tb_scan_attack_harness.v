`timescale 1ns/1ps

module tb_scan_attack_harness;

    reg clk = 0;
    reg resetn = 0;
    reg lock_resetn = 0;
    reg btn_start = 0;
    reg sw_unlock = 0;
    reg [6:0] sel_byte = 0;
    wire [7:0] led_out;
    wire led_done, led_locked;

    localparam [127:0] KEY = 128'h000102030405060708090A0B0C0D0E0F;

    scan_attack_harness dut (
        .clk(clk), .resetn(resetn), .lock_resetn(lock_resetn),
        .btn_start(btn_start), .sw_unlock(sw_unlock),
        .sel_byte(sel_byte), .led_out(led_out),
        .led_done(led_done), .led_locked(led_locked)
    );

    always #5 clk = ~clk;
    integer errors = 0;

    task read_key_bytes(output [127:0] key_out);
        integer b;
        begin
            for (b = 0; b < 16; b = b + 1) begin
                sel_byte = b;   // bytes 0..15 = captured[644:517], key_reg
                #1;
                key_out[127-8*b -: 8] = led_out;
            end
        end
    endtask

    reg [127:0] recovered;

    initial begin
        resetn = 0; lock_resetn = 0;
        repeat (3) @(posedge clk);
        #1 resetn = 1; lock_resetn = 1;
        @(posedge clk);

        // ---- Case 1: locked (fail-safe default), sw_unlock=0 ----
        sw_unlock = 0;
        // NOTE (same-edge race fix): btn_start must change away from the
        // exact posedge the DUT's synchronous FSM samples on, or the new
        // value can race the DUT's own posedge-triggered always block and
        // never be seen (confirmed by direct reproduction: the original
        // `@(posedge clk); btn_start = 1;` pattern left the harness FSM
        // stuck in S_IDLE forever, causing this test to hit the global
        // timeout). Asserting/deasserting on @(negedge clk) instead holds
        // btn_start=1 across a full, unambiguous posedge with no race.
        @(negedge clk); btn_start = 1;
        @(negedge clk); btn_start = 0;
        wait (led_done == 1'b1);
        @(posedge clk); #1;

        if (led_locked !== 1'b1) begin
            $display("FAIL: harness did not show locked=1 in default case");
            errors = errors + 1;
        end
        read_key_bytes(recovered);
        $display("LOCKED case: captured key window = %032h (expect all-zero)", recovered);
        if (recovered === {128{1'b0}}) begin
            $display("PASS: harness reproduces LOCKED defense result (key not recoverable)");
        end else begin
            $display("FAIL: harness shows key recoverable while locked!");
            errors = errors + 1;
        end

        // ---- Case 2: unlocked, sw_unlock=1 ----
        sw_unlock = 1;
        @(negedge clk); btn_start = 1;
        @(negedge clk); btn_start = 0;
        wait (led_done == 1'b1);
        @(posedge clk); #1;

        if (led_locked !== 1'b0) begin
            $display("FAIL: harness did not show locked=0 after unlock");
            errors = errors + 1;
        end
        read_key_bytes(recovered);
        $display("UNLOCKED case: captured key window = %032h (expect real KEY)", recovered);
        if (recovered === KEY) begin
            $display("PASS: harness reproduces UNLOCKED baseline result (key recoverable, matches KAT key)");
        end else begin
            $display("FAIL: harness did not recover the real key while unlocked");
            errors = errors + 1;
        end

        if (errors == 0)
            $display("TESTBENCH: ALL TESTS PASSED");
        else
            $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $finish;
    end

    initial begin
        #500000;
        $display("RESULT: GLOBAL TIMEOUT");
        $finish;
    end

endmodule