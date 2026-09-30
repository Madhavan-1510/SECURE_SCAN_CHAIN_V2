`timescale 1ns/1ps

module tb_board_top;

    reg         clk = 0;
    reg  [15:0] sw = 16'h0;
    wire [15:0] led;
    reg  [3:0]  btn = 4'h0;
    wire [2:0]  RGB0, RGB1;
    wire [3:0]  D0_AN, D1_AN;
    wire [7:0]  D0_SEG, D1_SEG;
    reg         UART_rxd = 1'b1;
    wire        UART_txd;

    localparam [127:0] KEY = 128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] EXPECTED_CT = 128'h69C4E0D86A7B0430D8CDB78070B4C55A;

    // Small values purely for simulation speed -- see board_top.v header,
    // same convention as io_conditioning.v's own DEBOUNCE_CYCLES pattern.
    board_top #(
        .CLK_FREQ_HZ(1000), .BAUD(250), .DEBOUNCE_CYCLES(4)
    ) dut (
        .clk(clk), .sw(sw), .led(led), .btn(btn),
        .RGB0(RGB0), .RGB1(RGB1),
        .D0_AN(D0_AN), .D0_SEG(D0_SEG), .D1_AN(D1_AN), .D1_SEG(D1_SEG),
        .UART_rxd(UART_rxd), .UART_txd(UART_txd)
    );

    always #5 clk = ~clk;
    integer errors = 0;

    task press(input integer idx);
        begin
            btn[idx] = 1'b1;
            repeat (10) @(posedge clk);
            btn[idx] = 1'b0;
            repeat (10) @(posedge clk);
        end
    endtask

    initial begin
        // ---- Power on: NO button interaction at all, simulating a board
        // where btn[0]/btn[1] idle at a level we never assume. power_on_reset
        // alone must bring the design up correctly. ----
        repeat (5) @(posedge clk); // let POR run its course

        // ---- Wait for firmware to run and trap, with ZERO button presses ----
        wait (dut.cpu_done == 1'b1);
        @(posedge clk); #1;
        $display("PASS: CPU completed with NO button interaction at all (POR-only bring-up)");

        $display("================================================================");
        $display("BOARD_TOP INTEGRATION CHECK");
        $display("================================================================");
        $display("Latched key:        %032h", dut.key_disp_reg);
        $display("Latched ciphertext: %032h", dut.ct_disp_reg);

        if (dut.key_disp_reg === KEY)
            $display("PASS: latched key matches KAT key (real firmware loaded it via PCPI)");
        else begin
            $display("FAIL: latched key mismatch"); errors = errors + 1;
        end

        if (dut.ct_disp_reg === EXPECTED_CT)
            $display("PASS: latched ciphertext matches NIST KAT");
        else begin
            $display("FAIL: latched ciphertext mismatch"); errors = errors + 1;
        end

        if (led[0] !== 1'b1) begin
            $display("FAIL: led[0] (cpu_done) not lit"); errors = errors + 1;
        end
        if (led[1] !== 1'b1) begin
            $display("FAIL: led[1] (locked) should default fail-safe locked=1"); errors = errors + 1;
        end else
            $display("PASS: fail-safe default locked=1 confirmed on led[1]");

        // ---- Scan dump while LOCKED (default) ----
        sw[0] = 1'b1; // ARM_SCAN
        repeat (20) @(posedge clk); // let debounce settle
        press(2);     // SCAN DUMP TRIGGER
        wait (dut.scan_dump_done == 1'b1);
        @(posedge clk); #1;

        $display("----------------------------------------------------------------");
        $display("Scan capture (LOCKED): captured[644:517] = %032h", dut.scan_capture[644:517]);
        if (dut.scan_capture[644:517] === {128{1'b0}})
            $display("PASS: scan dump shows all-zero key window while LOCKED (defense holds on board_top)");
        else begin
            $display("FAIL: key leaked through scan dump while LOCKED"); errors = errors + 1;
        end

        // NOTE: the scan dump above also zeroed the live aes_core registers
        // (scan_in tied 0 -- see scan_dump_controller.v header). This is
        // expected. Reset and re-run firmware before checking the UNLOCKED
        // case so we get a fresh, real key resident again.
        btn[0] = 1'b1; repeat(10) @(posedge clk); btn[0] = 1'b0;
        wait (dut.cpu_done == 1'b1);
        @(posedge clk); #1;

        // ---- Unlock, then scan dump again ----
        sw[1] = 1'b1; // UNLOCK
        repeat (20) @(posedge clk); // let debounce settle + lock_switch_ctrl pulse
        repeat (5) @(posedge clk);

        if (led[1] !== 1'b0) begin
            $display("FAIL: led[1] did not clear after UNLOCK switch asserted"); errors = errors + 1;
        end else
            $display("PASS: UNLOCK switch correctly cleared locked (led[1]=0)");

        press(2); // SCAN DUMP TRIGGER again, now unlocked
        wait (dut.scan_dump_done == 1'b1);
        @(posedge clk); #1;

        $display("----------------------------------------------------------------");
        $display("Scan capture (UNLOCKED): captured[644:517] = %032h", dut.scan_capture[644:517]);
        if (dut.scan_capture[644:517] === KEY)
            $display("PASS: scan dump recovers real key while UNLOCKED (baseline behavior reproduced)");
        else begin
            $display("FAIL: key not recovered while UNLOCKED"); errors = errors + 1;
        end

        // ---- Reset again, re-run firmware, then exercise the UART dump path ----
        btn[0] = 1'b1; repeat(10) @(posedge clk); btn[0] = 1'b0;
        wait (dut.cpu_done == 1'b1);
        @(posedge clk); #1;

        press(3); // UART DUMP TRIGGER
        wait (dut.uart_seq_state == 2'd0 && dut.key_dump_busy == 0 &&
              dut.ct_dump_busy == 0 && dut.scan_dump_busy_tx == 0);
        repeat (20) @(posedge clk);
        $display("----------------------------------------------------------------");
        $display("PASS: UART dump sequence (key -> ciphertext -> scan capture) ran to completion without hang");

        $display("================================================================");
        if (errors == 0)
            $display("TESTBENCH: ALL TESTS PASSED");
        else
            $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $display("================================================================");
        $finish;
    end

    initial begin
        #2_000_000;
        $display("RESULT: GLOBAL TIMEOUT");
        $finish;
    end

endmodule