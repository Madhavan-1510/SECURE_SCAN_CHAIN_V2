// ============================================================================
// tb_board_top_def.v  (Paper 2, board demo verification)
//
// Drives board_top_def over its real UART pins (bit-banged RX, sampled TX) and
// checks the replies, so the board console is verified in simulation before a
// bitstream is built. UART is sped up (CLK=100 kHz, BAUD=25 k -> 4 cycles/bit)
// and the lock timers shrunk, purely for sim speed; the RTL is unchanged.
//
// Checks:
//   1  out of reset: status locked=1
//   2  wrong unlock code: still locked
//   3  correct secret (after boot delay): locked=0
//   4  K/B/E with the NIST KAT key/block -> ciphertext == 69c4e0d8.. (console +
//      PCPI master + coprocessor all work)
//   5  relock -> status locked=1
//   6  locked scan read 'R' -> all zeros, on BOTH G1 (sel=0) and G4 (sel=1)
//   7  G1 locked: load KAT, relock, inject 'W'(EVIL), 'E' -> ciphertext != KAT
//      (write attack succeeds through the Paper 1 lock)
//   8  G4 locked: same sequence -> ciphertext == KAT (write attack blocked)
//   9  G4 UNLOCKED: inject then 'E' -> != KAT (negative control: works unlocked)
// ============================================================================
`timescale 1ns/1ps

module tb_board_top_def;
    localparam integer DIV = 4;              // CLK/BAUD
    reg clk = 0;
    reg [15:0] sw = 16'h0;
    reg [3:0]  btn = 4'b0;
    reg        rxd = 1'b1;
    wire       txd;
    wire [15:0] led; wire [2:0] RGB0, RGB1;
    wire [3:0] D0_AN, D1_AN; wire [7:0] D0_SEG, D1_SEG;

    board_top_def #(
        .CLK_FREQ_HZ(100_000), .BAUD(25_000),
        .SECRET(32'h5EC2_E7A1), .MAX_FAILS(3),
        .LOCKOUT_CYCLES(300), .BOOT_DELAY_CYCLES(120), .DEBOUNCE_CYCLES(4)
    ) dut (
        .clk(clk), .sw(sw), .led(led), .btn(btn), .RGB0(RGB0), .RGB1(RGB1),
        .D0_AN(D0_AN), .D0_SEG(D0_SEG), .D1_AN(D1_AN), .D1_SEG(D1_SEG),
        .UART_rxd(rxd), .UART_txd(txd));

    always #5 clk = ~clk;   // 100 MHz-ish; timing is cycle-based

    localparam [127:0] KEY  = 128'h000102030405060708090A0B0C0D0E0F;
    localparam [127:0] BLK  = 128'h00112233445566778899AABBCCDDEEFF;
    localparam [127:0] KAT  = 128'h69C4E0D86A7B0430D8CDB78070B4C55A;
    localparam [127:0] EVIL = 128'h0F1E2D3C4B5A69788796A5B4C3D2E1F0;

    integer errors = 0;

    // ---- UART bit-bang TX (into DUT rxd) ----
    task send_byte(input [7:0] b);
        integer i;
        begin
            rxd = 1'b0; repeat (DIV) @(posedge clk);           // start
            for (i = 0; i < 8; i = i + 1) begin rxd = b[i]; repeat (DIV) @(posedge clk); end
            rxd = 1'b1; repeat (DIV) @(posedge clk);           // stop
            repeat (DIV) @(posedge clk);                        // idle gap
        end
    endtask

    function [7:0] hexc(input [3:0] n); hexc = (n<10)?(8'h30+n):(8'h41+n-10); endfunction

    task send_str(input [8*40-1:0] s, input integer n);        // n chars, MSB-first
        integer i; reg [7:0] c;
        begin for (i = n-1; i >= 0; i = i - 1) begin c = s[i*8 +: 8]; send_byte(c); end end
    endtask

    task send_hex128(input [127:0] v);
        integer i; begin for (i = 0; i < 32; i = i + 1) send_byte(hexc(v[127 - i*4 -: 4])); end
    endtask
    task send_hex32(input [31:0] v);
        integer i; begin for (i = 0; i < 8; i = i + 1) send_byte(hexc(v[31 - i*4 -: 4])); end
    endtask
    task cr; begin send_byte(8'h0d); end endtask

    // ---- UART sample RX (from DUT txd) ----
    reg [7:0] rxbuf [0:255];
    integer   rxn;

    task recv_byte(output [7:0] b);
        integer i;
        begin
            @(negedge txd);                                    // start edge
            repeat (DIV + DIV/2) @(posedge clk);               // center of bit0
            for (i = 0; i < 8; i = i + 1) begin b[i] = txd; repeat (DIV) @(posedge clk); end
            @(posedge clk);
        end
    endtask

    // collect a reply line until LF (0x0a); store bytes (incl CR) in rxbuf
    task recv_line;
        reg [7:0] c; reg done;
        begin
            rxn = 0; done = 0;
            while (!done) begin
                recv_byte(c);
                if (c == 8'h0a) done = 1;
                else if (c != 8'h0d) begin rxbuf[rxn] = c; rxn = rxn + 1; end
            end
        end
    endtask

    // extract the 32-hex ciphertext following "E " in rxbuf -> value
    function [127:0] parse_ct(input dummy);
        integer i; reg [127:0] v;
        begin
            v = 0;
            for (i = 0; i < 32; i = i + 1) begin
                v = v << 4;
                v = v | nib(rxbuf[2 + i]);
            end
            parse_ct = v;
        end
    endfunction
    function [3:0] nib(input [7:0] c);
        if (c >= "0" && c <= "9") nib = c - "0";
        else if (c >= "A" && c <= "F") nib = c - "A" + 10;
        else nib = 0;
    endfunction

    // true if every char after "R " is '0'
    function all_zero_read(input dummy);
        integer i; reg z;
        begin z = 1; for (i = 2; i < rxn; i = i + 1) if (rxbuf[i] !== "0") z = 0; all_zero_read = z; end
    endfunction

    // find "lk=" and return the following char
    function [7:0] locked_char(input dummy);
        integer i;
        begin
            locked_char = "?";
            for (i = 0; i + 2 < rxn; i = i + 1)
                if (rxbuf[i]=="l" && rxbuf[i+1]=="k" && rxbuf[i+2]=="=") locked_char = rxbuf[i+3];
        end
    endfunction

    task chk(input cond, input [8*60-1:0] msg);
        begin if (cond) $display("PASS: %0s", msg);
              else begin $display("FAIL: %0s", msg); errors = errors + 1; end end
    endtask

    reg [127:0] ct;

    // run one command that returns a line; helpers below
    task cmd0(input [7:0] c);     begin send_byte(c); cr; recv_line; end endtask
    task cmdU(input [31:0] code); begin send_byte("U"); send_hex32(code); cr; recv_line; end endtask

    // Unlock sequence: wait out the boot delay, present the secret, read status.
    task do_unlock;
        begin
            repeat (200) @(posedge clk);     // > BOOT_DELAY_CYCLES
            cmdU(32'h5EC2_E7A1);
        end
    endtask

    task load_kat;                            // assumes unlocked
        begin
            send_byte("K"); send_hex128(KEY); cr; recv_line;
            send_byte("B"); send_hex128(BLK); cr; recv_line;
        end
    endtask

    integer n;
    initial begin
        // power-on: hold nothing; POR releases after a few cycles
        repeat (300) @(posedge clk);

        // 1 status locked
        cmd0("S"); chk(locked_char(0)=="1", "1 out of reset: locked=1");

        // 2 wrong code
        repeat (200) @(posedge clk);
        cmdU(32'hDEAD_BEEF); chk(locked_char(0)=="1", "2 wrong unlock code: still locked");

        // 3 correct code
        do_unlock; chk(locked_char(0)=="0", "3 correct secret: unlocked");

        // 4 KAT through the console (sel=0, G1 unlocked)
        load_kat;
        cmd0("E"); ct = parse_ct(0); chk(ct===KAT, "4 K/B/E reproduces the NIST KAT ciphertext");

        // 5 relock
        cmd0("L"); cmd0("S"); chk(locked_char(0)=="1", "5 relock: locked=1");

        // 6a locked read on G1
        cmd0("R"); chk(all_zero_read(0), "6a G1 locked scan read 'R' is all zeros");

        // 6b locked read on G4
        sw[0] = 1'b1; repeat (40) @(posedge clk);
        cmd0("R"); chk(all_zero_read(0), "6b G4 locked scan read 'R' is all zeros");
        sw[0] = 1'b0; repeat (40) @(posedge clk);

        // 7 G1 injection while locked: load KAT, relock, W(EVIL), E -> != KAT
        do_unlock; load_kat; cmd0("L");
        send_byte("W"); send_hex128(EVIL); cr; recv_line;
        cmd0("E"); ct = parse_ct(0);
        chk(ct!==KAT, "7 G1 locked injection changes the ciphertext (write attack succeeds)");
        $display("     G1 injected ciphertext = %032h", ct);

        // 8 G4 injection while locked: same -> == KAT (blocked)
        sw[0] = 1'b1; repeat (40) @(posedge clk);
        do_unlock; load_kat; cmd0("L");
        send_byte("W"); send_hex128(EVIL); cr; recv_line;
        cmd0("E"); ct = parse_ct(0);
        chk(ct===KAT, "8 G4 locked injection has NO effect (write attack blocked)");

        // 9 G4 unlocked injection -> != KAT (negative control)
        do_unlock; load_kat;
        send_byte("W"); send_hex128(EVIL); cr; recv_line;
        cmd0("E"); ct = parse_ct(0);
        chk(ct!==KAT, "9 G4 UNLOCKED injection changes ciphertext (defense only acts while locked)");

        if (errors == 0) $display("TESTBENCH: ALL TESTS PASSED");
        else             $display("TESTBENCH: %0d TEST(S) FAILED", errors);
        $finish;
    end

    initial begin #50_000_000; $display("RESULT: GLOBAL TIMEOUT"); $finish; end
endmodule
