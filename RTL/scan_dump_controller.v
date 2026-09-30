// ============================================================================
// scan_dump_controller.v
//
// Board-level scan capture, deliberately simpler than scan_attack_harness.v:
// it does NOT drive PCPI itself. The real key/plaintext were already loaded
// by genuine firmware running on the real picorv32 core (see board_top.v) --
// this controller only takes over scan_en/scan_in on demand and shifts the
// full SCAN_WIDTH-bit segment out, using the same authoritative capture rule
// verified in tb_scan_chain.v Check 3 / scan_attack_harness.v: one pre-shift
// sample of the current last bit (scan_out is combinational, visible before
// the first scan clock edge) plus (SCAN_WIDTH-1) post-edge samples.
//
// scan_in_o is tied to 0 for the whole dump. This means the dump is
// destructive to the live coprocessor state -- every scanned register ends
// up filled with zeros afterward, exactly the same functional-clearing
// behavior already proven in tb_scan_chain.v Check 4 ("shifting circulates
// scan_in, not the old functional value"). board_top.v accounts for this by
// latching the key/ciphertext for display BEFORE any scan dump can run, not
// by reading them live afterward.
// ============================================================================
`timescale 1ns/1ps

module scan_dump_controller #(
    parameter integer SCAN_WIDTH = 645
) (
    input  wire                    clk,
    input  wire                    resetn,
    input  wire                    start_i,     // 1-cycle pulse: begin a dump
    output reg                     scan_en_o,
    output wire                    scan_in_o,   // tied 0: pure readout, no injection
    input  wire                    scan_out_i,
    output reg  [SCAN_WIDTH-1:0]   captured_o,
    output reg                     done_o
);

    assign scan_in_o = 1'b0;

    localparam S_IDLE  = 2'd0;
    localparam S_PRE   = 2'd1;
    localparam S_SHIFT = 2'd2;
    localparam S_DONE  = 2'd3;

    reg [1:0]                       state;
    reg [$clog2(SCAN_WIDTH)-1:0]     shift_cnt;

    always @(posedge clk) begin
        if (!resetn) begin
            state      <= S_IDLE;
            scan_en_o  <= 1'b0;
            done_o     <= 1'b0;
            captured_o <= {SCAN_WIDTH{1'b0}};
        end else begin
            case (state)
                S_IDLE: begin
                    done_o <= 1'b0;
                    if (start_i) begin
                        scan_en_o <= 1'b1;
                        state     <= S_PRE;
                    end
                end

                S_PRE: begin
                    captured_o[SCAN_WIDTH-1] <= scan_out_i; // pre-shift sample
                    shift_cnt <= {$clog2(SCAN_WIDTH){1'b0}};
                    state     <= S_SHIFT;
                end

                S_SHIFT: begin
                    captured_o[SCAN_WIDTH-2-shift_cnt] <= scan_out_i;
                    if (shift_cnt == SCAN_WIDTH-2) begin
                        scan_en_o <= 1'b0;
                        done_o    <= 1'b1;
                        state     <= S_DONE;
                    end else
                        shift_cnt <= shift_cnt + 1'b1;
                end

                S_DONE: begin
                    done_o <= 1'b1;
                    if (start_i) begin
                        done_o    <= 1'b0;
                        scan_en_o <= 1'b1;
                        state     <= S_PRE;
                    end
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule