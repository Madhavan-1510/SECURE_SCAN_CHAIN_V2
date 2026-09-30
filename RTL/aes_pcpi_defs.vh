// ============================================================================
// aes_pcpi_defs.vh
//
// Custom instruction encoding for the AES-128 PCPI coprocessor.
//
// PicoRV32 PCPI contract this encoding must respect (see picorv32.v):
//   - The CPU offers EVERY instruction it does not itself decode to the
//     external PCPI port: pcpi_valid=1, pcpi_insn=<raw 32-bit instruction>,
//     pcpi_rs1/pcpi_rs2 = register file values for the rs1/rs2 fields.
//   - If CATCH_ILLINSN=1, a hidden countdown timer starts the moment
//     pcpi_valid asserts and pcpi_wait stays low; it forces an illegal-
//     instruction trap after a small, fixed number of cycles
//     (~16, see `pcpi_timeout_counter` in picorv32.v) if no PCPI device
//     claims the instruction. THEREFORE: our coprocessor must recognize
//     "is this mine?" and drive pcpi_wait=1 the SAME cycle pcpi_valid is
//     first seen, for any instruction using our opcode -- decoding must be
//     combinational off pcpi_insn, not registered.
//   - For instructions that are NOT ours, we must drive pcpi_wait=0 and
//     pcpi_ready=0 so the CPU's normal illegal-instruction/other-PCPI path
//     is not blocked.
//   - Completion is signaled with a single-cycle pcpi_ready=1 pulse;
//     pcpi_wr indicates whether pcpi_rd should be written to rd; pcpi_rd
//     is only sampled by the CPU on that same ready cycle.
//
// Opcode choice: RISC-V "custom-1" major opcode (0b0101011). PicoRV32 never
// decodes this opcode for any built-in instruction (getq/setq/retirq/
// maskirq/waitirq/timer use custom-0, 0b0001011, and only when ENABLE_IRQ=1),
// so custom-1 cannot collide with any built-in decode regardless of IRQ
// configuration.
//
// Instruction format (R-type layout, funct3 selects the AES operation):
//
//   31        25 24     20 19     15 14  12 11      7 6      0
//  |  funct7    |  rs2    |  rs1    |funct3|   rd    | opcode |
//
//   opcode = 0b0101011 (custom-1) for ALL AES instructions.
//   funct7 = don't-care (reserved, set to 0 by the assembler/toolchain).
//
// funct3 encodes the operation. Because PCPI only exposes two 32-bit
// source operands (rs1, rs2) per instruction, and our secrets are 128 bits,
// the key/block are loaded and results are read back ONE 32-BIT WORD AT A
// TIME using rs1 as a word-select index (0..3). Word 0 = bits[127:96]
// (most-significant word), consistent with the big-endian byte convention
// used throughout aes_core.v.
//
//   funct3 = 000  AES_LOADKEY    rs1[1:0] = word index (0-3)
//                                 rs2      = 32-bit key word to load
//                                 rd       = unused (pcpi_wr = 0)
//
//   funct3 = 001  AES_LOADBLOCK  rs1[1:0] = word index (0-3)
//                                 rs2      = 32-bit plaintext word to load
//                                 rd       = unused (pcpi_wr = 0)
//
//   funct3 = 010  AES_ENCRYPT    rs1, rs2 = unused
//                                 Starts the 10-round iterative encryption
//                                 using whatever key/block words have been
//                                 loaded so far. pcpi_wait stays high for
//                                 the full ~11-cycle AES latency; rd
//                                 unused (pcpi_wr = 0).
//
//   funct3 = 011  AES_READ_RESULT rs1[1:0] = word index (0-3) of ciphertext
//                                 rd       = selected 32-bit ciphertext word
//                                            (pcpi_wr = 1)
//
//   funct3 = 100  AES_STATUS      rs1, rs2 = unused
//                                 rd = {31'b0, busy} : bit0 = core busy_o
//                                 (pcpi_wr = 1). Lets software poll instead
//                                 of relying purely on pcpi_wait stalling
//                                 (useful once interrupts/IRQ are added).
//
//   funct3 = 101,110,111          reserved / not decoded (treated as "not
//                                  ours" -> pcpi_wait=0, pcpi_ready=0, so
//                                  the core CPU's illegal-instruction path
//                                  can still fire).
// ============================================================================

`define AES_OPCODE   7'b0101011

`define AES_F3_LOADKEY     3'b000
`define AES_F3_LOADBLOCK   3'b001
`define AES_F3_ENCRYPT     3'b010
`define AES_F3_READRESULT  3'b011
`define AES_F3_STATUS      3'b100
