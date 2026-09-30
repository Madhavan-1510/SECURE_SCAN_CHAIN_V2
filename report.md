# Paper 1 vs. Project RTL: Comparison Report

**Project:** Segmented secure-scan defense for a PicoRV32 + AES-128 PCPI coprocessor (Spartan-7, Real Digital Boolean Board)
**Reviewed:** the manuscript text and `ref2.zip` (Vivado project `reference`)
**Method:** source reading only. No simulation or synthesis was re-run.

**Not reviewed in depth:** `fpga_top.v`, `io_conditioning.v`, `uart_*`, `seven_seg_hex.v`, and `picorv32.v`. The last was not diffed against upstream, so "unmodified PicoRV32" is unconfirmed.

Legend: ✅ matches RTL | ⚠️ true but overstated or incomplete | ❌ contradicted by RTL | ❓ cannot be verified from the zip

---

## 1. What the project actually is

```
picorv32 (CPU, unmodified?) --PCPI--> aes_pcpi ----------------------------+
                                        |  scan chain (front -> back)      |
                                        |  key_stage[128]                  |
                                        |  block_stage[128]                |
                                        |  fsm_state[1]                    |
                                        +-> aes_core                       |
                                             round_reg[4]                  |
                                             state_reg[128]                |
                                             round_key_reg[128]  <- gated scan_in
                                             key_reg[128]                  |
                                             --> seg_out_muxed --> scan_out|
scan_lock_controller --locked--> aes_core (two combinational muxes)        |
```

- **Chain length:** 128 + 128 + 1 + 4 + 128 + 128 + 128 = **645 bits** ✅
- **Bit map:** key_reg [644:517], round_key_reg [516:389], state_reg [388:261], round_reg [260:257], fsm_state [256], block_stage [255:128], key_stage [127:0] ✅ (matches paper Table II)
- **Primitives:** `scan_cell` (1-bit, single clock) and `scan_chain` (parameterized, LSB-first)
- **Lock:** `scan_lock_controller`, a 32-bit static code compare. Locked on reset, `relock` has priority, separate `lock_resetn` domain.
- **Baseline:** `SECURE_SCAN` generate parameter in `secure_scan_rv_top_v2`. 0 means no controller and `locked` tied to 0.
- **Board:** `board_top` adds a hand-assembled firmware ROM, a scan dump controller (`scan_in` = 0), UART and 7-segment readout, and switch-driven lock control.

---

## 2. Claim-by-claim comparison

### Abstract and architecture

| Paper claim | RTL evidence | Verdict |
|---|---|---|
| Unmodified PicoRV32 coupled via PCPI | PCPI ports wired directly; `picorv32.v` in tree | ✅ / ❓ (not diffed) |
| Custom1 opcode, five funct3 ops, combinational decode | `AES_OPCODE = 7'b0101011`; `is_aes_opcode` is combinational; funct3 000-100 | ✅ |
| "Every scan-relevant register modelled as an explicit scan primitive" | `aes_core.fsm_state`, `aes_pcpi.start_i_reg`, `core_seen_running` are plain regs | ⚠️ |
| 645-bit segment | Computed above | ✅ |
| Lock isolates only the 256 key-bearing bits | `seg_out_muxed = locked ? 0 : seg_tap[4]` blanks the **entire** 645-bit output. Only `round_key_reg`'s scan-in is gated | ❌ |
| Masking is combinational, shift-count independent | Mux keyed only on registered `locked` | ✅ |
| Fail-safe locked on reset and relock; clears only on correct code | `locked_q <= 1` on reset/relock; clears on `unlock_valid && code match` | ✅ |
| "Single-cycle pulse presenting the correct code" | Clears in any cycle where `unlock_valid` is high with the right code (not strictly single-cycle) | ⚠️ (wording) |
| Locked and unlocked behave per spec, zero functional overhead | Mux acts only on scan wiring; `scan_en=0` paths untouched | ✅ |

The paper's Section V admits the mismatch in the row "lock isolates only the 256 key bits", but the abstract, contributions, and Section III(c) still describe a segmented lock. `tb_keystage_lock_scope.v` also states the whole-output blanking in its own header.

### Verification

| Paper claim | RTL evidence | Verdict |
|---|---|---|
| 12-testbench regression | 13 files in `sim_1/new` (includes `tb_scan_attack_harness`, `tb_fpga_top`) | ⚠️ reconcile the count |
| Ten shift-count points: 0, 1, 127, 255, 256, 388, 517, 644, 645, 1290 | `tb_scan_lock.v` `shift_points[]` matches | ✅ |
| Baseline attack recovers the full key | `tb_scan_attack` / `tb_scan_lock` unlocked path | ✅ (not re-run) |
| Attack "halts mid-computation" | Sim harness freezes after `FREEZE_CYCLES = 6`. **Board** dump runs after the firmware traps (computation finished) | ⚠️ sim yes, board no |
| Bit-exact KAT ciphertext regardless of lock | `tb_cpu_driven_aes`, `tb_scan_resume`, board Table II ciphertext | ✅ |
| Wrong-code rejection | `tb_scan_lock` PART C tests **one** wrong code | ⚠️ thin |

### Hardware

| Paper claim | RTL evidence | Verdict |
|---|---|---|
| Locked hardware scan dump is all zeros | Same mux; dump controller ties `scan_in` to 0 | ✅ |
| Unlocked dump reconstructs all 645 bits (Table II) | Every field is consistent with the RTL: `round_reg` = 0xA (final round holds), `fsm_state` = IDLE after READRESULT, `key_stage` = residue of the loaded key | ✅ |
| Round-10 key `13111D7F...30C5` | Standard AES-128 key schedule result for the FIPS-197 key | ✅ |
| 7-seg is an "independent readout path" | Both UART and 7-seg read `key_disp_reg` / `ct_disp_reg`, latched from `dbg_core_*` taps. They bypass scan **and the lock** | ⚠️ |
| Zero-interaction bring-up | `power_on_reset` + edge-pulse reset AND-ed | ✅ |
| Access control on hardware | `lock_switch_ctrl` presents the fixed code when sw[1] rises. It is a **physical switch** | ⚠️ undisclosed |

### Overhead (Table III)

| Item | Paper | Reports in zip | Verdict |
|---|---|---|---|
| LUTs, SECURE_SCAN=0 | 2,828 | 2,828 (impl_2 placed) | ✅ |
| FFs, SECURE_SCAN=0 | 1,225 | 1,225 | ✅ |
| BRAM | 1 RAMB36E1 | 1 | ✅ |
| WNS, SECURE_SCAN=0 | 2.502 ns | 2.502 | ✅ |
| Fmax (baseline) | ≈133.4 MHz | 1 / (10 - 2.502) = 133.4 | ✅ |
| LUTs, SECURE_SCAN=1 | 2,842 (+14) | not in zip | ❓ |
| WNS, SECURE_SCAN=1 | 2.084 ns | not in zip | ❓ |
| Full board design | 4,365 LUTs / 4,248 regs | `util.rpt`: 4,365 / 4,248 | ✅ |

Notes on Table III:
- Fmax here is derived from WNS against a 10 ns constraint, so call it "estimated".
- Baseline has `locked` tied to 0, so synthesis removes the boundary muxes. The +14 LUTs therefore include the mux logic as well as the controller. That's fair, but say it.

---

## 3. Findings in the RTL that the paper does not mention

1. **Scan-in is not gated while locked.** `key_stage`, `block_stage`, `fsm_state`, `round_reg` and `state_reg` can all be written with `locked = 1`. This allows tampering, key-stage overwrite, and a possible hang via the PCPI `fsm_state` bit. Not simulated; needs a testbench.
2. **Locked shifting zeroizes the key registers.** `seg_in_muxed` feeds 0 into `round_key_reg`. 128 shifts wipe it and 256 wipe both key registers. This is a DoS/zeroize side effect.
3. **`key_stage` holds the master key permanently.** Nothing ever clears it (it is the source for every `load_key`). It is only safe because of blanket output masking, so any move to granular masking would leak it.
4. **The unlock is weak.** It is a static 32-bit code with no attempt limiter and it is the public default parameter `32'hDEC0DED1`. Exhaustive search is about 2^32 cycles (about 43 s at 100 MHz). It also sits in the bitstream.
5. **Unscanned control state keeps running during scan.** `aes_core.fsm_state` advances while `round_reg` is being shifted, so `is_final_round` can fire on shifted-in data. The "freeze" is only real in the sim harness.
6. **The board's key display is a lock bypass by design.** `dbg_core_key_reg` feeds board registers regardless of `locked`. Fine for a demo, but it must be disclosed and removed in a secure build.
7. **Stale file in the tree.** `secure_scan_rv_top.v` (v1) has no scan/lock ports. Do not ship it with the design.
8. **Firmware is hand-assembled hex** in `initial` blocks, with no `.S` source.
9. **Repo hygiene.** The zip is 26 MB of `.Xil`, `.wdb`, `.dcp`. Track only `srcs/`, the XDC, and a build tcl. `secure.md` and `scan_map.md` are referenced in comments but were not in the zip.

---

## 4. Edits to make to Paper 1 (or plan for Paper 2)

**Wording, do now:**
- Rewrite the abstract and contribution 3 to say the lock **blanks the whole coprocessor scan-out**, with the key registers additionally scan-in gated. Move "segmented" to future work.
- Change "every scan-relevant register" to "every datapath and staging register".
- Disclose that the board unlock is a switch and that the 7-seg/UART path uses debug taps.
- Change "mid-computation" to "in simulation; the board demo dumps after completion".
- Fix the testbench count (12 vs 13).
- Fix Equation (1) indexing so it matches `round_reg` (round *i* applies K_i to the state after round *i-1*), and note that Rcon applies only when i mod 4 = 0 in Eq. (2).
- Fix references ([17], [18] mismatches; [15] and [16] uncited; [8] title mismatch) and strip the "Content: Journal Article" artifacts.
- Drop or qualify "first reconstruction of the 645-bit segment from live hardware".

**Engineering, Paper 2:**
- Real granular masking: gate `scan_en & ~locked` on the sensitive registers and bypass the tail so `scan_out` comes from `seg_tap[2]` when locked.
- Gate or protect scan-in at the chain front while locked.
- Attempt limiter plus a longer or challenge/response unlock.
- Scan or freeze the remaining control registers.
- Remove the `dbg_*` key taps from the secure build.
- Stuck-at fault coverage (Yosys + Fault/Atalanta) for full scan vs blanking vs granular lock.
- Baselines: zeroize-on-`scan_en`, and the paper-1 blanking scheme.
- Stronger attacks: write-while-locked, chosen-state capture, mode-switch, unlock brute force.
- Overhead for SECURE_SCAN off / paper-1 / paper-2 from one RTL source.

---

## 5. Bottom line

The RTL is correct, cleanly structured, and its hardware evidence (Table II) matches the source field for field. The gap is between what the design does and how the paper describes it:

| Paper says | Design does |
|---|---|
| Segmented lock protecting 256 of 645 bits | Whole-coprocessor scan-out kill switch |
| Access-controlled | Static 32-bit code, no limiter; switch-driven on the board |
| Attack "mid-computation" | Sim only; board dumps post-completion |

Fix the wording and the reference list and the paper is a fair workshop-level submission. Fix the engineering list and it becomes the stronger Paper 2.
