# SecureScan-RV (Paper 2) — Verified Project Reference for Paper Drafting

**Status.** Every simulation result in this document was produced this session by
compiling and running the actual project RTL/testbenches with **Icarus Verilog
12.0** (full gated regression: **30/30 PASS**), and the one formal result with
**Yosys 0.33 + Z3 4.8.12 + SymbiYosys**. Ciphertext goldens were checked
against **pycryptodome**, independent of the DUT. Lines quoted in fixed-width
blocks are copied from the run logs (`.reg_work/<tb>/run.log`). Claims that are
interpretation rather than a direct run are labelled **[inference]**. Items you
must still produce (synthesis, board photos) are marked **[[FILL]]**.

> This is the companion Paper 2 reference. Paper 2 = *"From locking scan
> **read** to securing scan **read and write**."* Paper 1 defended scan-read;
> Paper 2 shows the read lock does **not** defend scan-write, proves a
> write-side attack, builds a write-blocking defense (G4), hardens the lock
> (L1), proves a lock property formally, and quantifies the testability cost.

---

## 0. Title options

- **Primary:** *Securing Scan Read **and** Write for a PCPI-Coupled AES-128
  Coprocessor on RISC-V: A Write-Blocking Segmented Scan Lock with Formal and
  Testability Analysis.*
- **Alt:** *Beyond Scan-Read Locks: Key/Plaintext Injection Through Scan-Write
  on a Shared RISC-V SoC Chain, and a Verified Defense.*

Paper type: **implementation + verification + (partial) formal** paper. Use
"we design, implement, simulation-verify, and formally check"; the only missing
piece is FPGA synthesis/overhead numbers (§10).

---

## 1. Abstract material (condense to ~150 words)

Scan chains give near-total read/write access to a chip's flip-flops. Paper 1
showed that masking the coprocessor's scan **output** while locked defeats a
scan-**read** key-recovery attack. We show this is insufficient: the same lock
leaves the scan **input** open, so an attacker who never unlocks the chip can
(i) inject a chosen key and plaintext and make the coprocessor encrypt under
them, (ii) forge the ciphertext the CPU reads back, and (iii) zeroize the key —
all through the locked scan port, confirmed in simulation with ciphertexts
checked against an independent AES implementation. We quantify the exposed
surface: while locked, Paper 1's design reveals **0** bits on scan-out yet
leaves **388 of 645** chain bits scan-**writable**. We design a write-blocking
segmented lock (**G4**) that freezes the chain while locked, evaluate three
weaker variants (granular masking, flush-on-edge, recirculating tail) as
ablations that each fail in a measured way, harden the unlock controller
(attempt lockout + boot delay, no public default code), and show the whole
hardened design blocks every attack driven by the real CPU over PCPI while
keeping the AES functionally bit-exact (NIST KAT) and the chain fully testable
when unlocked (645/645, with scan stuck-at faults detected). We formally prove
(k-induction) that G4 holds scan-out at constant 0 while locked.

---

## 2. What is / isn't novel (put this in Related Work)

**Not novel (do not claim):** masking scan output to defeat scan-read attacks on
crypto hardware — established (Yang/Wu/Karri; DaRolt; DefScan, §13).

**Paper 2's contribution:**
1. **Scan-write as the live threat on a shared PCPI/RISC-V chain.** Prior secure-
   scan work assumes a standalone crypto core with a dedicated chain and a
   read attacker. Here the AES key lives in **256 of 645** bits of an SoC-wide
   chain shared with CPU/PCPI/datapath state, and the attacker writes as well
   as reads. Concrete, reproduced attacks: key+plaintext **injection**,
   ciphertext **spoof**, and **zeroize**, none needing an unlock.
2. **A write-blocking segmented lock (G4)** that closes all of them, with three
   weaker variants evaluated as ablations (why read-masking, a granular tail,
   and flush-on-edge are each insufficient) — not a single hero defense.
3. **A quantified security–testability trade-off** (T1/T2): exactly what is
   readable/writable while locked for each variant, and proof that unlocked
   testability (incl. stuck-at fault detection) is preserved.
4. **A formal lock property** (open-source toolchain) and an end-to-end
   **real-CPU** demonstration, extendable to a live FPGA console.

**Why not an LFSR/obfuscation lock:** the GF-Flush / ScanSAT line breaks dynamic
scan obfuscation given enough challenge/response pairs. Say so — it shows the
literature was done, and it justifies masking over obfuscation.

---

## 3. Threat model (table for the paper)

| | |
|---|---|
| **Assets** | AES-128 master key (and K10, invertible to it); integrity of key, plaintext, ciphertext, control state; coprocessor availability. |
| **Attacker** | Physical / JTAG-test access: controls `scan_en`/`scan_in`, observes `scan_out`, can halt/clock the chip and trigger normal-mode cycles. Knows the RTL, the scan map, and the public default unlock code. |
| **Public** | Plaintexts, ciphertexts, the design, the scan map. |
| **Goals** | G-conf: recover key. G-int: encrypt under attacker key/plaintext, or forge the ciphertext. G-avail: wipe/hang. G-unlock: pass the lock. |
| **Out of scope** | Power/EM side channels, breaking AES, invasive probing, glitch fault injection, software exfiltration. |
| **Defense goals (locked)** | No sensitive bit reaches `scan_out` (read); no attacker value reaches any key/plaintext/control register (write); lock resists guessing; unlocked = identical to undefended; AES functionally unchanged always. |

---

## 4. System architecture (verified against RTL)

```
PicoRV32 (unmodified) --PCPI--> aes_pcpi --> aes_core (iterative AES-128, 1 round/cycle)
custom-1 opcode 0101011, funct3: 000 LOADKEY 001 LOADBLOCK 010 ENCRYPT 011 READRESULT 100 STATUS
```

**Global 645-bit scan chain (front → back):**

| Segment (module) | Bits | Global range | Sensitive? |
|---|---|---|---|
| `key_stage` (aes_pcpi) | 128 | [127:0] | key residue (see A3) |
| `block_stage` (aes_pcpi) | 128 | [255:128] | plaintext (write-sensitive) |
| `fsm_state` (aes_pcpi) | 1 | [256] | control |
| `round_reg` (aes_core) | 4 | [260:257] | control |
| `state_reg` (aes_core) | 128 | [388:261] | round state (key-bearing early rounds) |
| `round_key_reg` (aes_core) | 128 | [516:389] | **yes** (= K10 at DONE) |
| `key_reg` (aes_core) | 128 | [644:517] | **yes** (master key) |

Protected key material = **256 of 645 bits (39.7%)**; the rest is shared SoC
state. (Put this as a bar chart — it is the "shared chain" exhibit.)

---

## 5. The attacks (each verified this session)

KAT key `000102030405060708090A0B0C0D0E0F`, plaintext
`00112233445566778899AABBCCDDEEFF`, ciphertext
`69C4E0D86A7B0430D8CDB78070B4C55A`. Attacker key (EVIL)
`0F1E2D3C4B5A69788796A5B4C3D2E1F0`.

### A1 — Scan-read key recovery (baseline; Paper 1's attack)
Load KAT, freeze mid-encryption, shift 645 bits out of `scan_out`, read
`captured[644:517]`. **Testbench:** `tb_scan_attack.v`, `tb_attack_matrix.v`.
```
Recovered key:  000102030405060708090a0b0c0d0e0f
RESULT: KEY RECOVERY SUCCESS
SECONDARY SEARCH: 2 matching window(s) found   (key_reg and the key_stage residue)
```
Blocked by Paper 1's output mask (G1).

### A3 — Key + plaintext injection (headline) **[new]**
128 scan shifts write EVIL into `key_stage` while `locked=1` (never unlocked);
the same shift pushes the old key into `block_stage`. `ENCRYPT` then runs on the
attacker's pair. **Testbench:** `tb_attack_write_inject.v`, `tb_attack_defenses.v`,
`tb_attack_top_def.v`. Golden (pycryptodome):
`AES(EVIL, 000102..0f) = 50b58e80ce784e98ad48d63390c5dfd7` — matches the DUT.

### A2 — Ciphertext spoof **[new]**
Shift a chosen value into `state_reg`; a bare `READRESULT` (no ENCRYPT) returns
it to the CPU as a forged ciphertext. Works in G0 and G1. **Testbench:**
`tb_attack_modeswitch.v` (M3-A/M3-B), `tb_attack_defenses.v` (A2/A2c).

### A6 — Zeroize / DoS **[new]**
Shifting while locked feeds 0 into `round_key_reg` (128 shifts) and `key_reg`
(256). `AES(0,0) = 66e94bd4ef8a2c3b884cfa59ca342b2e` (pycryptodome).
`round_key_reg===0 && key_reg===0` asserted directly. **Testbench:**
`tb_zeroize.v` (97 checks).

### A4 — Unlock brute force
v1 lock = one guess/clock, no limiter, public default `DEC0DED1`; worst case
2³² = 42.95 s @100 MHz **[inference from the measured cost model]**.
**Testbench:** `tb_attack_bruteforce.v` (14 checks).

### A5 — CPU register-file read
Deferred (appendix) — needs the register file in the chain.

---

## 6. The defenses

All variants are one parameter in `aes_pcpi_def`/`aes_core_def`:
`DEFENSE_LEVEL` = 1 (G1) / 2 (G2) / 3 (G3) / 4 (G4) / 5 (G2R); 0 = original.

| ID | Mechanism | Verdict (measured) |
|---|---|---|
| **G0** | undefended (`locked=0`) | all attacks succeed |
| **G1** | Paper 1: `scan_out = locked ? 0 : …`; only `round_key_reg` scan-in gated | blocks **read only** |
| **G2** | granular masking: freeze sensitive segments, keep tail observable | read-safe; tail still writable → plaintext corrupts, ENCRYPT can hang |
| **G3** | flush all registers on a `scan_en` edge while locked | defeated by holding `scan_en` high (A2c); one shift zeroizes the key |
| **G2R** | like G2 but the tail recirculates (observable, not injectable) | can't choose the value, but rotation still corrupts; still hangs |
| **G4** | **freeze the whole chain while locked** (`scan_en` forced 0) + `scan_out` masked | **blocks every asserted attack** |
| **L1** | hardened unlock controller: attempt lockout + boot delay, secret on a port (no public default) | ~45 yr worst case at default params **[inference from a formula verified at scaled params]** |

**The G4 security gate (combinational, lock-only, shift-count-independent):**
```verilog
wire scan_en_sens = (scan_en & ~locked);   // frozen while locked
wire seg_out_muxed = locked ? 1'b0 : seg_tap[4];   // masked while locked
```
Masking, not encryption: while locked `scan_out` is a constant 0 — nothing to
invert. The functional (`scan_en=0`) path never sees `locked`, so AES runs
normally. **Recommended paper design: G4 + L1; G1/G2/G3/G2R are ablations.**

---

## 7. Verification results (all re-run this session)

### 7.1 Attack × design matrix (`tb_attack_defenses.v`, 58 checks)
```
  attack      | G0        | G1        | G4 locked | G2        | G3        | G2R
  A1 read     | SUCCEEDS  | BLOCKED   | BLOCKED   | BLOCKED   | BLOCKED   | BLOCKED
  A2c spoof   | SUCCEEDS  | SUCCEEDS  | BLOCKED   | n/a       | SUCCEEDS  | BLOCKED
  A3 inject   | SUCCEEDS  | SUCCEEDS  | BLOCKED   | PARTIAL   | WIPE      | ROTATE
  A6@1 zero   | intact    | intact    | intact    | intact    | ZEROED    | intact
```

### 7.2 Through the real CPU + real lock (`tb_attack_top_def.v`, 105 checks)
```
  config        | none    | A1 read | A2 spoof | A3 inject | A6 wipe
  G0 (no lock)  | KAT ok  | LEAKS   | SUCCEEDS | SUCCEEDS  | SUCCEEDS
  G1 + L1       | KAT ok  | BLOCKED | SUCCEEDS | SUCCEEDS  | SUCCEEDS
  G4 + L1       | KAT ok  | BLOCKED | BLOCKED  | BLOCKED   | BLOCKED
  G4 + L1 (unlk)| KAT ok  | LEAKS   | SUCCEEDS | SUCCEEDS  | SUCCEEDS
```
Only **G4 + L1** blocks all four; G4 unlocked = G0 (defense is inert when
authorized).

### 7.3 Functional cost = zero
`tb_scan_lock.v`: `RESULT: PASS - functional AES correct while LOCKED` (KAT
bit-exact). `tb_def_functional.v`: KAT + back-to-back KAT, L1–L5, locked and
unlocked (10/10). `tb_cpu_driven_aes_def.v`: real CPU program on all 18
DEFENSE_LEVEL × LOCK_VERSION configs → `ALL TESTS PASSED (18 configurations)`.
`tb_defense_equiv.v`: unlocked variants cycle-identical to the original over
900 random cycles.

### 7.4 T1 — testability while locked (`tb_testability_t1.v`)
```
DL0/G1 : writable=388/645  observable=0     <- read-locked but WRITE-OPEN
G2     : writable=132/645  observable=133   <- tail only
G3     : writable=388/645  observable=0
G4     : writable=0/645    observable=0     <- fully closed
G2R    : writable=0/645    observable=133*  (*recirculates; observable-not-writable)
```
Headline number: **Paper 1 hides 100% on read yet leaves 388/645 writable; G4
closes both.**

### 7.5 T2 — chain integrity + stuck-at (`tb_testability_t2.v`)
```
flush recovered UNLOCKED/LOCKED:  G0 645/0  G1 645/0  G2 645/133  G3 645/0  G4 645/0  G2R 645/0
stuck-at faults injected=10 detected=10
```
**Every variant is fully testable unlocked (645/645); G4's cost is only that
the chain is frozen while locked.** Stuck-at faults are caught by a flush test.

### 7.6 Formal (SymbiYosys, `formal/readlock.sby`)
Property: in G4, `locked |-> scan_out == 0`, all inputs free.
```
engine_0.basecase: pass     engine_0.induction: pass     DONE (PASS)
```
**Unbounded** (k-induction), i.e. proven for all inputs and all time, not just a
bounded depth. Next: write-side non-interference (two key copies) + a failing
negative control.

### 7.7 Mutation testing (tests are not vacuous)
`mutate.py` 12/12 mutants caught; +2 mutants on the new top-level/resume tbs
caught; +1 on the board tb caught. Evidence the testbenches detect real RTL
bugs, not just pass.

### 7.8 Full regression
`./run_regression.sh` → `SUMMARY passed=30 failed=0 total=30` (Icarus 12.0).

---

## 8. File inventory (what each file does)

### RTL — original (unchanged from Paper 1 baseline)
| File | Role |
|---|---|
| `picorv32.v` | RV32I core, byte-identical to upstream |
| `aes_pcpi_defs.vh` | custom-1 opcode + funct3 encodings |
| `aes_sbox.v`, `aes_core.v`, `aes_pcpi.v` | AES engine + PCPI wrapper (scan-retrofitted) |
| `scan_cell.v`, `scan_chain.v` | 1-bit scan flop; parameterized scan register |
| `scan_lock_controller.v` | v1 lock: 32-bit compare, fail-safe locked, public default `DEC0DED1` |
| `secure_scan_rv_top_v2.v` | Paper 1 top (CPU+AES+mem+lock, `SECURE_SCAN`) |
| `scan_attack_harness.v`, `fpga_top.v`, `io_conditioning.v` | read-attack demo + board I/O front-end |
| `board_top.v`, `lock_switch_ctrl.v`, `scan_dump_controller.v`, UART/7-seg/reset | Paper 1 board demo |

### RTL — new in Paper 2
| File | Role |
|---|---|
| `aes_core_def.v`, `aes_pcpi_def.v` | defense variants (`DEFENSE_LEVEL` 1–5); logic identical to originals at DL that matches, gates added |
| `scan_lock_controller_v2.v` | L1 lock: attempt lockout, boot delay, `secret_i`/`secret_valid_i`, `lockout_o`, optional hard lockout |
| `secure_scan_rv_top_def.v` | parameterized top: `DEFENSE_LEVEL` 0–5 × `LOCK_VERSION` 0/1/2 (for overhead sweeps + CPU tests) |
| `board_top_def.v` | **board demo**: G1 + G4 on one bitstream, UART console, `sw[0]` selects |
| `scan_uart_bridge.v`, `uart_rx.v` | UART command console (PCPI master + scan driver) + receiver |

### TB — attacks
`tb_scan_attack.v` (A1), `tb_attack_matrix.v` (A1–A6 G0/G1 table),
`tb_attack_write_inject.v` (A3), `tb_attack_modeswitch.v` (A2 spoof),
`tb_zeroize.v` (A6), `tb_attack_bruteforce.v` (A4), `tb_attack_probe.v`
(informational go/no-go).

### TB — defenses / verification
`tb_attack_defenses.v` (7-column attack×defense, 58 checks),
`tb_defense_equiv.v` (unlocked equivalence), `tb_def_functional.v` (KAT per
variant), `tb_scan_resume_def.v` (resume, L1–L5), `tb_cpu_driven_aes_def.v`
(real CPU × 18 configs), `tb_attack_top_def.v` (attacks through the top),
`tb_testability_t1.v` (T1), `tb_testability_t2.v` (T2), `tb_lock_v2.v` /
`tb_scan_lock_v2.v` (L1 lock), plus the Paper 1 suite
(`tb_scan_cell/chain/aes_core/aes_pcpi/scan_lock/double_encrypt_control/
scan_resume/keystage_lock_scope/cpu_driven_aes/scan_attack_harness/fpga_top/
board_top/sensitivity`).

### Formal / tooling / docs
`formal/fv_readlock.v` + `formal/readlock.sby` (G4 read-lock proof),
`run_regression.sh` (30 gated tbs), `mutate.py` (mutation runner),
`scripts/scan_console.py` (host UART console), `docs/*` (this file,
`board_demo.md`, `claims_to_evidence.md`, `CHANGES_since_first_zip.md`).

---

## 9. Board demo (live hardware story)

`board_top_def.v` + `CONSTRAINTS/board_top_def.xdc` on the Boolean Board
(XC7S50). One bitstream carries a G1 and a G4 instance sharing one L1 lock;
`sw[0]` selects which the UART console (115200 8N1) drives. Verified in sim by
`tb_board_top_def.v` (9/9), including the headline:
```
G1 injected ciphertext = 50b58e80ce784e98ad48d63390c5dfd7   (attack succeeds)
G4 injected ciphertext = 69c4e0d8...   (true KAT; attack blocked)
```
Commands: `S` status · `R` scan-read (all zeros locked) · `W<hex>` inject ·
`K`/`B` load · `E` encrypt · `U<hex>` unlock · `L` relock. See
`docs/board_demo.md` and `scripts/scan_console.py --demo`.

**[[FILL — board results you will capture]]**
- Serial-terminal transcript of the `--demo` run (G1 changes, G4 holds).
- Photo/screenshot: locked `R` all-zeros vs unlocked key.
- LED/RGB state photos (locked vs unlocked).

---

## 10. Implementation / synthesis results — **MEASURED (Vivado, Spartan-7 XC7S50-CSGA324)**

Top `secure_scan_rv_top_def`, clock-only XDC, 100 MHz target (10.000 ns),
one implementation run per row (single seed — a ≥3-seed spread is still
optional, see note). All rows **meet timing** (WNS > 0, TNS = 0, 0 failing
endpoints). Fmax = 1 / (10 ns − WNS). Deltas are vs the G0 baseline.

**Table A — overhead (`secure_scan_rv_top_def`):**

| Config | DL / LV | LUT | ΔLUT | FF | ΔFF | BRAM | DSP | WNS (ns) | Fmax (MHz) |
|---|---|---|---|---|---|---|---|---|---|
| G0 undefended | 0 / 0 | 2830 | — | 1225 | — | 1 | 0 | 2.231 | 128.7 |
| G1 Paper-1 lock | 1 / 1 | 2844 | **+14** | 1226 | **+1** | 1 | 0 | 2.401 | 131.6 |
| G4 write-block | 4 / 1 | 2843 | +13 | 1226 | +1 | 1 | 0 | 1.926 | 123.9 |
| **G4 + L1 (proposed)** | 4 / 2 | 2888 | **+58** | 1260 | **+35** | 1 | 0 | 1.843 | 122.6 |

Percent overhead of the full design (G4+L1) vs baseline: **+2.05 % LUT,
+2.86 % FF, 0 BRAM, 0 DSP.** Fmax stays **>120 MHz**, comfortably above the
100 MHz target (slack +1.84 ns).

**Table B — board demo build (`board_top_def`, `board_top_def.xdc`):**
6111 LUT (18.75 %), 3539 FF (5.43 %), 0 BRAM, WNS 1.922 ns → 123.8 MHz,
bitstream built **Y** (two coprocessors G1+G4 + UART console + lock on one
device).

**Reading / headline numbers for the paper:**
- **Sanity gate PASSED:** G1 here is **+14 LUT / +1 FF** over baseline —
  *identical* to Paper 1's reported "+14 LUT / +1 FF", and the baseline
  (2830 LUT / 1225 FF) matches Paper 1's 2,828 / 1,225 to within 2 LUTs. The
  setup is faithful, so the rest of the table is trustworthy.
- **G4 costs essentially the same as G1** (+13 vs +14 LUT, +1 FF each): full
  scan-**write** blocking is **as cheap as** Paper 1's read-only masking. This
  is a strong result — the stronger defense is not more expensive.
- **The lock hardening (L1) is the only visible cost:** G4→G4+L1 adds +45 LUT
  / +34 FF (the attempt counter, lockout and boot-delay registers). Still only
  ~2 % of the design.
- **No timing penalty that matters:** every variant closes 100 MHz with
  >1.8 ns slack; the ~5 % Fmax spread across variants is placement noise at
  this utilization (report it as a range, not a trend — and see the ≥3-seed
  note).

Source reports: `final_reports/{util,timing}_DL0_LV0`, `_DL1_LV1`, `_DL4_LV1`,
`_DL4_LV2`, `_board_top_def`.

> **Optional polish (not required):** re-run Implementation 3× per row with
> different strategies/seeds and report mean/min/max for LUT/FF/Fmax. This
> turns the single Fmax values into a spread and directly fixes Paper 1's
> "Fmax asserted, not shown" erratum. The area numbers barely move; it mainly
> firms up the Fmax column.

---

## 11. What YOU need to do (owner checklist)

**On the board (Spartan-7):**
1. Vivado: add all `RTL/*.v` + `aes_pcpi_defs.vh`; set **`board_top_def`** as top;
   add **`CONSTRAINTS/board_top_def.xdc`**; generate bitstream; program.
2. Open serial 115200 8N1 (or `python3 scripts/scan_console.py --port <COM> --demo`).
3. Capture the demo: locked `R` = zeros; `sw[0]=0` (G1) inject → `50b58e80…`;
   `sw[0]=1` (G4) inject → KAT. Save the transcript + photos → §9 [[FILL]].

**Synthesis / overhead:** ✅ DONE — all 4 configs + board build measured (§10).
   Reports in `results/vivado/`. Only optional polish left: ≥3-seed spread for
   the Fmax column (§10 note).

**Housekeeping:**
6. Reconnect GitHub (https://claude.ai/connect-github) + install the Claude app on
   the repo so the commits can be pushed off this container.
7. Confirm the two **decisions**: (a) defense ladder = G4+L1 proposed, G2/G2R/G3
   ablations? (b) target venue / page limit (sets formal depth).

**Optional (I can do any in-session):** write-side non-interference formal proof +
negative control; LBIST mode (secure *and* testable while locked); adaptive
multi-session attacks; T3 ATPG fault coverage.

---

## 12. IEEE paper skeleton → evidence map

1. **Abstract** — §1.
2. **Introduction** — shared-chain scan threat; "design, implement, verify, formally check."
3. **Related Work** — §2 + §13 refs; position vs DefScan; reject LFSR via GF-Flush.
4. **Threat Model** — §3 table.
5. **Architecture** — §4 (block diagram + 645-bit map bar chart).
6. **Attacks** — §5 (A1 read, A3 inject = headline, A2 spoof, A6 zeroize, A4 brute force), each with its verified output and golden.
7. **Defense Design** — §6 (why masking not obfuscation; G4 gate; the ablation ladder; L1).
8. **Verification** — §7: attack×defense matrices (7.1/7.2), zero functional cost (7.3), T1 (7.4), T2 (7.5), formal (7.6), mutation (7.7). Largest section.
9. **Board demo** — §9 + photos.
10. **Overhead** — §10 Table A once synthesized.
11. **Discussion / Limitations** — over-masking scope; G4 freezes the chain while locked (T1 trade-off, LBIST as future work); attacks characterized for constant/EVIL feeds and single freeze points; lock secret is a bitstream constant; formal is read-side so far.
12. **Conclusion** — restate the scan-write contribution + G4; don't re-claim masking itself.

---

## 13. References

**Confirmed this session (cite as-is):**
- B. Yang, K. Wu, R. Karri, "Scan based side-channel attack on dedicated hardware implementations of DES," *ITC* 2004, 339–344.
- B. Yang, K. Wu, R. Karri, "Secure scan: a design-for-test architecture for crypto chips," *DAC* 2005 / *IEEE TCAD* 25(10) 2006, 2287–2293.
- J. DaRolt, G. Di Natale, M.-L. Flottes, B. Rouzeyre, "Scan attacks and countermeasures in presence of scan response compactors," *ETS* 2011, 19–24.
- J. DaRolt et al., "Thwarting scan-based attacks on secure-ICs with on-chip comparison," *IEEE TVLSI* 22(4) 2014, 947–951.
- J. Lee, M. Tehranipoor, J. Plusquellic, "A low-cost solution for protecting IPs against scan-based side-channel attacks," *VTS* 2006, 94–99.
- A. Das, B. Ege, S. Ghosh, L. Batina, I. Verbauwhede, "Security analysis of industrial test compression schemes," *IEEE TCAD* 32(12) 2013, 1966–1977.
- DefScan (Ray et al.), *IEEE TCAD* 2024, DOI 10.1109/TCAD.2024.3368289 — **closest prior art; position against it.**
- ScanSAT, "Unlocking static and dynamic scan obfuscation," arXiv:1909.04428 — justifies rejecting LFSR locks.
- E. Biham, A. Shamir, "Differential fault analysis of secret-key cryptosystems," *CRYPTO* 1997.
- P. Dusart, G. Letourneux, O. Vivolo, "Differential fault analysis on AES," *ACNS* 2003, 293–306.
- M. Doulcier, M.-L. Flottes, B. Rouzeyre, "AES-based BIST," *VTS* 2007 — cite if LBIST is added.
- YosysHQ Yosys + SymbiYosys (formal toolchain); Z3 (de Moura, Bjørner, *TACAS* 2008).

**Confirm authors/venue/pages before citing (from the ideas-doc screening pass):**
- "Securing Cryptographic Chips against Scan-Based Attacks…," *Sensors* 19(20) 2019, 4598.
- "Enhancing Sensor Network Security with Improved Internal Hardware Design," *Sensors* 19(8) 2019, 1752.
- "Novel Test-Mode-Only Scan Attack… Compression-Based Scan," *IEEE TCAD* 2015, DOI 10.1109/TCAD.2015.2398423.
- Y. Sao, K. K. Soundra Pandian, S. Subidh Ali, "Revisiting static masking and compaction… improved scan attack on AES," *AsianHOST* 2020.
- "Secure Scan Architecture Based on Hidden Authorization and Dynamic Replacement," *J. Electronic Testing* (Springer) 2026.
- RISC-V crypto-coprocessor context (FAC-V, AFTAB, Crypto-RV) — to establish tightly-coupled coprocessors as a real area.

### Paper 1 errata to fix while writing related work
- "Segmented" vs the RTL's whole-coprocessor blanking; "every scan-relevant register is a scan primitive" overstated (`fsm_state`, `start_i_reg`, `core_seen_running` are plain regs); refs [17]/[18] don't support their sentences; [15]/[16] never cited; Fig. 3 caption → Table II; "zero functional overhead" next to a ~5% Fmax drop → say "zero effect on encryption correctness"; Fmax-from-placer asserted not shown (run seeds); soften "first reconstruction of the 645-bit segment from live hardware"; verify the DefScan author list.

---

## 14. Reproducibility / methodology (one paragraph for the paper)

All simulation: Icarus Verilog 12.0, one command `./run_regression.sh` (30 gated
testbenches, each compiled against all RTL, pass only on its `ALL TESTS PASSED`
banner with no failure/timeout marker; a missing/uncompilable/timed-out tb is a
FAIL). Ciphertext goldens checked against pycryptodome. Tests validated by
mutation (deliberate RTL bugs; all caught). Formal: Yosys 0.33 + Z3 4.8.12 +
SymbiYosys, `mode prove` (k-induction). **Tool note:** `tb_scan_attack.v` uses
`matches` as an identifier (reserved under `-g2012`), so the suite compiles with
default language flags — a flag choice, not an RTL defect.

---

## 15. Key constants (appendix)

| Name | Value |
|---|---|
| KAT key | `000102030405060708090A0B0C0D0E0F` |
| KAT plaintext | `00112233445566778899AABBCCDDEEFF` |
| KAT ciphertext | `69C4E0D86A7B0430D8CDB78070B4C55A` |
| K10 (of KAT key) | `13111D7FE3944A17F307A78B4D2B30C5` |
| Attacker key (EVIL) | `0F1E2D3C4B5A69788796A5B4C3D2E1F0` |
| A3 injected ciphertext | `50b58e80ce784e98ad48d63390c5dfd7` = AES(EVIL, 000102..0f) |
| A6 zeroized ciphertext | `66e94bd4ef8a2c3b884cfa59ca342b2e` = AES(0,0) |
| v1 default unlock code | `DEC0DED1` |
| Board L1 secret (demo) | `5EC2E7A1` |
| Chain / protected | 645 bits / 256 protected (39.7%) |
