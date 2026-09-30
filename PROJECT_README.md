# SecureScan-RV — Paper 2 Master README

**Use this file as the single source of truth for this project.** It supersedes
`README_paper2_ideas.md` (kept only as a brainstorming/novelty-check history —
see §12) and the `SecureScan-RV_Paper2_README_PRD_v2.md` upload (kept only as
the original planning changelog — its content is folded in here, current as
of the date below).

> **Session update (30 Sep 2026, third Phase 5 session, this repo) -- read this first.**
> Project now lives in git (`RTL/`, `TB/`, `CONSTRAINTS/` layout). Everything below was run here with Icarus 12.0 on the project RTL as uploaded:
> (1) `run_regression.sh` rewritten for the `RTL/`+`TB/` layout (the copy in the upload was still the old flat-directory 16-tb script). Full run of the 24 previously gated tbs: **`SUMMARY passed=24 failed=0 total=24`**; `tb_attack_defenses` PASS lines identical to the saved `tb_attack_defenses.log` (58 PASS). Gate negative control: a missing tb reports MISSING and exits 1.
> (2) NEW `secure_scan_rv_top_def.v`: CPU + AES top with `DEFENSE_LEVEL` (0 = original datapath, 1-5 = `_def` variants) and `LOCK_VERSION` (0 none, 1 v1, 2 `scan_lock_controller_v2`). **L1 is now wired into a top-level** (simulation only; not synthesized).
> (3) NEW `tb_cpu_driven_aes_def.v`: real-CPU KAT on all 18 DEFENSE_LEVEL x LOCK_VERSION configs + locked/unlocked scan read + v2 lockout at top level: **144 PASS / 0 FAIL, 18/18 configs**. NEW `tb_scan_resume_def.v`: the unchanged 20-case resume sweep on L1-L5: **100/100 OK**. Each has a mutant that it catches (s5g).
> (4) Legacy `secure_scan_rv_top.v` deleted. Line-by-line read of `*_def.v`: no functional defect found, 4 notes (s5g). **Full regression: `SUMMARY passed=26 failed=0 total=26`.**
>
> **Previous session update (30 Sep 2026, second Phase 5 session):**
> Phase 5 is still IN PROGRESS. Measured this session (Icarus 12.0, single-core sandbox; every result below was produced by running the project RTL, and the G2/G3/G2R probe was re-run and matched the saved `probe3.log` line for line):
> (1) `tb_attack_defenses.v` now has 7 columns (G0, G1, G4 locked, G4 unlocked, **G2, G3, G2R locked**) and **58 asserted checks, 0 fail**. Goldens for G2/G3/G2R injection cases were checked against pycryptodome.
> (2) New `tb_def_functional.v`: KAT bit-exact and back-to-back KAT for all five `_def` variants, locked and unlocked (10 cells PASS).
> (3) `run_regression.sh` rebuilt: **24 gated tbs** (see s3 note and s5f for the result of the full run).
> (4) Mutation results for the new G2/G3/G2R assertions: s5f.
> Headline findings: **G2 and G2R are NOT write defenses** (the tail stays scan-writable; G2R rotates instead of accepting values but still corrupts). **G3 fails when `scan_en` is held high** (flush is edge-triggered) and is the cheapest DoS (one shift zeroizes the key). **Only G4 blocks every asserted row.**
> NOT done: L1 wiring into a top-level, `tb_cpu_driven_aes` on any variant, formal work, Vivado numbers, line-by-line review of `*_def.v`, T1 testability metric. Provenance caveat unchanged: `aes_core_def.v`/`aes_pcpi_def.v` were regenerated from a recorded script (s3, s5f).

**Last verified:** 29 Sep 2026, by an independent Icarus Verilog 12.0 run
against the real project RTL (not just re-reading a prior claim). This
session's Phase 2 re-verification: `tb_attack_bruteforce.v` re-run
(14/14 checks PASS, ~12.6 s wall), `tb_lock_v2.v` written fresh and run
(25/25 checks PASS, 10 mutants injected into `scan_lock_controller_v2.v`
and all 10 caught FAIL, unmutated control 0 FAIL), `tb_scan_lock_v2.v`
written fresh replacing the empty stub (17/17 checks PASS, drives the
unmodified `aes_pcpi`/`aes_core`). `run_regression.sh` extended from 16 to
19 gated testbenches (`tb_attack_bruteforce`, `tb_lock_v2`, `tb_scan_lock_v2`
added) and re-run in full: 19/19 PASS at that point (superseded: now 21 gated, 21/21 PASS, see Phase 4 status above).
**Phase 4 status (29 Sep 2026): DONE** -- `tb_attack_modeswitch.v` (owner-written, reviewed and corrected) and new `tb_attack_matrix.v` (attack x design table, G0/G1) both gated; `run_regression.sh` now 21 gated, **full run 21/21 PASS (Icarus 12.0, ~9 min wall)**. **Open decision 1 RESOLVED: plaintext IS write-sensitive** (Phase 5 unblocked; see s10). **Phase 2 status (29 Sep 2026): DONE.** A4 brute-force cost re-measured this
session against v1 (§5d); L1 hardening (`scan_lock_controller_v2.v`) verified
this session as a standalone unit test AND integrated against the real
AES datapath for the first time (§5d).
**Phase 1 status (29 Sep 2026):** `tb_zeroize.v` passes in Icarus 12.0 (97 checks,
0 fail); `tb_attack_write_inject.v` passes both in the owner's Vivado run and in Icarus 12.0;
(Phase 1 point-in-time: 16/16 PASS.) **Phase 3 (sensitivity map) DONE — see §5c/§8.** `picorv32.v`
verified byte-identical to upstream master (0 diff lines). See §5b.
**Priority:** highest — no other projects currently active.
**Owner:** Madhavan R (Maddy), final-year ECE, Saveetha Engineering College.

---

## 1. What this project is

**Paper 1** (submitted): *Segmented Secure Scan Lock for a PCPI-Coupled AES
Coprocessor on a RISC-V Processor.* PicoRV32 + custom AES-128 coprocessor over
PCPI, a 645-bit scan chain, a lock that masks the coprocessor's `scan_out` to
0 while locked. Shown to defeat a scan-**read** attack. Verified in Vivado
simulation, formal-ish testbench regression, and on real Spartan-7 hardware
(Boolean Board, xc7s50csga324-1).

**Paper 2** (in progress, this document's subject): *From "Locking Scan
Output" to "Securing Scan Read and Write."* Paper 1 only defended
observability (reading the chain). Paper 2 shows the same lock does **not**
defend controllability (writing the chain), demonstrates a confirmed,
independently-verified write-side attack, builds a sensitivity map of which
scan bits actually carry secret information, and designs + evaluates a
granular, write-blocking defense.

**One-line thesis:** *Securing scan observability alone is insufficient. A
coprocessor behind a scan-read lock remains vulnerable to scan-write
key/plaintext injection and zeroize attacks — confirmed by simulation, not
hypothesized. A register-granular, write-blocking defense with a hardened
lock closes them, is analyzed under a reduced-model formal proof, and costs
little.*

---

## 2. Architecture (as built, verified against real RTL)

```
picorv32 (CPU, unmodified) --PCPI--> aes_pcpi ---------------------------------+
                                      scan chain, front -> back:                |
                                      key_stage[128]    (staging copy of key)   | <- scan_in NEVER
                                      block_stage[128]  (staging copy of pt)    |    gated by `locked`
                                      fsm_state[1]      (aes_pcpi IDLE/BUSY)    |
                                   -> aes_core                                  |
                                      round_reg[4]                              | <- scan_in NEVER
                                      state_reg[128]                           |    gated by `locked`
                                      round_key_reg[128] <- scan-in FORCED TO 0 when locked (ONLY gated register)
                                      key_reg[128]
                                      -> seg_out_muxed = locked ? 0 : seg_tap[4] -> scan_out
scan_lock_controller --locked--> aes_core (two combinational muxes: seg_in_muxed, seg_out_muxed)
```

Global 645-bit map:

| Segment | Bits | Global range | scan-in gated while locked? |
|---|---|---|---|
| key_stage | 128 | [127:0] | **No** |
| block_stage | 128 | [255:128] | **No** |
| aes_pcpi fsm_state | 1 | [256] | **No** |
| round_reg | 4 | [260:257] | **No** |
| state_reg | 128 | [388:261] | **No** |
| round_key_reg | 128 | [516:389] | **Yes** |
| key_reg | 128 | [644:517] | No direct gate; only reachable by shifting through round_key_reg |

Convention: LSB-first shift; `scan_out` is a combinational tap of the last
cell, so a full **read** capture needs 1 pre-shift sample + 644 shifts. A
**write** into `key_stage` needs only 128 shifts — it's the first register in
the chain.

---

## 3. File inventory (verified against the actual project this session)

| File | Role | Status |
|---|---|---|
| `picorv32.v` | Reference RV32I core | Present, **byte-identical to YosysHQ/picorv32 master** (fetched 29 Sep 2026; diff ignoring CRLF = 0 lines). Compared against master, not a tagged release — record the upstream commit hash when tagging the baseline. `PICORV32_REGS` hook present (appendix extension only). |
| `aes_pcpi_defs.vh` | custom-1 opcode + funct3 encodings | Present, stable |
| `aes_sbox.v`, `aes_core.v`, `aes_pcpi.v` | AES engine + PCPI wrapper, scan-retrofitted | Present, compiles, passes regression unmodified |
| `scan_cell.v`, `scan_chain.v` | 1-bit scan flip-flop, parameterized register | Present, verified |
| `scan_lock_controller.v` | 32-bit static-code lock, fail-safe locked | Present. No attempt limiter. Public default code `32'hDEC0DED1` (hardcoded, verified present in RTL). |
| `secure_scan_rv_top_v2.v` | Real top: CPU + AES + memory + lock; `SECURE_SCAN` param | Present, compiles |
| `secure_scan_rv_top.v` | Legacy v1 top, no scan/lock ports | **Deleted** (30 Sep 2026, third Phase 5 session); nothing referenced it |
| `secure_scan_rv_top_def.v` | **NEW.** Same CPU/AES/memory as `_v2`, plus `DEFENSE_LEVEL` (0 = original `aes_pcpi`, 1-5 = `aes_pcpi_def`) and `LOCK_VERSION` (0 none, 1 v1, 2 `scan_lock_controller_v2` with `secret_i`/`secret_valid_i`/`lockout_o`). `_v2` left untouched as the Paper 1 baseline. | PASS via `tb_cpu_driven_aes_def` (s5g). Not synthesized |
| `tb_sensitivity.v` + `phase3/analyze_sensitivity.py` | Phase 3 sensitivity map (645 bits x 16 capture points x 32 random pairs), scan-equivalence check, F5/F6 direct checks | **NEW, PASS (Icarus 12.0). Outputs in `phase3/`:** `sens_perbit_classified.csv`, `sens_segment_summary.txt`, `sens_direct_checks.txt`, `sens_heatmap.png`, raw `sens_bits.csv`, `kat_snaps.txt` |
| `run_regression.sh` | One-command Icarus regression for the `RTL/`+`TB/` layout, **26 gated tbs** (list in s5g). Each tb runs in its own dir under `.reg_work/`; `JOBS=N` for parallel runs; optional tb names as arguments | Result of the full run: s5g. `tb_attack_probe.v` and `probe_g235.v` are informational, not gated |
| `scan_attack_harness.v`, `fpga_top.v`, `io_conditioning.v` | Read-attack demo + board I/O front-end | Present, pass |
| `board_top.v`, `lock_switch_ctrl.v`, `scan_dump_controller.v`, UART/7-seg/reset support | Board demo | Present, pass |
| `CONSTRAINTS/constraints.xdc` | Boolean Board pins | Present |
| 13 original Paper 1 `tb_*.v` testbenches | Part of the regression | All pass (s5g) |
| `tb_attack_probe.v` | Paper 2's go/no-go probe (A3/A6) | **Present, independently re-run, results confirmed — see §5** |
| `tb_zeroize.v` | F3/A6 regression: exact 645-bit model comparison, locked vs unlocked, 10 shift counts | **NEW, PASS (Icarus 12.0): 97 PASS / 0 FAIL** |
| `tb_attack_write_inject.v` | A3 regression: region-A model sweep (14 shift counts x plaintext LSB 0/1), F8 cases A/B, golden ciphertext | **NEW, PASS in owner's Vivado run and in Icarus 12.0 (via `run_regression.sh`).** `check()` width fixed (§5b) |
| `scan_lock.v`, `tb_coprocessor_scan.v` | Referenced in old notes | **Confirmed absent from the project — nothing to recover, just stale references to delete** |

| `tb_attack_modeswitch.v` | A2 (owner-written; reviewed this session): ungated-window sweep vs 645-bit model at 16 shift counts, M1/M2/M3-A/M3-B | **PASS, 111 checks (Icarus 12.0).** Two defects fixed: `check()` msg width 1024->2048 (truncated the M3-A label), and M3-B had NO assertion and its banner claimed a hang the run refuted (s5e) |
| `tb_attack_matrix.v` | Phase 4: attack x design matrix, G0 (locked=0) vs G1 (locked=1); A1, A2, A3, A6 each asserted per design | **NEW, PASS.** Output table in s5e |
| `scan_lock_controller_v2.v` | L1: attempt counter + lockout + boot delay, no public default code (secret on `secret_i`/`secret_valid_i`), fail-safe locked out of reset | **PASS, re-verified this session (unit test + integration).** Not yet instantiated in any top-level (Phase 5) and not synthesized |
| `tb_attack_bruteforce.v` | A4 against v1: cost model, C0-C6 | **Re-run this session, PASS, 14/14 checks, ~12.6 s wall.** Owner's copy had a truncated C0 message and stale hard-coded throughput; fixed in an earlier session (§5d) |
| `tb_lock_v2.v` | L1 unit test: exact boot-delay/lockout cycle counts, HARD mode, measured attacker cost | **Written and run this session, PASS, 25/25 checks.** Mutation-checked, 10/10 mutants caught (§5d) |
| `tb_scan_lock_v2.v` | v2 driving the unmodified aes_pcpi/aes_core: Phase-7 read attack + KAT in locked/lockout/unlocked | **Written this session (the file in the project was an empty Vivado-generated stub with 0 tests); now PASS, 17/17 checks** |

**Phase 5 files (30 Sep 2026; see s5f for what is and is not verified):**

| File | Role | Status |
|---|---|---|
| `aes_core_def.v`, `aes_pcpi_def.v` | Defense variants selected by `DEFENSE_LEVEL` (1=G1, 2=G2, 3=G3, 4=G4, 5=G2R). Originals `aes_core.v`/`aes_pcpi.v` untouched. | **Regenerated** from a recorded python script because the earlier copies were lost with an old sandbox. Wiring reviewed by grep only. Keep under version control. |
| `tb_attack_defenses.v` | Attack x design matrix, 7 columns: G0, G1, G4 locked, G4 unlocked (negative control), G2, G3, G2R locked. A1, A1b, A2, A2b, A2c, A3, A3b, A3c, A6, A6@1, A7, A8, A9. | **PASS, 58 checks.** Sim time is minutes on a single-core sandbox (about 87 s earlier on a faster one). Gated. |
| `tb_defense_equiv.v` | Lockstep: L1-L5 unlocked vs undefended `aes_pcpi`; L1 locked vs original locked. 900 random cycles, fixed seed. | PASS. Gated. |
| `tb_def_functional.v` | **NEW.** All five `_def` variants x {locked, unlocked}: KAT bit-exact, second KAT with no reset, plus an informational scan-session-then-fresh-KAT case. | **PASS, 10/10 cells.** Gated. |
| `probe_g235.v`, `probe3.log` | Print-only measurement probe over all 7 columns and the log that G2/G3/G2R assertions were written from. | Re-run in the second Phase 5 session, output identical to the saved log. `probe_g235.v` is in this upload; `probe3.log` is not. Informational, not gated. |
| `mutate.py` | Earlier session's mutation runner for the first 12 mutants. | Present in this upload. Written for a flat directory (all `.v` in one folder); see s5g for how it was run here. |
| `tb_cpu_driven_aes_def.v` | **NEW.** Real-CPU program on `secure_scan_rv_top_def`, all 18 DEFENSE_LEVEL x LOCK_VERSION configs | **PASS, 144 checks.** Gated (s5g) |
| `tb_scan_resume_def.v` | **NEW.** `tb_scan_resume`'s 20 cases on L1-L5 (generated from the original; only the DUT, messages and banner changed) | **PASS, 100/100 cases.** Gated (s5g) |

`run_regression.sh` note: the copy in the uploaded project was again the old flat-directory 16-test script (the 24-tb version from the previous session did not make it into the upload). It was rewritten in this repo for the `RTL/`+`TB/` layout and now gates 26 tbs. It requires a PASS banner and no failure marker, and counts a missing, uncompilable or timed-out tb as FAIL. It is now under git, so it should not be lost again.

Project-snapshot discrepancies (this upload): the `phase3/` outputs listed above are not in the upload (`tb_sensitivity` regenerates `sens_bits.csv` and `kat_snaps.txt` into `.reg_work/tb_sensitivity/`; `analyze_sensitivity.py` and the heat map are not in the upload), `probe3.log` is not in the upload, and `tb_scan_lock_v2.v.vivado_stub` is not in the upload. `constraints.xdc` is present under `CONSTRAINTS/`.

**Not yet written (Paper 2 deliverables):** formal `.sby` files, Vivado sweep scripts, synthesis of `secure_scan_rv_top_def`, a board top using `scan_lock_controller_v2`. (T1/T2 done, s5i/s5j; `docs/claims_to_evidence.md` maps every claim to its test.) (The planned `aes_core_g2.v`/`aes_pcpi_g2.v` names were replaced by the `*_def.v` parameterized variants.)

---

## 4. Threat model

| | |
|---|---|
| **Assets** | (1) AES-128 master key and anything it can be recovered from: `key_stage`, `key_reg`, `round_key_reg` (K10, invertible to the master key), early-round `state_reg`. (2) **Integrity** of key, plaintext (write-sensitive by owner decision), ciphertext/state_reg, and control state — now includes plaintext substitution, confirmed exploitable. (3) **Availability** of the coprocessor. |
| **Attacker** | Physical or JTAG/test-port access: controls `scan_en`/`scan_in`, observes `scan_out`, can halt/clock the chip. Knows the RTL and the public default unlock code. May submit many unlock attempts. Can trigger normal-mode cycles. |
| **Public to attacker** | Plaintexts, ciphertexts, the design, the scan map. |
| **Attacker goals** | G-conf: recover key bits. G-int: make the device encrypt under an attacker-chosen key and/or plaintext (**confirmed reachable**). G-avail: wipe or hang the device. G-unlock: pass the lock. |
| **Out of scope** | Power/EM side channels, breaking AES itself, invasive probing, voltage/clock-glitch fault injection, software-level exfiltration. |
| **Defense goals** | While locked: no sensitive bit reaches `scan_out` (read); no attacker-chosen value reaches any sensitive or key/plaintext-consuming register (write); the lock resists guessing; non-sensitive segments stay as testable as possible. Unlocked: identical to undefended. Functional AES unchanged in every case. |

---

## 5. Findings — current verification status

| # | Finding | Status |
|---|---|---|
| F1 | Scan-in is **not gated** while locked for `key_stage`, `block_stage`, `fsm_state`, `round_reg`, `state_reg`. | **VERIFIED** — direct RTL inspection, both `aes_pcpi.v` and `aes_core.v`. |
| F2 | `key_reg` loads from `key_stage` on each `ENCRYPT`; scan-writing `key_stage` then issuing `ENCRYPT` uses the attacker's key. | **VERIFIED — attack executed and independently re-run, see §5a.** Also carries plaintext injection (see F2a). |
| F2a | The same 128-shift injection into `key_stage` also pushes its old contents into `block_stage` — this is a **key + plaintext** injection, not key-only. | **VERIFIED** by independent simulation + independent AES math check (§5a). |
| F3 | Locked shifting feeds 0 into `round_key_reg` (128 shifts) and `key_reg` (256 shifts) — an unintended zeroize side effect. | **VERIFIED** — `tb_zeroize.v` (Icarus 12.0, 97 PASS / 0 FAIL): both registers equal an independent shift model at every tested count and are 0 at >=128 / >=256 shifts; unlocked negative control is non-zero at the same counts. See §5b. |
| F4 | `key_stage` holds the master key permanently after `LOADKEY`, safe today only because of blanket output masking. | **VERIFIED (Phase 3).** All 128 `key_stage` bits are key-dependent at every one of 16 capture points, including after `READRESULT`; `key_stage == master key` checked at LOADKEY-idle (KAT). Not yet tied to a specific G2 design failure — do in Phase 5. |
| F5 | `state_reg` is `block XOR key` after load, then round intermediates. Early-round `state_reg` reveals key material with known plaintext; ciphertext at DONE is public. | **VERIFIED (Phase 3).** `state_reg == P xor K` at ENC+1, asserted in the testbench on the KAT run and 32 random pairs (0 failures); `state_reg` is key- AND plaintext-dependent (128/128 bits) from ENC+1; equals the ciphertext at ENC+11, DONE, after-READ (KAT run). |
| F6 | `round_key_reg` at DONE = K10, invertible to the master key (textbook AES fact). Paper 1's Table II shows K10 on hardware and calls it harmless. | **VERIFIED (Phase 3), against an independent Python key schedule.** RTL `round_key_reg` at DONE = `13111d7f...30c5` = K10; `round_key_reg` tracks RK0..RK10 exactly over ENC+1..ENC+11; inverting K10 in Python recovers `000102...0f`. So K10 is key-equivalent, not harmless — include in Paper 1 errata (§13). |
| F7 | 32-bit static unlock, no attempt limit, public default code (`32'hDEC0DED1`) baked into every top-level instantiation. | **VERIFIED (Phase 2), §5d.** v1 accepts one guess per clock with no limiter; cost is exactly secret+1 guesses (checked at 0, 1, 1000, 65535 and the top 65,536 values). Worst case 2^32 guesses = 42.95 s at 100 MHz is arithmetic from that model, not a 2^32 simulation. Public default is also a zero-effort attack: the code is in the RTL. |
| F8 | Unscanned control regs (`aes_core.fsm_state`, `aes_pcpi.start_i_reg`, `core_seen_running`) keep running during scan; a shifted-along `round_reg` value can trip `is_final_round`. | **Partly verified.** The `aes_pcpi.fsm_state` interaction is confirmed both ways by `tb_attack_write_inject.v` (owner's run): plaintext LSB=0 -> fsm lands IDLE, ENCRYPT accepted, ciphertext `50b58e80...dfd7`; LSB=1 -> fsm lands BUSY and ENCRYPT is not accepted for 50 cycles (availability hazard). The `round_reg`/`is_final_round` spurious-transition path in the unscanned `aes_core.fsm_state` is now **CONFIRMED** by `tb_attack_modeswitch.v` M3-B: after 389 shifts of 1 from a frozen RUNNING core, `aes_core.fsm_state`=DONE with `round_reg_q`=15 (spurious RUNNING->DONE). Consequence is NOT a hang (see s5e). |
| F13 | **Ciphertext spoofing (found during A2).** Scan-shifting 389 bits from a frozen RUNNING core makes `state_reg` fully attacker-chosen. A bare `READRESULT` (no ENCRYPT) then returns that value to the CPU as if it were the AES output: the CPU/software receives a forged ciphertext. Two paths, both asserted in `tb_attack_modeswitch.v`: **M3-A** aes_pcpi lands IDLE (fed=0) and READRESULT is accepted directly; **M3-B** aes_pcpi lands falsely BUSY (fed=1) but the spurious core DONE (F8) clears it in one clock, then READRESULT returns `FFFFFFFF`. Needs no key, no unlock; identical in G0 and G1. | **VERIFIED (Phase 4), s5e.** Integrity impact: software trusting the coprocessor output can be fed a forged result. Not covered by any Paper 1 claim. **G4 must block it; `tb_attack_modeswitch.v` M3-A/M3-B are the regression check for that.** |
| F14 | The predicted M3-B availability hang does NOT occur (refuted by measurement). Spurious `aes_core` RUNNING->DONE via `round_reg`/`is_final_round` is real (F8) but self-heals `aes_pcpi`. | **VERIFIED (Phase 4).** Do not claim a hang in the paper. |
| F9 | Board key/ciphertext display and UART bypass scan and the lock entirely (`dbg_core_*` taps). | True by inspection of `board_top.v` — disclose in the paper, no simulation needed. |
| F10 | Board unlock is a physical switch presenting the fixed code — not real access control. | True by inspection — disclose. |
| F11 | Board scan dump runs after firmware traps; only the sim attack freezes mid-computation. | True by inspection — disclose. |
| F12 | Firmware is hand-assembled hex; key is baked in as `lui`/`addi` immediates. Relevant only if the CPU-register-file appendix extension is attempted. | True by inspection. |

### 5c. Phase 3 sensitivity map results (Icarus 12.0, `tb_sensitivity.v`)

Method as §8: 32 random (Ka,Kb,Pa,Pb) pairs (fixed seed), 3 runs per pair
(Ka,Pa),(Kb,Pa),(Ka,Pb), 16 capture points (LOADKEY-idle, LOADBLOCK-idle,
ENC+0..ENC+11, DONE, after-READ), all 645 chain bits; a bit is key-/plaintext-
dependent if it differed in >=1 of the 32 pairs. Every key-dependent bit
differed in 7 to 26 of 32 pairs. Snapshots are hierarchical reads of the 645
scanned flops; **scan-vs-snapshot equivalence was checked directly at 3 points
(LOADBLOCK-idle, mid-freeze, DONE): full 645-bit scan captures matched — PASS.**

| Segment (width) | Read sensitivity observed |
|---|---|
| `key_stage` (128) | key-dependent at all 16 capture points (128/128 bits) |
| `block_stage` (128) | plaintext-dependent from LOADBLOCK on; never key-dependent |
| `fsm_state` (1), `round_reg` (4) | depend on neither key nor plaintext (timing/control only) |
| `state_reg` (128) | zero until ENC+1; then key- AND plaintext-dependent; equals the public ciphertext at ENC+11/DONE/after-READ |
| `round_key_reg` (128) | key-dependent from ENC+1 through after-READ (= K10 at DONE) |
| `key_reg` (128) | key-dependent from ENC+1 through after-READ |

Counting (bit, capture point) cells: 6656 of 10320 are key-dependent and not
the public ciphertext. Full segment x capture-point table:
`phase3/sens_segment_summary.txt`; heat map `phase3/sens_heatmap.png`; per-bit CSV
`phase3/sens_perbit_classified.csv`.

Observations and limits (state exactly this way):
- **Nothing is cleared after use:** `key_stage`, `key_reg`, `round_key_reg` are still
  key-dependent at the after-READ capture point (the only post-use point sampled).
- **Runs start from reset (all registers 0).** Residue carried across operations
  without a reset is not part of this map.
- "Not public-derivable" is only applied to the ciphertext-equal `state_reg`
  cells; I did not attempt other derivations from (P, C). `state_reg` at ENC+1
  equals P xor K, and `round_key_reg` at DONE is key-equivalent (F5/F6), so those
  are treated as key-sensitive.
- **This is a read-side map only.** Write sensitivity (e.g. `block_stage`, `fsm_state`)
  comes from A3/F2a/F8 (§5a-5b), not from these runs.
- The "2^-32 miss probability" argument assumes a truly key-dependent bit flips
  with probability ~1/2 per random pair; not proved here.

### 5d. Phase 2 — A4 brute force and L1 lock hardening (Icarus 12.0, re-verified this session)

**A4 against v1 (`tb_attack_bruteforce.v`, re-run this session: 14/14 checks PASS, 0 FAIL, ~12.6 s wall).** Measured: 2,000,000 sequential wrong guesses never unlock (C0); 10,000 consecutive wrong guesses, one per clock, no lockout, and the correct code then succeeds immediately (C1/C2); a 1-bit-off and a 32-bit-off guess both leave `locked=1` at the first sample (C3, cycle granularity only; that the compare is a single `==` is by RTL inspection); sequential guessing unlocks at exactly guess = secret for secrets 0, 1, 1000, 65535, secret 0x12345678 is not reached in a 65,536 sweep, and secret 0xFFFFFFFF unlocks exactly on the last guess of the 0xFFFF0000..0xFFFFFFFF sweep (C4/C5).
Derived (not simulated end to end): worst case 2^32 guesses = 42.95 s at 100 MHz. Simulation throughput re-measured this session with a separate 20,000,000-guess run against `scan_lock_controller.v`: 26.84 s wall-clock -> ~0.75 M guesses/s on this machine (Icarus 12.0), so a full 2^32 sweep in simulation would take ~96 min; not run. (Throughput is environment-dependent — an earlier session measured ~1.0 M guesses/s on different hardware; report a range, not a single fixed number, in the paper.)

**L1 (`scan_lock_controller_v2.v`).** Plain gate: one 32-bit compare, counters, no LFSR. (1) No code parameter and no default: reference code arrives on `secret_i`, qualified by `secret_valid_i` (unprovisioned = never unlocks); `grep -v '^\s*//' scan_lock_controller_v2.v | grep -c DEC0DED1` = 0, re-confirmed this session. (2) `MAX_FAILS` consecutive wrong codes start a `LOCKOUT_CYCLES` lockout (attempts ignored, not counted, do not extend it); `HARD_LOCKOUT=1` makes it permanent until reset. (3) `BOOT_DELAY_CYCLES`: attempts ignored after reset, because the counter sits in the reset domain and a reset would otherwise clear it. Fail-safe `locked=1` out of reset, `relock` priority: unchanged from v1.

**Correction to a prior-session claim:** the `tb_scan_lock_v2.v` file actually present in the project was a Vivado-generated empty module (`module tb_scan_lock_v2(); endmodule`, 523 bytes, zero tests) — not the 16-check integration test a prior session's notes described. That prior "PASS (16 checks)" claim could not have come from running this file. Rewritten this session from scratch (kept the empty original as `tb_scan_lock_v2.v.vivado_stub`); see below for what actually runs now.

**`tb_lock_v2.v` (written this session; 25/25 checks PASS, 0 FAIL), all timing exact:** locked + lockout active right after reset; correct code inside boot delay ignored, first accepted at attempt index 20 for BD=20; v1 default `DEC0DED1` rejected; `secret_valid_i=0` blocks the right code; correct code accepted exactly LO=50 attempts after lockout begins, hammering during lockout does not extend or count, and after expiry 2 more wrong codes do not immediately re-lock (ignored attempts were not counted); success clears the fail counter; wrong codes while unlocked trigger nothing; relock beats a simultaneous correct unlock; reset while unlocked re-locks; HARD mode rejects the correct code for 500 cycles until reset, then a reset clears it.
**Mutation check** (10 deliberate RTL bugs injected one at a time into `scan_lock_controller_v2.v`, each re-run against the unmodified `tb_lock_v2.v`; unmutated control: 0 FAIL): relock-priority removed → 1 FAIL; boot-delay off-by-one → 3 FAIL; secret_valid ignored → 1 FAIL; attempt evaluated during lockout → 4 FAIL + hangs the T5/T11 waits (GLOBAL TIMEOUT); HARD never latches → 1 FAIL; fail-open reset (`locked_q<=0` on reset) → 12 FAIL; MAX_FAILS off-by-one → 7 FAIL; counter not cleared on success → 1 FAIL; lockout-length off-by-one → 4 FAIL; `lockout_o` ignoring `dead` → 1 FAIL. **10/10 mutants caught.**
**Measured attacker cost** (attacker knows `lockout_o`, advances only on evaluated guesses; secret=40): v1 41 cycles; v2 (MF=3, LO=BD=1000) 14,041 cycles = BD+(N+1)+floor(N/MF)*LO exactly, re-confirmed this session; second config (MF=5, LO=200, BD=300, secret=123) 5,224 = formula exactly, re-confirmed. Reset-cycling attacker: 14,067 cycles with 13 resets when BD=LO=1000 (not cheaper than the 14,041-cycle waiting attacker); with BD=100<LO=1000 it takes 1,467 cycles with 13 resets vs 13,141 waiting — reset-cycling genuinely cheaper here, confirming the design rule. **Rule: keep `BOOT_DELAY_CYCLES >= LOCKOUT_CYCLES`.**
**Projection at defaults** (MF=3, LO=BD=1e8 cycles, 100 MHz), arithmetic from the verified formula, NOT simulated: worst case 143,165,580,894,967,296 cycles = 1,431,655,808 s ~ 16,570 days ~ 45 years (about 3.3e7 x the v1 worst case; average about half).
**Integration (`tb_scan_lock_v2.v`, written this session; 17/17 checks PASS), v2 through the same `locked` wire into the unmodified `aes_pcpi`/`aes_core`, reusing `tb_scan_lock.v`'s exact Phase-7 attack procedure:** out of reset, locked=1 and the boot delay is active; a correct-secret attempt presented inside the boot delay is ignored; the Phase-7 attack at 0, 1, 127, 255, 256, 388, 517, 644, 645, 1290 shifts recovers nothing in the key window OR anywhere in the full 645-bit stream, and the zero-shift sample is masked; `DEC0DED1` is rejected and leaves the key window all-zero; the real secret unlocks (after the boot delay) and the attack then recovers the KAT key exactly as Phase 7 (`000102030405060708090a0b0c0d0e0f`); 3 wrong codes trigger a lockout, the correct code is rejected during it, the attack stays all-zero, and the correct code unlocks once the lockout expires; functional KAT (`69c4e0d86a7b0430d8cdb78070b4c55a`) is bit-exact while locked (no lockout), while locked-and-in-lockout, and while unlocked.
**What L1 does NOT do (state in the paper):** it does not stop A3/A6 (write attacks need no unlock); it does not protect the secret's storage (a constant in the bitstream is only as secret as the bitstream); it does not fix F10 (board switch presents the code); an attacker who can burn `MAX_FAILS` attempts can block a legitimate unlock for LOCKOUT_CYCLES (availability trade-off, unlock only, never functional AES); an attacker who controls power/reset is bounded by BOOT_DELAY, not stopped (and is genuinely cheaper than waiting if BOOT_DELAY < LOCKOUT_CYCLES, confirmed above). Only the v1 controller is used by the existing tops/board; v2 is not yet wired into any top-level (Phase 5) and has no Vivado numbers.

### 5e. Phase 4 -- A2 mode-switch and attack x design matrix (Icarus 12.0)

**Review of the owner's `tb_attack_modeswitch.v`.** Compiled and ran as delivered: 108 PASS, 0 FAIL, but two real defects: (1) `check()` took a 1024-bit message, silently truncating the leftmost characters of long labels (the M3-A confirmation printed as `PASS: : bare READRESULT ...`); widened to 2048 bits. (2) The M3-B branch only `$display`ed a diagnostic -- no assertion -- and the banner text claimed a "DISTINCT availability hazard" that the run contradicts. Measured instead: after 389 shifts of 1, `aes_core.fsm_state`=DONE (round_reg_q=15, F8 path), `aes_pcpi.fsm_state_q`=BUSY at the end of the shift, but because core_done is spuriously 1 it self-clears to IDLE in one clock; READRESULT is then accepted at cycle 0 with `pcpi_wr=1`, `pcpi_rd`=`FFFFFFFF` = the forced state_reg word. My own first follow-up assertion (pcpi_wr=0, "silent stale read") was also wrong and was corrected against the measurement. **Net: the predicted M3-B hang was refuted; it is a second ciphertext-spoof path.** Now 111 checks, all asserted.

**Attack x design matrix (`tb_attack_matrix.v`, PASS; each cell asserted).** G0 = undefended (`locked` tied 0), G1 = Paper 1 lock engaged.

| Attack | G0 undefended | G1 Paper-1 lock |
|---|---|---|
| A1 scan-read (key recovery) | SUCCEEDS | **BLOCKED** |
| A2 mode-switch / ciphertext spoof | SUCCEEDS | SUCCEEDS |
| A3 key+plaintext injection (golden `50b58e80...dfd7`) | SUCCEEDS | SUCCEEDS |
| A6 zeroize key_reg after 256 shifts | not zeroed | zeroed |
| A6 zeroize all key regs after 645 shifts | zeroed | zeroed |
| A4 brute force | see `tb_attack_bruteforce.v` / `tb_lock_v2.v` | |

Reading: the Paper 1 lock changes only the READ column. Every write attack works identically with or without it; the lock merely makes zeroize cheaper (256 vs 645 shifts). Limits: G0/G1 are modelled by driving `locked` directly on the unmodified datapath (identical to SECURE_SCAN=0/1 wiring for scan purposes); A5 (CPU registers) is not in the chain and is not covered.

**Are all attacks done? No.** A1-A4 and A6 now each have an asserted testbench and A2 is resolved, but: A5 is deferred (appendix); attacks were run only from a mid-computation freeze or a post-load idle state (no unlock-then-relock or reset-during-scan interleavings); write attacks are characterised only for constant feeds and the EVIL_KEY stream, not adaptive multi-session scan-in. These are gaps, not claimed covered.

### 5f. Phase 5 (partial) -- G4 write-blocking, measured (Icarus 12.0, 30 Sep 2026)

**What G4 is here:** `DEFENSE_LEVEL=4` in `aes_pcpi_def`/`aes_core_def`. While `locked`, `scan_en` is forced to 0 on all five chains (`key_stage`, `block_stage`, `fsm_state`, `round_reg`, and the three core registers), and `scan_out` stays masked. Both gates depend only on `locked` (plus `scan_en`), so they are combinational and shift-count independent like Paper 1.

**Measured matrix (`tb_attack_defenses.v`, 31 checks PASS; every cell asserted; expected ciphertexts from pycryptodome, not from the DUT):**

| Attack | G0 undefended | G1 Paper-1 lock | G4 locked | G4 unlocked (control) |
|---|---|---|---|---|
| A1 scan-read | SUCCEEDS | BLOCKED | BLOCKED | SUCCEEDS |
| A2 ciphertext spoof (fed 0) | SUCCEEDS | SUCCEEDS | BLOCKED (returns true KAT `69c4e0d8...c55a`) | SUCCEEDS |
| A2b ciphertext spoof (fed 1) | SUCCEEDS | SUCCEEDS | BLOCKED (true KAT) | SUCCEEDS |
| A3 key+plaintext injection | SUCCEEDS | SUCCEEDS | BLOCKED (returns AES(real key, real pt) `c32d9c18...290f`) | SUCCEEDS |
| A6 key_reg after 256 zero-shifts | intact | zeroed | intact | intact |
| A6 all key regs after 645 zero-shifts | zeroed | zeroed | intact | zeroed |
| A3b (pt LSB=1, the F8 hang case), G4 only | not run | not run | ENCRYPT accepted, KAT exact | not run |
| A3c (pt MSB=1, hostile shifts, then ENCRYPT), G4 only | not run | not run | ENCRYPT accepted, ciphertext = `946f2c6a...de87` | not run |
| A1b (all-ones key, 1-bit `scan_out` probe) | leaks 1 (positive control) | no 1 seen | no 1 seen | leaks 1 (positive control) |

Reading: in this model G4 closes the read, spoof, injection and zeroize rows that G1 leaves open, and G4 unlocked equals G0. **Zeroize decision:** G4 blocks zeroize (key_reg stays intact after 256 and 645 hostile shifts) because the chain is frozen while locked. That is a consequence of freezing, not a separate mechanism. The cost is that the whole chain is untestable while locked; this is not yet quantified (the T1 testability metric is still to do).

**G2, G3, G2R locked results (this session; `tb_attack_defenses.v` cols 4-6, each cell asserted from `probe3.log`, re-run and identical):**

| Row | G2 locked | G3 locked | G2R locked |
|---|---|---|---|
| A1/A8/A9 key read (differential: two keys, full 645-sample `scan_out`) | blocked, `scan_out` key-independent | blocked, key-independent | blocked, key-independent |
| Tail observable while locked | **yes** (public tail data) | no | **yes** |
| A3 injection | **partial**: key stays real (key_stage frozen) but attacker plaintext lands: ciphertext = AES(real KEY, EVIL) `a3b364bf...aefd` | **wipe**: ciphertext = AES(0,0) `66e94bd4...2b2e`, attacker value does not land | **rotation**: attacker cannot pick the value but the tail rotates it: AES(KEY, PT0>>5) `cdb0244b...8606` |
| A2 (389 shifts, then READRESULT) | faulty ciphertext `305fa571...` (state corrupted, integrity lost) | reads 0 (wipe) | same faulty ciphertext as G2 |
| A2c (`scan_en` HELD HIGH, one READRESULT) | word0 `305fa571` (corrupted) | **`FFFFFFFF` accepted: forged word, spoof works** | READRESULT completes with `pcpi_wr=0` and no data |
| A3b (plaintext LSB=1 then ENCRYPT) | **ENCRYPT hangs** | ok | **ENCRYPT hangs** |
| A6 key_reg zeroize | intact at 256/645 shifts | **zeroed after ONE shift** | intact at 256/645 |

Reading:
- **G2 and G2R are read-masking variants, not write defenses.** In both, `block_stage`/`fsm_state`/`round_reg` remain scan-writable while locked, so by owner decision 1 (plaintext is write-sensitive) they fail. G2R is "observable, not injectable" only in the sense that the attacker cannot choose the value; the rotation still corrupts plaintext and can hang the coprocessor. The hang is an availability hazard that G4 removes.
- **G3's flush is edge-triggered.** It closes A2/A2b (spoof becomes a wipe) only if `scan_en` falls before READRESULT. Holding `scan_en` high (A2c) defeats it: the shifted-in value is returned as the ciphertext. G3 also turns any single hostile shift into a full zeroize (cheapest DoS of all variants: 1 shift vs 256 for G1).
- **Only G4 blocks every asserted row** (including A2c, A6@1, A7, A9). Its cost is that the whole chain is untestable while locked; the T1 testability metric is still to do.
- The old A1b probe ("any 1 on `scan_out` is a leak") is invalid for G2/G2R because they legitimately show the public tail; A8/A9 are asserted for them instead (`a1b` is still recorded as 1 there, documented in the tb).

**Mutation testing of the new G2/G3/G2R assertions (4 mutants applied with `sed`, run against the unmodified `tb_attack_defenses.v`):**

| Mutant (RTL bug, applied by `sed` to `*_def.v`) | Result |
|---|---|
| M1 G2 sensitive registers ungated (`SENS_GATE` drops level 2) | caught, 3 FAIL (G2 A3, A2, A6) |
| M2 granular `scan_out` mux removed (G2/G2R lose the tail-only output) | caught, 2 FAIL |
| M3 G3 flush disabled (`FLUSH_EN=0`) | caught, 4 FAIL (G3 A3, A6, A2b, timeouts) |
| M4 G2R tail input made to take `scan_in` like G2 | caught, 2 FAIL (G2R A3, A2c) |

4/4 caught. Together with the earlier 12 (G4 and equivalence) that is 16 hand-picked mutants; this is evidence, not exhaustive. Unmutated control: 0 FAIL.

**Mutation testing of these two tbs (12 deliberate bugs in `*_def.v`, fresh mutants against the current RTL):**

| Mutant | tb | Result |
|---|---|---|
| A-F: `state_reg`, `round_key_reg`, `key_reg`, `round_reg`, `key_stage`, `block_stage` left ungated | attack_defenses | caught (6/6) |
| I: gate polarity swapped | attack_defenses | caught |
| G: `aes_pcpi.fsm_state` left ungated | attack_defenses | **first SURVIVED; caught after adding A3c** |
| H: core output mask removed | attack_defenses | **first SURVIVED; caught after adding A1b** |
| EQ1 gate polarity, EQ2 flush not lock-qualified, EQ3 tail mux ignores lock | defense_equiv | caught (3/3) |

Why G and H survived (measured, then fixed): `fsm_state` is fed by `block_stage[127]` and the original plaintext had MSB=0, so an ungated FSM shifted in a harmless 0. Under G4 the frozen chain exposes only `key_reg[127]` on `scan_out`, and the KAT key's MSB is 0, so a leaked bit was invisible. Lesson: fixed KAT constants can hide a leak; use data with the relevant bit set, plus a positive control.

**`tb_defense_equiv.v` fix:** `(r[18:16] % 6)` inside a concatenation has indefinite width, so it never compiled. Also gave `compare` its own loop variable, removed dead code in the `scan_en` toggle, and added a stat proving scan shifting happened both while the reference core was running (189 cycles) and idle (215 cycles). Result: L1-L5 unlocked are cycle-identical to the undefended `aes_pcpi` over 900 random cycles on all compared outputs; L1 locked matches the original locked.

**Corrections to earlier claims:** a previous session reported mutants `m1_core_gate_removed`, `m2_pcpi_gate_removed`, `m3_core_polarity` as caught. Those ran against an RTL variant with a `scan_en_eff` signal that the regenerated files do not contain, so they are **not reproduced** and are not counted here. That session also described an "expanded" `tb_attack_defenses.v` with G2/G3/G2R columns and an A2c case; that file was not in the project. **Those columns and A2c have now been rebuilt and asserted (above).** A later session's transcript (tool budget ran out before assertions were written) is the source of the probe; its measurements were re-run and reproduced.

**Limits (state these exactly in the paper):**
- G2, G3, G2R now have locked-behaviour tests (above) for A1/A2/A2b/A2c/A3/A3b/A3c/A6/A6@1/A7-A9 only; no other attacks (e.g. interleavings of unlock/relock with scan, adaptive multi-session feeds) were tried.
- `tb_defense_equiv` compares L1-L5 unlocked and L1 locked only, one seed, 900 cycles. It is not exhaustive equivalence and does not compare locked L2-L5.
- Mutation coverage is 12 hand-picked bugs, not exhaustive. A passing tb here is evidence, not proof, and not a formal result.
- The `*_def.v` RTL was regenerated (provenance above); the two tbs pass against it, not against a separately reviewed original.
- Functional checks per variant: `tb_def_functional.v` shows KAT bit-exact and a back-to-back KAT for L1-L5, locked and unlocked. The 20-case `tb_scan_resume` sweep and the CPU-driven program now also pass on every variant (s5g).
- No Vivado numbers exist for any defense variant.

### 5g. Phase 5 (continued) -- top-level wiring, resume and CPU-driven checks per variant (Icarus 12.0, 30 Sep 2026, third session)

**Baseline re-run before any change.** Upload imported into git unmodified (first commit). `run_regression.sh` rewritten for the `RTL/`+`TB/` layout and run on the 24 previously gated tbs with `JOBS=4`: `SUMMARY passed=24 failed=0 total=24`, 6 min 35 s wall. `tb_attack_defenses`: 58 PASS lines, identical line for line to the saved `tb_attack_defenses.log`.

**`secure_scan_rv_top_def.v` (new).** CPU, memory and PCPI wiring copied from `secure_scan_rv_top_v2.v`; the AES instance is `aes_pcpi` (DEFENSE_LEVEL=0) or `aes_pcpi_def #(DEFENSE_LEVEL)`; the lock is none / v1 / v2 by `LOCK_VERSION`. v2's `secret_i`, `secret_valid_i`, `lockout_o` are top-level ports. `_v2` is unchanged, so Paper 1 Vivado numbers still refer to the same file.

**`tb_cpu_driven_aes_def.v` (new; 144 PASS / 0 FAIL, 18/18 configs, 3 min 23 s).** The unchanged hand-assembled program from `tb_cpu_driven_aes.v` on all DEFENSE_LEVEL 0-5 x LOCK_VERSION 0-2, v2 scaled to MAX_FAILS=3, LOCKOUT=BOOT_DELAY=400 cycles. Per config: C1 CPU-driven KAT from reset with the lock in its reset state (`locked`=1 for v1/v2); C2 645-shift scan read after the program: KAT key absent from the 646-sample stream (any alignment, either bit order) when locked, present when LOCK_VERSION=0; C3 v1 rejects a wrong code; v2 ignores/rejects `DEC0DED1`, 3 wrong codes after the boot delay set `lockout_o`, the real secret is rejected during lockout, lockout expires; C4 correct code unlocks; C5 resetn-only pulse (lock domain untouched), program re-run: KAT, still unlocked; C6 unlocked scan read shows the key (positive control for C2).
Mutant (top connects `.locked(1'b0)` into `aes_pcpi_def` while a lock exists): **caught, exactly the 10 expected configs fail C2** (DL 1-5 x LV 1-2); the 8 untouched configs still pass.

**`tb_scan_resume_def.v` (new; 100/100 cases OK, 4 min 47 s).** Generated from `tb_scan_resume.v` by script; only the DUT (`aes_pcpi_def #(DL)`), the case messages and the banner changed. Same v1 lock, same freeze point (ENCRYPT + 6 cycles), shift counts 0, 1, 127, 255, 256, 388, 517, 644, 645, 1290, unlocked and locked, no reset between scan exit and the next KAT: all 20 cases OK for each of L1-L5.
Mutant (the `core_seen_running` stale-done fix removed from `aes_pcpi_def`): **caught, 91/100 cases fail** (L1, L2, L4, L5: 20/20; L3: 11/20, because G3's flush also resets the core).

What this does and does not show: every variant, under every lock version, still runs the real CPU's AES program correctly and recovers from any of the 10 scan sessions without a reset. It does not re-run the attack matrix through the top-level (the attack tbs drive `aes_pcpi_def` directly with `locked` from a v1-style source; C2 is the only attack run through the top). The v2 parameters are scaled for simulation; default-parameter behaviour is still the s5d projection.

**Line-by-line review of `aes_core_def.v` / `aes_pcpi_def.v` (by reading, this session).** No functional defect found. Notes:
1. Reset is synchronous (`scan_cell`), so G3's `flush` (`locked & (scan_en ^ scan_en_q)`) is a synchronous clear, not a glitch-prone async reset. `aes_pcpi_def` and `aes_core_def` each compute `flush` from their own `scan_en_q` flop; both see the same `scan_en`/`locked`, so they flush in the same cycle.
2. `scan_en_q` has an initial value but no reset. Fine on the FPGA (INIT). On an ASIC it would power up X, and G3 could flush once on the first cycle (harmless: it only clears).
3. Any `DEFENSE_LEVEL` outside 1-5 silently behaves as G1; there is no parameter check. The new top maps 0 to the original module, so 0 never reaches `_def`.
4. G1's `round_key_reg` scan-in gate (`seg_in_muxed`) is kept at every level (redundant for 2/4/5). In G4, scan_en while locked has no effect at all, so the core keeps computing functionally; that is why A3b gives the true KAT. For G2/G2R the tail ring is `block_stage`+`fsm_state`+`round_reg` = 133 bits.
Header comments of both files named the original files; fixed to name the `_def` files (comment-only change).

**`mutate.py` re-run in this repo (12 mutants, unmodified tbs; the earlier session's claim re-checked, not trusted):** A `state_reg` ungated 5 FAIL; B `round_key_reg` ungated 3; C `key_reg` ungated 5; D `round_reg` ungated 5; E `key_stage` ungated 6; F `block_stage` ungated 4; G `aes_pcpi.fsm_state` ungated 3; H core output mask removed 3; I gate polarity 15 (all `tb_attack_defenses`); EQ1 gate polarity 3; EQ2 flush not lock-qualified 1; EQ3 tail mux ignores lock 2 (`tb_defense_equiv`). **12/12 caught.** (Run in two parts: the first stopped at a 30-min sandbox limit after A-H; I and EQ1-EQ3 re-run separately.) Together with the 4 G2/G3/G2R mutants (s5f, not re-run here) and the 2 new-tb mutants above: 18 hand-picked mutants, all caught. Evidence, not exhaustive.

**Regression (28 gated tbs):** the 24 previously gated + `tb_scan_resume_def`, `tb_cpu_driven_aes_def`, `tb_attack_top_def` (s5h) and `tb_testability_t1` (s5i). Full-run result (`JOBS=3 ./run_regression.sh`): **`SUMMARY passed=28 failed=0 total=28`**, ~12.5 min wall on a 4-core sandbox. (Interim milestones this session: 26/26 after the resume+CPU tbs, 27/27 after the top-level attack tb.)

### 5h. Phase 5 (continued) -- attack matrix through the full top-level (Icarus 12.0, 30 Sep 2026, third session)

`tb_attack_top_def.v` runs the attacks against `secure_scan_rv_top_def` with the **real picorv32 driving the coprocessor over PCPI and the real lock controller driving `locked`**. The attacker touches only `scan_en`/`scan_in`/`scan_out` -- no `locked` override, no hierarchical writes into the design (the only hierarchical accesses are the testbench loading the CPU's program and reading the word the CPU itself stored, as in `tb_cpu_driven_aes.v`). Firmware: the `tb_cpu_driven_aes.v` program plus a service loop (poll 0x700; 1 = ENCRYPT+READRESULT, 2 = READRESULT only; result to 0x810). The attacker acts while the CPU is in the poll loop; then the tb writes the flag (the legitimate request) and checks the ciphertext the CPU stored. Golden values from pycryptodome. v2 lock scaled to MAX_FAILS=3, LOCKOUT=BOOT_DELAY=400. **PASS, 105 checks, 25 runs.**

| config | none | A1 read | A2 spoof (READRESULT only) | A3 inject (EVIL) | A6 wipe (256 zeros) |
|---|---|---|---|---|---|
| P1 (DL0, v1 lock), locked | KAT | BLOCKED | SUCCEEDS (all-ones) | SUCCEEDS `50b58e80..` | SUCCEEDS AES(0,0) `66e94bd4..` |
| G0 (DL0, no lock) | KAT | LEAKS | SUCCEEDS | SUCCEEDS | SUCCEEDS |
| G1 (DL1) + L1, locked | KAT | BLOCKED | SUCCEEDS | SUCCEEDS | SUCCEEDS |
| **G4 (DL4) + L1, locked** | KAT | **BLOCKED** | **BLOCKED (true KAT)** | **BLOCKED (true KAT)** | **BLOCKED (true KAT)** |
| G4 + L1, unlocked (authorised) | KAT | LEAKS | SUCCEEDS | SUCCEEDS | SUCCEEDS |

Reading: through the real integration, **G4 + L1 is the only locked configuration that blocks A1, A2, A3 and A6 at once**; Paper 1 (with either lock version) blocks only A1; G4 unlocked equals G0 (so the defense adds nothing in authorised use). The "none" column confirms the service loop itself returns the true KAT in every configuration (the write attacks are what change it). This is the integrated evidence for success criterion S3 and the paper's headline table, not just module-level driving.
Mutant (G4's `key_stage` scan-enable ungated in `aes_pcpi_def`): **caught** -- G4 A3 then returns AES(EVIL, real PT) = `56c284f3..` and A6 returns AES(0, real PT) = `c8a331ff..` (both confirmed in pycryptodome), so the injected plaintext lands again; the tb flags both as OTHER and fails.

Limits: one firmware, one freeze point (CPU in the poll loop), constant/EVIL feeds only, v2 parameters scaled for simulation. A2 here is the READRESULT-only spoof (fed=1, all-ones state); the fed=0 / 389-shift IDLE variant and A2c (scan_en held high) are covered at module level in s5f. A4 (brute force) and A5 (CPU registers) are not part of this tb.

### 5i. Phase 7 metric T1 -- testability while locked (Icarus 12.0, measured, 30 Sep 2026)

`tb_testability_t1.v`. **Writable** (controllability) is measured exactly, per segment: reset to 0, assert locked, shift 645 bits of a constant, and read the actual stored state through the `dbg_*` ports (no shift-alignment assumptions); a bit is writable iff its stored value follows the shifted constant. **Observable** (readability) is the number of locked `scan_out` samples (of 646) that differ between an all-0 chain and an all-1 chain. `fsm_state` (1 control bit, no secret) has no `dbg` port, so it is excluded from the writable count but still shifts, so it is included in the observable tail.

| Variant | Writable /645 | Observable | Writable by segment (key_stage / block_stage / round_reg / state_reg / round_key_reg / key_reg) |
|---|---|---|---|
| DL0 = original datapath, driven locked (= G1) | 388 | 0 (masked) | 128 / 128 / 4 / 128 / 0 / 0 |
| G1 (DL1) Paper 1 | 388 | 0 (masked) | 128 / 128 / 4 / 128 / 0 / 0 |
| G2 (DL2) granular mask | 132 | 133 (tail drains) | 0 / 128 / 4 / 0 / 0 / 0 |
| G3 (DL3) flush-on-edge | 388 | 0 (masked) | 128 / 128 / 4 / 128 / 0 / 0 |
| **G4 (DL4) write-block** | **0** | **0** | 0 / 0 / 0 / 0 / 0 / 0 |
| G2R (DL5) recirc tail | 0 | 133* | 0 / 0 / 0 / 0 / 0 / 0 |

Reading:
- **Paper 1 (G1) is read-locked but write-open:** 0 bits observable, yet **388 of 645 bits writable** while locked (`key_stage`, `block_stage`, `round_reg`, `state_reg`; only `round_key_reg` and the `key_reg` behind it are gated). That 388 is the write surface the injection/spoof attacks use.
- **G3** has the same 388 writable surface (its flush only clears on the `scan_en` edge; the shifted-in data still lands, matching s5f's "held `scan_en` defeats it").
- **G2** freezes the four sensitive segments (0 writable there) but leaves the 132-bit tail (`block_stage`+`round_reg`) writable and the 133-bit tail (+`fsm_state`) observable -- which is exactly why A3 corrupts the plaintext under G2.
- **G2R** makes the tail observable (133, recirculating) but **not writable (0)** -- the "observable, not injectable" property, confirmed by measurement.
- **G4 is the only variant that is both 0 writable and 0 observable.** Its cost is the whole chain (645 bits) is untestable while locked; unlocked it is identical to the original (s5f equivalence). This is the security-vs-testability trade-off for the paper's T1 table.

(*) G2R's observable count saturates at 646 because the tail recirculates its 1s instead of draining; the true observable width is the 133-bit tail, taken from the structure, not from the saturated sample count. Gated assertions in the tb check the exact writable counts for G1/G2/G4 (G4 = 0, G2 sensitive = 0 and tail = 132, G1 `round_key_reg` = 0 and `key_stage`/`state_reg` = 128).

### 5j. Phase 7 metric T2 -- chain-integrity (flush) + stuck-at in simulation (Icarus 12.0, measured, 30 Sep 2026)

`tb_testability_t2.v`. **Flush / chain-integrity:** shift a known 645-bit pattern in, then shift it out feeding 0 and capture `scan_out`; a bit is "recovered" only if it tracks the input in BOTH the pattern pass and its complement (so a masked or stuck constant output nets to 0 rather than coincidentally matching an alternating pattern -- an artifact that a single-pattern count would have mis-reported as 323). **Stuck-at:** force one scan cell's `q_reg` to a constant and re-run the unlocked flush; the fault must corrupt the recovered stream. 5 chain positions x {s-a-0, s-a-1} on G1.

| Variant | Flush recovered UNLOCKED | Flush recovered LOCKED |
|---|---|---|
| G0 (DL0 datapath) | 645/645 | 0 |
| G1 | 645/645 | 0 (masked) |
| G2 | 645/645 | 133 (tail) |
| G3 | 645/645 | 0 (masked) |
| **G4** | 645/645 | 0 (frozen) |
| G2R | 645/645 | 0 (tail observable but not injectable, so a loaded pattern is not read back) |

Stuck-at: **10/10 injected faults detected** (each drops unlocked recovery from 645 to 0 under the strict metric).

Reading:
- **Every defense variant is fully testable while UNLOCKED (645/645).** The defenses cost nothing in normal manufacturing-test mode; this is the flip side of T1 and supports S6/S8.
- **Locked recovery matches T1:** G1/G3/G4/G2R expose nothing recoverable, G2 exposes its 133-bit tail. G2R's T1 "observable" (scan_out depends on content) and T2 "recovered" = 0 (a shifted-in pattern cannot be read back) together are exactly the "observable but not injectable" property.
- **A standard flush test detects scan stuck-at faults**, so the chain remains a usable DfT structure when unlocked. This is a sim demonstration at 10 sites, not full ATPG coverage (T3, appendix).

Limit: fault detection shown at 10 representative sites with `force`/`release`, not an exhaustive 645-site sweep; T3 (Yosys+Fault/Atalanta) is still appendix-only.

### 5a. A3 / A6 — independently verified, not just claimed

`tb_attack_probe.v` was **re-run independently** (not just trusted from a
prior session's narration): fresh copy of the real RTL, compiled and run with
Icarus Verilog 12.0.

- **A3 (key + plaintext injection): CONFIRMED, independently.** 128 scan
  shifts write an attacker-chosen 128-bit pattern into `key_stage` while
  `locked=1` from reset and never unlocked. The same shift pushes
  `key_stage`'s prior legitimate contents into `block_stage`. Issuing
  `ENCRYPT` with no fresh `LOADKEY`/`LOADBLOCK` produces ciphertext
  `50b58e80ce784e98ad48d63390c5dfd7`. **Checked independently in Python
  (pycryptodome), not by trusting the testbench's own `$display`:**
  `AES_encrypt(0f1e2d3c...e1f0, 00010203...0e0f) = 50b58e80...dfd7` — matches
  exactly, both encrypt and decrypt directions confirmed. The coprocessor
  genuinely encrypted the attacker-injected (key, plaintext) pair, entirely
  through the locked scan port, zero unlock attempts.
- **A6 (zeroize): CONFIRMED, independently, with the assertion the original
  probe was missing.** Added `round_key_reg===0 && key_reg===0` directly
  after 256 zero-shifts while locked: **PASS.** Both registers are hard-zero,
  exactly matching the F3 mechanism.

### 5b. Phase 1 regression testbenches

- **`tb_zeroize.v` (run by me, Icarus 12.0): 97 PASS, 0 FAIL.** It compares
  `round_key_reg`/`key_reg` to an independent 645-bit chain model (locked mode
  forces `round_key_reg`'s scan-in to 0) at n = 0,1,64,127,128,129,200,255,256,257,
  locked and unlocked. Two testbench pitfalls found and fixed while writing it
  (RTL was correct throughout; an earlier draft gave 21 false FAILs):
  1. Boundary checks of the form "not yet zero below 128/256 shifts" are
     **data-dependent**: at 127 shifts the register holds only the original bit 0,
     which is 0 for this key schedule, so it is legitimately all-zero. Compare to a
     model instead.
  2. Scan registers shift on every scan clock, so "unchanged when unlocked" is
     wrong; and a trailing functional `@(posedge clk)` after dropping `scan_en`
     advances the still-RUNNING core. Sample right after the last shift edge.
- **`tb_attack_write_inject.v` (owner's Vivado simulator run, not Icarus):** all checks
  PASS, including both F8 cases and the golden ciphertext. The golden constant
  `50b58e80ce784e98ad48d63390c5dfd7` = AES(key `0f1e2d3c...e1f0`, block
  `00010203...0e0f`) was re-checked in Python (pycryptodome) this session.
  **Cosmetic bug (fixed in the delivered file):** `check()` took a 1024-bit message and
  the caller concatenated a 1024-bit `label`, truncating the prefix. Now `msg` is
  2048 bits with a 256-bit label; the file was retyped, and Icarus reruns it PASS.

**This closes the paper's single most important go/no-go gate on real
evidence, independently reproduced — not on a prior session's claim.**

---

## 6. Attack suite status

| ID | Attack | Status |
|---|---|---|
| A1 | Scan-read | Blocked by Paper 1, re-confirmed |
| A2 | Mode-switch (write mid-computation state, functional read) | **MEASURED (`tb_attack_modeswitch.v`, s5e).** (a) Key-tampering variant fails, as predicted: controlling `state_reg` needs >=262 shifts, which already zeroizes `round_key_reg` (F3) -- write and zeroize are inseparable. (b) BUT a distinct exploit exists: **ciphertext spoofing** -- after 389 shifts a bare `READRESULT` (no ENCRYPT) returns the scan-forced `state_reg` value, in G0 and G1. Works for fed=0 and fed=1. |
| A3 | Key + plaintext injection | **CONFIRMED, independently verified**; regression-grade `tb_attack_write_inject.v` passes (owner's Vivado run). Headline result — lead with this. |
| A4 | Unlock brute force | **Measured against v1 (§5d):** one guess/clock, no limiter, exactly secret+1 guesses; 2^32 worst case = 42.95 s @100 MHz (derived). Against L1 (§5d): exact cost formula verified at two parameter sets; ~45 years worst case at default parameters is a projection, not a simulation. |
| A5 | CPU register read | Optional appendix extension only (needs the CPU in the chain). |
| A6 | Zeroize / DoS | **CONFIRMED**; `tb_zeroize.v` passes in Icarus 12.0 (model-exact at 10 shift counts, lock-sensitive negative control). |

---

## 7. Defense variants (L1 built; G2-G4, S1 planned)

| ID | Defense | Mechanism |
|---|---|---|
| G0 | Undefended | `SECURE_SCAN=0` |
| G1 | Paper 1 blanket masking | `scan_out = locked ? 0 : ...`; only `round_key_reg` scan-in gated. **Confirmed to NOT block A3/A6.** |
| G2 | Granular read masking | Only sensitive segments hidden while locked; non-sensitive tail stays observable. |
| G3 | Flush on `scan_en` transition | Clear sensitive registers on `scan_en` change; `scan_out` stays gated until flush completes. |
| G4 | Write blocking + interlock | Sensitive segment's `scan_en` forced to 0 while locked — **this is the mechanism that actually closes A3**, not G1/G2 alone. Optional AES-busy interlock. Must also close F13 (ciphertext spoof, via `state_reg`/`round_reg`/`fsm_state` writes) and, per owner decision 1, protect `block_stage` (plaintext) -- i.e. block scan-in for key_stage, block_stage, fsm_state, round_reg, state_reg, not only the key registers. |
| L1 | Lock hardening | **BUILT and verified (Phase 2, §5d):** `scan_lock_controller_v2.v`. Attempt counter + lockout + boot delay; no public default code; simple gate (no LFSR — see GF-Flush break in Paper 1's own related work). **Wired into `secure_scan_rv_top_def.v` (`LOCK_VERSION=2`) and exercised through the real CPU (s5g).** Not synthesized; the board top still uses v1. |
| S1 | Secure-build hygiene | Remove `dbg_*` taps / board bypass from the secure build (F9/F10/F11). |

**Phase 5 status (30 Sep 2026):** G4 built as `DEFENSE_LEVEL=4` and measured against A1/A2/A2b/A3/A3b/A3c/A6 (s5f). G2, G3, G2R (`DEFENSE_LEVEL` 2, 3, 5) are now measured locked (s5f): G2 and G2R leave the tail writable (partial injection / rotation, plus an ENCRYPT hang), G3 wipes instead of accepting values but is defeated by holding `scan_en` high (A2c) and zeroizes on one shift. None is a complete write defense; G4 is. All five variants also pass the 20-case resume sweep and the CPU-driven program under no lock / v1 / v2 (s5g).

**Planned granular chain layout (G2/G4):**
```
UNLOCKED:  scan_in -> [SENSITIVE: key_stage, state_reg, round_key_reg, key_reg] -> [TAIL: block_stage, fsm_state, round_reg] -> scan_out
LOCKED  :  scan_in ---------------------- (bypass mux) ----------------------> [TAIL] -> scan_out
                     SENSITIVE: scan_en forced 0, output not connected
```
Both muxes keyed only on `locked` (combinational), preserving Paper 1's
zero-shift, shift-count-independent property.

**Open point:** given A3 also corrupts `block_stage` (plaintext), decide
whether plaintext needs write-protection even though it's read-public. See
§10, open decision 1 (**awaiting the owner's confirmation before Phase 5**).

---

## 8. Sensitivity analysis method (Phase 3 — DONE, results in §5c)

1. Vary key (K_a vs K_b) and plaintext (P_a vs P_b) independently; capture
   points: idle-after-LOADKEY, each freeze cycle 0–11, DONE, idle-after-READRESULT.
2. For each capture point, run pairs differing in exactly one input, capture
   all 645 bits, XOR.
3. ≥32 random key pairs (a truly key-dependent bit failing to differ across
   32 pairs has probability 2^-32).
4. Classify each (bit, capture point): key-dependent / plaintext-dependent /
   both / neither.
5. Classify exploitability separately: key-dependent AND not derivable from
   public data.
6. Output: segment × phase heat map + per-bit CSV. **No defense work starts
   before this is done.**

**Original hypothesis (now confirmed by §5c, except the write-sensitivity remark, which comes from A3 not from this read-only map):** `key_stage`, `key_reg`,
`round_key_reg`, `state_reg` (early/last rounds) sensitive for read;
`block_stage` is plaintext-dependent for read but now also flagged
write-sensitive given A3; `fsm_state`/`round_reg` depend on neither for read,
but their writes are functionally dangerous regardless (F8).

---

## 9. Formal verification plan (Phase 7 — honestly scoped)

**Do not call this "provable" anywhere in the paper without the qualifier in
the same sentence.** The result is a reduced-width, black-boxed-core proof,
not a full-design guarantee.

**Property (non-interference), reduced model:** for two instances of the
design differing only in secret key material, identical scan/PCPI/lock
inputs, `locked=1` from reset, `scan_out` is identical in both copies at
every cycle of the reduced/bounded model under test.

| Step | What |
|---|---|
| 1 | Two-copy miter wrapper: `assume` same public inputs + `locked=1`, `assert(scan_out_A==scan_out_B)`. |
| 2 | Prove first on a reduced-width scan segment (e.g. 8-bit) with the AES core black-boxed. |
| 3 | `bmc` to ~2-3x chain length, then `prove` (k-induction/PDR) where it converges. |
| 4 | G1 first (sanity check — and now we know *why* it's insufficient: A3 shows the write side isn't covered by this property at all), then G2/G3/G4. |
| 5 | **Add a write-side property**, directly motivated by A3: with `locked=1`, no sensitive/key-consuming register's next state depends on `scan_in`. Arguably more important than the read-side proof now.  Property must cover F13: with `locked=1` no scan_in-dependent value reaches `state_reg`/`round_reg`/`fsm_state`/`block_stage` either. |
| 6 | Negative control: a deliberately broken variant must fail the proof, proving the property can catch a real leak. |
| 7 | State exactly what is proven (reduced width, black-boxed core, bounded/unbounded) every time it's mentioned in the paper. |

**Testability under lock (Phase 7):**

| Tier | Metric | Required? |
|---|---|---|
| T1 | Observable fraction and writable fraction of chain bits while locked (G1 vs G2 vs G4) | **Yes — core deliverable** |
| T2 | Chain-integrity flush test + stuck-at injection in sim | **DONE (s5j):** `tb_testability_t2`, 645/645 unlocked all variants, 10/10 stuck-at detected |
| T3 | Yosys+Fault/Atalanta restricted stuck-at coverage | Optional — appendix only |

**Tooling dependency:** SymbiYosys (`sby`) must be confirmed installable
before committing to this phase's scope. Not yet confirmed.

---

## 10. Open decisions (need a call before Phase 5)

1. ~~Given A3 also corrupts `block_stage`, does the threat model now treat
   plaintext as write-sensitive even though it's read-public?~~ **DECIDED (owner, 29 Sep 2026): YES -- plaintext is write-sensitive.** Consequence for G4/G2: `block_stage` (and `fsm_state`, `round_reg`, `state_reg`, per M1/M3) must have scan-in gated/blocked while locked, not only the key registers. Original recommendation: yes — say so explicitly, it strengthens the main
   contribution.**
2. Accept a small `picorv32.v` diff to scan PC/pipeline, or keep the core
   untouched and scope to the register file? (Only relevant if the appendix
   CPU-register extension is attempted.)
3. Which venue tier — check the current CFP and page limit before committing
   to Phase 7's depth.
4. Board write-demo (`scan_write_harness.v`), or is simulation evidence
   enough? **Recommendation: simulation is enough for the core paper.**
5. Confirm SymbiYosys is actually installable on the working machine before
   committing to Phase 7's scope as written.

---

## 11. Work breakdown and timeline

**Correction from the v2 PRD:** its phase list summed to ~14-16 weeks even
accounting for the stated Phase 2/3 parallelism, not the "10-12 weeks" that
document concluded with. Use the recomputed estimate below.

| Phase | Content | Est. duration | Depends on |
|---|---|---|---|
| 0 | Baseline cleanup: tag `paper1-baseline`, diff `picorv32.v` vs upstream, remove legacy top, regression script, re-run missing Vivado reports, Vivado sweep script (3-5 directives), write Paper 1 errata list (§13) | 3-4 days | — |
| 1 | Formalize the write attack: promote `tb_attack_probe.v` into regression-grade `tb_attack_write_inject.v` (add assertions, sweep F8's fsm_state interaction both ways, sweep partial shift counts); `tb_zeroize.v` with the direct register assertions (already prototyped in §5a) | 3-4 days | Phase 0 |
| 2 | Lock attacks and hardening baseline: `tb_attack_bruteforce.v` (A4); L1 (attempt counter/lockout) in `scan_lock_controller_v2.v` | 1 week | Phase 1 (can run parallel to Phase 3) |
| 3 | Sensitivity map (§8): `tb_sensitivity.v`, CSV + heat map, confirm/refute F4-F6 | 2 weeks | Phase 1 (can run parallel to Phase 2) |
| 4 | **DONE (29 Sep 2026)** Attack suite completion: A1-A4, A6 asserted; A2 measured (negative for key tamper, POSITIVE for ciphertext spoof); attack x design table for G0, G1 (`tb_attack_matrix.v`, s5e) | 1 week | Phases 2 and 3 both done |
| 5 | Defenses: **G4 first** (closes the confirmed A3 attack; reordered ahead of G2 for exactly this reason), then G2, then G3; re-run the full attack suite on each variant; full regression (KAT, `tb_scan_resume`, `tb_cpu_driven_aes`) must still pass; functional-cost check (ciphertext bit-exact while locked) | 4 weeks (**IN PROGRESS: G1-G4/G2R measured locked (s5f); resume + CPU-driven checks pass on every variant, L1 wired into a top-level (s5g). Outstanding: attack matrix through the top-level, T1, Vivado**) | Phase 4 |
| 7 | Formal analysis (§9) + testability (T1 required, T2 required, T3 optional) + Vivado sweep for G0-G4 (mean/min/max over ≥3 directives) | 3 weeks | Phase 5 |
| 8 | Paper: central attack × defense matrix, sensitivity heat map, all sections, cover letter relating to Paper 1 | 4 weeks | Phase 7 |

**Sequential-with-stated-parallelism total: ≈ 3.5 + 14 (max of Phase 2/3, run
together) + 7 + 28 + 21 + 28 ≈ 101.5 days ≈ 14.5 weeks.**
Budget **15 weeks**, not 10-12, unless you can genuinely run Phase 5's three
sub-items or Phase 7's sub-items concurrently with help.

**Deferred to appendix (not on the critical path — see §12):** CPU register
file via `PICORV32_REGS`, G2-R recirculating tail, T3 fault-coverage flow,
board write-demo.

---

## 12. Appendix: optional extensions (pick up only with time to spare)

- **CPU register file:** `scan_regfile.v` via `PICORV32_REGS` (hook confirmed
  present), ~992 additional scan cells, new firmware via `.S` + assembler, A5.
  Biggest single schedule risk for the smallest marginal contribution — keep
  as a generalization experiment for a follow-up paper, not this one.
- **G2-R recirculating tail:** observable-but-not-injectable tail variant,
  evaluate vs. plain bypass.
- **T3 fault-coverage flow:** Yosys+Fault/Atalanta, restricted fault set,
  clearly labeled as non-ASIC-signoff.
- **Board write-demo (`scan_write_harness.v`):** synthesizable FSM mirroring
  `scan_attack_harness.v` but for A3 (since `scan_dump_controller` currently
  ties `scan_in` to 0). Nice for a live demo; not needed for the evidence
  chain, since A3 is already proven in simulation.
- **Per-device / challenge-response unlock codes:** beyond L1's basic lockout
  counter.

---

## 13. Paper 1 errata (fix before/while writing Paper 2's related-work section)

- Abstract/contribution 3 call the lock "segmented"; the RTL actually blanks
  the whole coprocessor `scan_out` as one unit.
- "Every scan-relevant register is a scan primitive" overstated:
  `fsm_state`, `start_i_reg`, `core_seen_running` are plain registers.
- "Dedicated vs. shared chain" wording is inconsistent between the
  abstract, Section III, and the conclusion.
- References [17]/[18] don't support the sentences citing them — replace or drop.
- References [15]/[16] are never cited in the body — cite or remove.
- Fig. 3 caption points to Table III; the reconstruction is Table II.
- "Zero functional overhead" (abstract) sits next to a ~5% Fmax drop — say
  "zero effect on encryption correctness" instead.
- Fmax drop attributed to placer layout is asserted, not shown — run 3-5
  placer seeds per configuration and report the spread.
- "First reconstruction of the 645-bit segment from live hardware" should be
  dropped or qualified.
- Verify the DefScan author list against the actual paper before citing again.

---

## 14. Repository layout to target

```
rtl/
  cpu/picorv32.v                  (unmodified, diffed vs upstream)
  aes/{aes_sbox,aes_core,aes_pcpi}.v, aes_pcpi_defs.vh
  scan/{scan_cell,scan_chain}.v
  scan/scan_lock_controller.v     (P1, kept)      scan_lock_controller_v2.v   (NEW: lockout)
  scan/aes_core_g2.v aes_pcpi_g2.v (NEW: granular variants, selected by parameter)
  top/secure_scan_rv_top_v2.v     (SECURE_SCAN / DEFENSE_LEVEL parameter)
  board/ board_top.v lock_switch_ctrl.v scan_dump_controller.v uart_* seven_seg_hex.v ...
  harness/ scan_attack_harness.v
  appendix/ scan_regfile.v scan_write_harness.v   (optional extensions, §12)
tb/
  (all Paper 1 testbenches, unchanged)
  tb_attack_write_inject.v   (promoted from tb_attack_probe.v)
  tb_zeroize.v  tb_attack_bruteforce.v  tb_sensitivity.v  tb_attack_modeswitch.v
formal/  noninterference_read_g{1,2,3,4}.sby  noninterference_write_g{1,4}.sby  miter_wrapper.v  negative_control.sby
scripts/ run_regression.sh  vivado_sweep.tcl  collect_reports.py  make_heatmap.py
docs/    scan_map.md  chain_composition.md  claims_to_evidence.md  paper1_errata.md
results/ sensitivity.csv  attack_matrix.csv  vivado_sweep.csv  proofs/
```

---

## 15. Numbers Paper 2 must compare against (from Paper 1)

| Item | Value |
|---|---|
| Chain | 645 bits, protected (Paper 1's definition) 256 bits |
| Baseline (`SECURE_SCAN=0`) | 2,828 LUT, 1,225 FF, 1 RAMB36E1, WNS 2.502 ns |
| Defended (`SECURE_SCAN=1`) | 2,842 LUT (+14), 1,226 FF (+1), WNS 2.084 ns — reports missing, re-run in Phase 0 |
| Full board design | 4,365 LUT (13.39%), 4,248 regs (6.52%) |
| Brute-force cost, no limiter (v1) | Model measured (§5d): secret+1 guesses, 1 guess/clock. Worst case 2^32 cycles = 42.95 s at 100 MHz (arithmetic from the model, no 2^32 run) |
| Brute-force cost, L1 defaults (MF=3, LO=BD=1e8 cycles) | ~1.43e17 cycles ~ 45 years worst case @100 MHz (projection from a formula verified at two scaled parameter sets) |
| KAT | key `000102...0F`, plaintext `001122...FF`, ciphertext `69C4E0D86A7B0430D8CDB78070B4C55A` |
| K10 for that key | `13111D7FE3944A17F307A78B4D2B30C5` |
| **A3 injected key (independently confirmed)** | `0F1E2D3C4B5A69788796A5B4C3D2E1F0`, injected while `locked=1`, never unlocked, ciphertext `50b58e80ce784e98ad48d63390c5dfd7` |

---

## 16. Immediate next steps (pick up here)

1. Phase 0 cleanup (tag baseline, diff picorv32, remove legacy top, write
   regression script, re-run missing Vivado reports, Vivado sweep script).
2. ~~Promote probe into `tb_attack_write_inject.v` and `tb_zeroize.v`~~ — done, both in `run_regression.sh` (§5b).
2b. Remaining Phase 0: tag `paper1-baseline`, delete `secure_scan_rv_top.v` and stale `scan_lock.v`/`tb_coprocessor_scan.v` references from the owner's tree, re-run missing Vivado reports, Vivado sweep script, errata list (§13).
3. ~~Phase 3 (sensitivity map)~~ — **done (§5c).**
3b. ~~Phase 2 (`tb_attack_bruteforce.v`, L1 lock hardening)~~ — **done (§5d).** Next: Phase 4 (attack suite completion: A1-A4, A6 as reusable tasks, A2 negative result, attack x design table for G0/G1). Phase 4 done (s5e). Phase 5 unblocked (decision 1 resolved).
4. Confirm SymbiYosys is installed/installable before committing to Phase 7 as scoped.
5. Defer the CPU register file extension until the core path is done.
6. **Phase 5 next (in this order):** ~~(a) version control~~ done (git); ~~(b) G2/G3/G2R columns, regression~~ done (s5f); ~~(c) `tb_scan_resume`/`tb_cpu_driven_aes` on variants~~ done (s5g); ~~(d) line-by-line review of `*_def.v`~~ done, no defect, 4 notes (s5g); (e) ~~wire `scan_lock_controller_v2` into a top-level~~ done (s5g); ~~re-run the attack matrix through `secure_scan_rv_top_def` with the v2 lock~~ done, `tb_attack_top_def`, G4+L1 blocks A1/A2/A3/A6 (s5h); (f) decide the paper's defense ladder: G1 -> G4 as the recommended design, G2/G2R/G3 as ablations that show why read-masking, granular tails and flush-on-edge are insufficient; ~~(g) T1 testability metric~~ done (s5i); ~~(h) re-run `mutate.py`'s 12 mutants~~ done, 12/12 caught (s5g).
7. Ask the owner for Vivado reports for G0/G1/G4 before any overhead number is written anywhere. Confirm SymbiYosys before scoping Phase 7 (item 4 above).

---

## 17. Success criteria

| # | Criterion | Status |
|---|---|---|
| S1 | Write-based attack confirmed or refuted on Paper 1 | **DONE — A3/A6 confirmed independently** |
| S2 | Sensitivity map covers all chain bits × ≥10 capture points × ≥32 key pairs | **DONE — 645 bits × 16 capture points × 32 random pairs (§5c)** |
| S3 | Hardened design: A1-A6 all give 0 bits recovered/controlled or documented residual | **Partial.** G4 blocks every asserted row (A1, A2, A2b, A2c, A3, A3b, A3c, A6, A6@1, A9) in one 58-check tb with mutation checks (s5f); G2/G3/G2R measured and shown NOT to be complete write defenses. Through the full top-level (`tb_attack_top_def`, s5h): G4+L1 blocks A1/A2/A3/A6 driven by the real CPU with the real v2 lock; P1/G1 block only A1. A4 through the top-level and A5 still deferred. |
| S4 | A4 requires >2^32 effort or is blocked by lockout | **Partly done.** L1 built; unit + integration tests pass; cost formula verified at scaled parameters; >2^32 effort at real parameters is a projection. Wired into `secure_scan_rv_top_def` and exercised through the real CPU at scaled parameters (s5g). Not synthesized |
| S5 | Write-side non-interference proved on at least G4, with a failing negative control | Not started |
| S6 | Functional AES unchanged (KAT bit-exact, `tb_scan_resume` 20/20, `tb_cpu_driven_aes` PASS) for every variant | Baseline confirmed for G0/G1. For `_def` variants: unlocked lockstep equivalence (900 random cycles) and `tb_def_functional` (KAT + back-to-back KAT, L1-L5 locked and unlocked) PASS. **`tb_scan_resume` 20/20 on each of L1-L5 (100/100) and the CPU-driven KAT on all DEFENSE_LEVEL 0-5 x LOCK_VERSION 0-2 (18/18) PASS (s5g).** Functional side of S6 met in simulation for every variant; no hardware or post-synthesis run. |
| S7 | Overhead reported as a spread over ≥3 directives vs. a correct baseline | Not started |
| S8 | Testability metric T1 (+T2) reported for G0/G1 vs G2/G4 | **T1 done (s5i):** writable/observable per variant measured -- G1 0 observable but 388/645 writable, G4 0/0, G2 tail 132 writable, G2R tail observable-not-writable. **T2 done (s5j):** all variants 645/645 testable unlocked; 10/10 stuck-at faults detected; locked recovery matches T1. T3 appendix-only. |
| S9 | Every paper claim traceable to a passing test, proof, or report | In progress — this document is entry 1 |

**Non-goals:** proving AES itself secure; power/EM side channels; ASIC
signoff; full-chip ATPG coverage; PC/pipeline scan without disclosing it as a
core edit.
