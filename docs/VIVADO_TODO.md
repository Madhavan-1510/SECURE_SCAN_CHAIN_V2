# Vivado run-list + what to send back

Two Vivado jobs: **(A) overhead numbers** (the paper's cost table) and
**(B) the board demo capture** (you already have the bitstream). Plus the
board serial transcript. That's all that's left on the hardware side.

---

## A. Overhead / utilization + timing  (top = `secure_scan_rv_top_def`)

You edit the two parameters **in the RTL** (`RTL/secure_scan_rv_top_def.v`,
lines 24–25) before each run — leave `LOCKOUT_CYCLES`/`BOOT_DELAY_CYCLES` at
their defaults (they're just counter widths, fine for synthesis):

```
parameter integer DEFENSE_LEVEL = <see table>;
parameter integer LOCK_VERSION  = <see table>;
```

**Constraints for this top:** do NOT use the board XDC (this top has no
sw/led/uart ports). Use a **clock-only** XDC:
```
create_clock -period 10.000 -name sys_clk [get_ports clk]
```
(10.000 ns = 100 MHz. Keep the SAME part and this SAME clock for every row so
the numbers are comparable.)

**Runs (5 rows; the first two are sanity checks):**

| Row | DEFENSE_LEVEL | LOCK_VERSION | Meaning |
|---|---|---|---|
| 1 | 0 | 0 | G0 undefended baseline |
| 2 | 1 | 1 | G1 = Paper 1 lock |
| 3 | 4 | 1 | G4 write-block only |
| 4 | 4 | 2 | **G4 + L1 (the proposed design)** |
| 5 (optional) | 2 / 3 / 5 | 1 | G2 / G3 / G2R ablations |

For **each** row: run **Synthesis → Implementation** (you need implementation for
timing; no bitstream needed). Then in the Tcl console export two reports:

```tcl
report_utilization    -file util_DL<d>_LV<l>.rpt
report_timing_summary  -file timing_DL<d>_LV<l>.rpt
```
e.g. `util_DL4_LV2.rpt`, `timing_DL4_LV2.rpt`.

**Spread (do this for at least rows 1–4):** re-run **Implementation** 3× with
different directives so the paper can report mean/min/max instead of one
number. Easiest: Implementation Settings → Strategy, pick 3 different ones
(e.g. `Performance_Explore`, `Area_Explore`, `Default`), or set 3 placer seeds.
Name the reports `..._run1/2/3.rpt`. (This also fixes a Paper 1 erratum — they
reported a single Fmax with no spread.)

**Sanity gate:** rows 1–2 should land near Paper 1's numbers (baseline ≈ 2,828
LUT / 1,225 FF / WNS 2.502 ns; defended ≈ 2,842 LUT / 1,226 FF / WNS 2.084 ns).
If they don't, stop and tell me — the setup differs and the other rows won't be
comparable.

### Send me (A)
- The `util_*.rpt` and `timing_*.rpt` files (all rows, all runs), **or** just a
  copy-paste of, per run: **LUT, FF, (BRAM/DSP if any), and WNS / achieved Fmax**.
  I'll build the overhead table (PAPER_REFERENCE §10 Table A) and the per-row
  spread.

---

## B. Board demo capture  (top = `board_top_def`, bitstream already built)

XDC = `CONSTRAINTS/board_top_def.xdc`. Program the board, open a serial terminal
at **115200 8N1** (or `python3 scripts/scan_console.py --port <COM> --demo`).

Run this sequence and capture it (copy the terminal text + a couple of photos):

1. `S` → shows `locked=1` out of reset.
2. `U5EC2E7A1` → unlock; `S` shows `locked=0`.
3. `K000102030405060708090A0B0C0D0E0F`, `B00112233445566778899AABBCCDDEEFF`,
   `E` → should print `E 69C4E0D8...` (the KAT). **This proves it works.**
4. `L` (relock), then `R` → all zeros (**read lock**, both defenses).
5. **`sw[0]=0` (G1):** `U5EC2E7A1`, reload `K`/`B`, `L`, then
   `W0F1E2D3C4B5A69788796A5B4C3D2E1F0`, `E` → ciphertext **changes** to
   `50b58e80...` (**write attack succeeds**).
6. **`sw[0]=1` (G4):** same `W...` then `E` → returns the true KAT
   `69C4E0D8...` (**write attack blocked**).

### Send me (B)
- The serial transcript of steps 1–6 (text is enough).
- Optional but nice for the paper: 2–3 photos — board with LEDs in locked vs
  unlocked state, and the terminal showing the G1-changes / G4-holds contrast.

I'll drop these into PAPER_REFERENCE §9 (board) and the paper's demo figure.

---

## C. Remaining phases (apart from the formal write-side proof, which we paused)

| Phase / item | Who | Status |
|---|---|---|
| Phase 5 defenses (RTL, attacks, G1–G4, L1, 30/30 sim) | done | ✅ |
| **Overhead numbers (job A)** | **you** | ⏳ only this closes Phase 5 |
| Phase 7 — T1 testability | done | ✅ |
| Phase 7 — T2 chain-integrity + stuck-at | done | ✅ |
| Phase 7 — formal read-lock proof (G4) | done | ✅ (committed) |
| Phase 7 — formal write-side proof | paused | ⏸ future work (defensible to omit) |
| Phase 7 — T3 ATPG fault coverage | optional | ○ appendix only, not required |
| **Board hardware capture (job B)** | **you** | ⏳ evidence for the demo section |
| Phase 8 — write the IEEE paper | you + me | ◻ not started; PAPER_REFERENCE.md is the source |
| GitHub reconnect so commits push | you | ⏳ still 403 |

**Net:** after you send me (A) the synthesis reports and (B) the board
transcript, the evidence chain is complete except the (optional) formal
write-side proof and T3. Then it's just writing — and I can draft any section of
the paper from PAPER_REFERENCE.md whenever you want.

## D. Optional enhancements (only if you want more novelty; all doable in sim here)
- LBIST mode — "secure **and** testable while locked" (removes the one real
  criticism of G4). Highest-impact add.
- Adaptive / multi-session attacks — hardens the "G4 blocks everything" claim.
- Finish the write-side formal proof (staging-register scope) — quick to retry.
Say the word on any of these; none block the paper.
