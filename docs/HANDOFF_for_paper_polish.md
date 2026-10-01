# Handoff — to finish SecureScan-RV into a publishable IEEE paper

Give the files in Part 1 to the next assistant, paste the prompt in Part 2, and
work the checklist in Part 3. Everything here is already produced and verified;
the remaining work is author details, reference verification, venue formatting,
and optional extras — not new engineering.

---

## Part 1 — What to upload / hand over

**Essential (the paper cannot be polished without these):**
1. `paper/SecureScanRV_Paper2.docx` — the IEEE two-column draft (the paper itself).
2. `docs/PAPER_REFERENCE.md` — the SINGLE SOURCE OF TRUTH. Every verified number,
   the attack/defense results, the Vivado table, the board demos, the reference
   list, and the section-by-section evidence map. The assistant should trust this
   over anything it re-derives.
3. `paper/figures/` — all paper figures (fig_top, fig_chain, fig_g4, fig_overhead,
   fig_t1) and `paper/figures/board/board1..6.jpg` (the hardware photos).

**Strongly recommended (context + the long report):**
4. `paper/SecureScanRV_Project_Report.docx` — the ~30-page explanatory report
   (background, every file, every attack/defense, glossary). Great context.
5. `docs/claims_to_evidence.md` — every claim mapped to the testbench that proves it.
6. `results/vivado/` — the raw utilization and timing reports (the overhead numbers).
7. The four PuTTY screenshots (Demo 1, Demo 3, Demo 4.1, Demo 4.2) if kept.

**Optional (only if they want to re-verify or regenerate):**
8. The whole repo (GitHub `Madhavan-1510/SECURE_SCAN_CHAIN_V2`, branch
   `claude/wizardly-faraday-4pdlp5`): `RTL/`, `TB/`, `formal/`, `run_regression.sh`,
   `mutate.py`, and the figure generators `paper/build_paper.js` / `build_report.js`.
9. The target venue's own template (the IEEE Word/LaTeX template the committee requires).

**Simplest option:** hand over the whole repo zip plus the venue template. It
contains all of the above.

---

## Part 2 — Prompt to paste into the new chat

> I have a finished final-year hardware-security project and a near-complete IEEE
> conference paper draft. Help me turn it into a submission-ready paper.
>
> Treat `PAPER_REFERENCE.md` as the authoritative source for every number and
> claim — do not invent or change results. The draft is `SecureScanRV_Paper2.docx`.
> The work: a RISC-V (PicoRV32) SoC with a PCPI-coupled AES-128 coprocessor on a
> 645-bit shared scan chain. Paper 1 masked the scan output (read lock); this paper
> (Paper 2) shows the scan WRITE path is still open, demonstrates key/plaintext
> injection, ciphertext spoofing and key erase through the locked scan port,
> builds a write-blocking segmented lock (G4) plus a hardened unlock controller
> (L1), evaluates three weaker variants as ablations, measures FPGA overhead on a
> Spartan-7, proves the locked-read property formally, and demonstrates everything
> live on hardware. 30/30 testbenches pass.
>
> Please: (1) tighten the writing to the venue's template and length; (2) verify
> and complete the reference list (authors, venue, year, DOI); (3) fill the author
> block; (4) add the title footnote; (5) flag anything that reads as overclaiming
> and make it precise; (6) keep the attack × defense matrix, the T1/T2 testability
> results, the Vivado overhead table, and the board photos as the core evidence.
> Ask me for anything you need. Do not weaken any honest limitation.

---

## Part 3 — Checklist to reach "publishable"

**Must do:**
- [ ] Author block: real names, affiliations, emails/ORCID (2 authors, 5 lines each).
- [ ] Title footnote for the `*` (funding / acknowledgement, or remove the `*`).
- [ ] Verify EVERY reference against the actual paper: authors, venue, volume,
      pages, year, DOI. `PAPER_REFERENCE.md` §13 marks which are confirmed and
      which say "confirm before citing" — resolve all of those.
- [ ] Reformat to the exact venue template (margins, fonts, column rules). Use
      the committee's own Word/LaTeX template, not just the generic one.
- [ ] Run the venue's similarity/plagiarism check; ensure the novelty framing vs
      DefScan and the secure-scan prior art is explicit (it is in §2 — keep it).
- [ ] Proofread once end to end; confirm figures and tables are referenced in order.

**Strongly recommended (raise acceptance odds):**
- [ ] 3-seed Fmax spread: re-run Vivado implementation 3x per config with
      different strategies/seeds; report mean/min/max (fixes a Paper 1 erratum).
- [ ] Add the board-photo pair (G1 `90C5DFD7` attack vs G4 `70B4C55A` blocked) as
      a prominent figure — it is the strongest single visual (already in the draft).
- [ ] Confirm the abstract is 250–300 words and has no symbols (current: 288, clean).

**Optional (strengthen, not required):**
- [ ] Add G2/G3/G2R overhead rows to the cost table.
- [ ] Finish the write-side formal proof (read-side proof is already done).
- [ ] Add an LBIST "secure-and-testable while locked" paragraph as future work.

---

## Part 4 — Facts the next assistant must not get wrong (quote from here)

- Chain: 645 bits total, 256 protected (key_reg + round_key_reg). ~39.7%.
- KAT: key `000102...0F`, plaintext `00112233...FF`, ciphertext
  `69C4E0D86A7B0430D8CDB78070B4C55A`. 7-seg low word `70B4C55A`.
- Injection (attacker key `0F1E2D3C...E1F0`): ciphertext
  `50b58e80ce784e98ad48d63390c5dfd7`; 7-seg low word `90C5DFD7`.
- Erase: AES(0,0) = `66e94bd4ef8a2c3b884cfa59ca342b2e`.
- Only G4 blocks A1 (read), A2 (spoof), A3 (inject), A6 (erase). G1 blocks read only.
- T1 while locked: G1 = 0 readable but 388/645 writable; G4 = 0/0.
- T2: all variants 645/645 testable UNLOCKED; 10/10 stuck-at faults detected.
- Overhead (Spartan-7): baseline 2830 LUT / 1225 FF; G1 +14 LUT/+1 FF (matches
  Paper 1); G4 +13 LUT/+1 FF; G4+L1 +58 LUT/+35 FF (~2%); Fmax > 120 MHz.
- Regression: 30/30 pass (Icarus 12.0). Mutation: all mutants caught.
- Formal: locked-read property proved by k-induction (Yosys + SymbiYosys + Z3).
- Board: Boolean Board XC7S50; red = locked, green = unlocked; 7-seg = ciphertext
  low word; sw[0] selects G1 (0) vs G4 (1).
- Do NOT claim: "provably secure" (only the read property is proved), a full
  write-side proof, or any overhead number not in the Vivado reports.
