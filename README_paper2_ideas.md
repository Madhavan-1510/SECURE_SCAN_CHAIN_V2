# Paper 2 — Ideas, Plan and References

Follow-up to: *Segmented Secure Scan Lock for a PCPI-Coupled AES Coprocessor on a RISC-V Processor* (paper 1).
Platform already available: PicoRV32 + PCPI AES-128 + scan cells/chains + lock controller, Boolean Board (XC7S50), 12-testbench Vivado regression, +14 LUT / +1 FF baseline.

Status legend: **[verified]** = seen in a search result this session; **[hypothesis]** = not simulated yet.

---

## 0. Fixes to paper 1 before reusing it as a base

1. Refs [17] (floorplanning) and [18] (character-recognition accelerator) do not support the sentences they are cited for. Replace or drop the sentences.
2. Refs [15] and [16] are never cited in the body.
3. Fig. 3 caption says "Table III"; the reconstruction is Table II.
4. Abstract: "zero functional overhead" sits next to a ~5% Fmax drop. Say "zero effect on encryption correctness".
5. Fmax explanation (placer layout) is asserted, not shown. Run 3-5 placer seeds per configuration.
6. "First reconstruction of the complete 645-bit scan segment from live hardware" is hard to defend. Soften it.
7. Verify the DefScan author list against the paper itself (TCAD 2024, DOI 10.1109/TCAD.2024.3368289 per its IEEE/ACM listing).

---

## 1. Candidate topics

### A. Shared-chain extension (promised in paper 1's conclusion)
- Put PicoRV32 state (register file, PC) into the scan chain.
- Replace the single output mux with a true boundary over only the 256 sensitive bits.
- Report chain composition (key material vs CPU state vs control) and testability retained under lock.

### B. CPU-side key exposure (likely the strongest new result)
- In `board_top.v` the firmware loads the key via `lui`/`addi` into CPU registers and it sits in program memory.
- Once the register file is scannable, the key exists in flops outside the coprocessor lock.
- Result: coprocessor-only masking is insufficient in a shared chain; show a lock that covers the CPU path.
- Combines naturally with A.

### C. Scan-write / functional-read attack on the output-only lock (see section 2)

### D. Lock hardening
- Current lock: fixed 32-bit compare, no attempt limit, code presented straight from a switch.
- Options: attempt counter with lockout, per-device code, challenge-response, relock on mode switch.
- Small on its own; best as a section of A or C.

### E. Fault-coverage measurement
- Paper 1 says testability is preserved but does not measure it.
- Inject stuck-at faults in simulation, measure coverage unlocked vs locked (blanket mask vs granular boundary).
- Pairs with A, since "testability retained under lock" needs exactly this number.

---

## 2. The attack idea in detail (Topic C)

**Framing (important):** not "paper 1 fails". Paper 1 secures the scan-read path against a scan-read attacker. Paper 2 extends the threat model to a scan-write attacker and hardens the design. If the attack fails, the paper is "a stronger attacker was tested and the design holds".

**Mechanism [hypothesis, not simulated]**
- The lock masks `scan_out` and the scan-in of `round_key_reg` only.
- `round_reg` and `state_reg` sit upstream of the mask, so they remain scan-writable while locked.
- `ciphertext_o` = `state_reg_q`, readable by the CPU via `READRESULT`.
- Next state = `MixColumns(ShiftRows(SubBytes(state))) ^ next_round_key`, and `next_round_key` derives from `round_key_reg`.
- Attacker: scan-inject chosen `round_reg`/`state_reg`, drop `scan_en`, clock one functional step, read result over PCPI.

**Known obstacle:** shifting to load `round_reg`/`state_reg` also shifts `round_key_reg` and `key_reg` (zeros enter `round_key_reg` while locked). Loading all 132 bits probably wipes the key, so the full-state version likely fails. Partial shifts are the interesting case: a short shift may disturb only a few key bits, leaving most recoverable with small brute force. **First step: write the testbench and see.**

**Novelty caveat:** the general attack classes are established (see references). Your contribution would be the PCPI-coupled-coprocessor context, a concrete break of (or proof of resistance of) an output-only mask lock, and a hardened boundary with measured overhead.

**Plan**
1. Attack testbench: scan-inject while locked, functional step, read via PCPI, check for key-dependent information.
2. Quantify: bits leaked, at which shift counts, residual brute-force effort.
3. Harden: mode-switch reset/flush, gate `scan_en` (or scan-in) while locked, or isolate the whole datapath.
4. Re-run the identical attack at all shift points against the hardened design.
5. Vivado overhead vs paper 1 baseline, multiple placer seeds.
6. Optional: add PicoRV32 registers (merges with A/B).

### References for the attack idea [all verified as existing via search; confirm exact authors/pages before citing]

**Foundational scan attacks / secure scan**
- B. Yang, K. Wu, R. Karri, "Scan based side channel attack on dedicated hardware implementations of Data Encryption Standard," Proc. ITC 2004, pp. 339-344.
- B. Yang, K. Wu, R. Karri, "Secure scan: a design-for-test architecture for crypto chips," DAC 2005, pp. 135-140; IEEE TCAD vol. 25, no. 10, 2006, pp. 2287-2293.

**Functional-mode and mode-switching attacks, and mode-reset countermeasures**
- "Securing Cryptographic Chips against Scan-Based Attacks in Wireless Sensor Network Applications," Sensors 2019, 19(20), 4598, doi:10.3390/s19204598. Describes mode-switch clearing and test-control isolation of the key. (Authors: check.)
- "Enhancing Sensor Network Security with Improved Internal Hardware Design," Sensors 2019, 19(8), 1752, doi:10.3390/s19081752. Defines the functional-mode and mode-switching attacks; countermeasure ANDs shift-enable with a mode-select signal. (Authors: check.)
- US Patent 8,051,345, "Method and apparatus for securing digital information on an integrated circuit during test operating modes." Prior art for resetting registers before/after scan mode.

**Test-mode-only attacks (attacker only uses scan; defeats mode-switch-reset)**
- "New scan-based attack using only the test mode," IEEE conference paper (IEEE Xplore document 6673281). (Authors/venue: check.)
- "Test-mode-only scan attack using the boundary scan chain," (ResearchGate listing, 2014). (Authors/venue: check.)
- "Test-mode-only scan attack and countermeasure for contemporary scan architectures," (2014 listing). (Authors/venue: check.)
- "Novel Test-Mode-Only Scan Attack and Countermeasure for Compression-Based Scan Architectures," IEEE TCAD, 2015, DOI 10.1109/TCAD.2015.2398423.

**Compaction / compression interplay**
- J. DaRolt, G. Di Natale, M.-L. Flottes, B. Rouzeyre, "Scan attacks and countermeasures in presence of scan response compactors," ETS 2011, pp. 19-24.
- A. Das, B. Ege, S. Ghosh, L. Batina, I. Verbauwhede, "Security analysis of industrial test compression schemes," IEEE TCAD vol. 32, no. 12, 2013, pp. 1966-1977.
- Y. Sao, K. K. Soundra Pandian, S. Subidh Ali, "Revisiting the security of static masking and compaction: discovering new vulnerability and improved scan attack on AES," AsianHOST 2020.

**Countermeasures worth comparing against**
- J. DaRolt, G. Di Natale, M.-L. Flottes, B. Rouzeyre, "Thwarting scan-based attacks on secure-ICs with on-chip comparison," IEEE TVLSI vol. 22, no. 4, 2014, pp. 947-951.
- J. Lee, M. Tehranipoor, J. Plusquellic, "A low-cost solution for protecting IPs against scan-based side-channel attacks," VTS 2006, pp. 94-99.
- DefScan (already in paper 1 as [1]).

**Attacks on obfuscation-style locks**
- ScanSAT: "Unlocking static and dynamic scan obfuscation," arXiv:1909.04428. (Authors: check.)

---

## 3. More options (beyond the scan-attack line)

### F. Formal proof of the lock property (novel and very doable)
Use a formal tool (e.g. SymbiYosys/Yosys) or gate-level information-flow tracking to prove "when locked, no key-dependent bit reaches `scan_out`", and see what it says about scan-write plus functional-read. A formal noninterference check on a PCPI-coupled coprocessor lock is a clean contribution, and the tool will either find the leak or certify the design. Pairs well with C.

### G. Scan compression vs your mask
Add an XOR compactor or small decompressor to the chain and test whether the mask still holds. The test-mode-only/compaction papers above show this is a real weak point of masking schemes; doing it on a PCPI SoC is the new part.

### H. Debug-port (JTAG-style) security for the SoC
Scan is one door to the registers; a debug TAP is another. Add a small TAP or debug module to PicoRV32, show what it exposes, and extend the lock to gate it.

### I. Multi-domain lock
Generalize the lock to several protected segments (AES key, boot key, debug unlock state) with different privilege levels and one shared controller.

### J. Scan-chain encryption / test-pattern encryption on the shared chain
Compare your masking boundary with an encrypted-scan-data approach on the same platform, with measured overhead. (Prior scan-encryption work exists; the PCPI/shared-chain angle is the new part.)

### K. BIST for the coprocessor
LFSR pattern generation plus MISR signature, with stuck-at fault coverage. Standard DFT, lower novelty. Related prior art: Doulcier, Flottes, Rouzeyre, "AES-based BIST: self-test, test pattern generation and signature analysis," VTS 2007.

### L. Connect to AURA-FPGA
Use scan or BIST as the fault-detection mechanism for radiation-induced soft errors. Speculative; needs a literature check first.

---

## 4. Suggested combinations

| Combination | Novelty | Effort | Notes |
|---|---|---|---|
| A + B (+ E) | High | High | Delivers the promised extension; needs RTL changes and new Vivado runs |
| C + D + F | High | Medium | Reuses most existing RTL; formal proof strengthens either outcome |
| C + G | Medium-high | Medium | Attack plus compression interaction |
| A + B + C | Highest | Highest | Full "what happens when the chain is actually shared" paper |

Recommended: **C + F as the core (fast, publishable either way), extended toward A + B if time allows.**

---

## 5. Claims discipline
- Only claim what is measured on your RTL/board.
- The attack hypothesis in section 2 is unverified until the testbench runs.
- Confirm every reference's authors, venue, volume and pages against the actual papers before finalizing the bibliography.

---

## 6. Novelty check (run 28 Sep 2026)

**Method and limits:** five web searches (scan-injected DFA, formal verification of scan security, scan security on RISC-V SoCs, secure BIST for crypto, plus the earlier attack/compression searches). This is a screening pass, **not a systematic literature review**. "Not found" here does not mean "does not exist". Before committing to a topic, repeat the search on IEEE Xplore / Google Scholar / dblp with several keyword variants. Authors/venues below come from search snippets and must be confirmed against the papers.

### 6.1 Scan-injected DFA (the "DFA via scan chain" suggestion)
- **Not found** as an established topic in these searches, but that is weak evidence.
- Related work found:
  - Classic DFA: Biham & Shamir (Crypto 1997); Dusart, Letourneux, Vivolo, "Differential fault analysis on AES," ACNS 2003, pp. 293-306.
  - Scan chains used for fault injection in *fault-tolerance evaluation* (Thor microprocessor study; a gate-level embedded-processor fault-testing paper using a scan chain to inject faults).
  - "Fault-Injection Based Chosen-Plaintext Attacks on Multicycle AES," GLSVLSI 2022 (Auburn University group). Uses scan-chain access to observe the round register together with chosen plaintexts, so **scan-assisted chosen-plaintext attacks on iterative AES already exist**.
- **Technical problem remains:** the chain is one serial register, so a byte-precise fault means shifting the whole chain (which wipes the round key when locked). Precise DFA faults are not available through scan on your design.
- **Verdict:** not novel enough to claim, and technically awkward. Cite the Auburn paper if you keep Topic C.

### 6.2 Formal verification of the scan lock (Topic F)
- **Formal analysis of scan security already exists:**
  - "Design-for-Security vs. Design-for-Testability: A Case Study on DFT Chain in Cryptographic Circuits" uses gate-level information-flow assurance to formally prove that inserting a scan chain can violate security properties, and extends this to BIST structures. (Authors/venue: confirm.)
  - "A Formal Framework for Gate-Level Information Leakage Using Z3" (2020 listing).
  - SecVerilog: a hardware description language for static information-flow analysis with a noninterference proof.
  - Hardware-Trojan detection via information-flow verification, arXiv:1803.04102.
  - Industry write-ups list debug scan chains and JTAG as standard sources in formal security verification.
- **What is still open (by these searches):** proving a **lock/mask boundary** correct at RTL, covering scan-write followed by functional-read, on a **PCPI-coupled coprocessor**, with open-source tools and FPGA validation.
- **Verdict:** medium novelty. The framing must be "formal verification of a scan lock's masking property," not "formal analysis of scan chains."

### 6.3 Scan security on RISC-V SoCs / shared chain (Topics A, B)
- Searches returned only RISC-V crypto coprocessor papers (Crypto-RV, AES-RV, ATHOS, CryptRISC) focused on performance or power side channels, plus RISC-V leakage papers on microarchitecture. **No scan-chain security work on a RISC-V + coprocessor SoC surfaced.**
- Closest: "Secure Software/Hardware Hybrid In-Field Testing for System on Chip" (already your ref [15]; VLSI-SoC 2024; KMAC-based response compaction with per-device keys) and "Secure Mutual Testing Strategy for Cryptographic SoCs" (IACR ePrint 2014/544).
- **Verdict:** the gap looks real, but confirm with a proper search. This remains the strongest novelty angle.

### 6.4 Scan compression vs masking (Topic G)
- **Heavily studied already:** DaRolt 2011; Das 2013; test-mode-only attack on compression (TCAD 2015); a modified differential scan attack on AES with X-masking/X-tolerance; a statistical security analysis of AES with an X-tolerant response compactor against all test-infrastructure attacks; an on-chip-comparison secure output response compactor.
- **Verdict:** low novelty unless the contribution is specifically the PCPI/shared-chain context with a compactor-aware boundary.

### 6.5 Secure BIST / LBIST for AES (Topic K, Option 3)
- **Already crowded:**
  - Doulcier, Flottes, Rouzeyre, "AES-based BIST: self-test, test pattern generation and signature analysis," 2007. Also proves the AES loop-back gives full fault coverage.
  - "Low-Cost Self-Test of Crypto Devices" (2008 listing) and "Self-Test Techniques for Crypto-Devices" (2010 listing; also surveys scan attacks and JTAG).
  - "Challenge-response based secure test wrapper for testing cryptographic circuits" (KATAN-based wrapper).
  - "A dual mode self-test for a stand alone AES core," PLOS ONE 2021.
  - Keyed LBIST against BIST-aliasing Trojans, arXiv:1511.07792.
  - "Secure Mutual Testing Strategy for Cryptographic SoCs" (ePrint 2014/544).
- **Verdict:** lowest novelty. I could not verify the FIPS 140-3 wording from the other assistant's answer.

### 6.6 New related work for the lock-hardening idea (Topic D)
- "Secure Scan Architecture Based on Hidden Authorization and Dynamic Replacement," Journal of Electronic Testing (Springer, 2026): hidden authorization plus NLFSR-substituted scan data. Cite as recent related work.
- US patent 11971987 (scan-chain key leakage in logic locking) also describes resetting registers on test-mode transitions. This supports the mode-switch reset countermeasure as known prior art.

### 6.7 Novelty verdicts

| Topic | Concept novelty | Novel angle that survives | Risk |
|---|---|---|---|
| A + B shared chain + CPU key exposure | Gap appears real | PCPI/RISC-V shared chain, CPU-side key path | Needs RTL changes + new Vivado runs |
| C scan-write / functional-read | Attack class is known | Concrete test of an output-only mask lock on PCPI coprocessor, plus hardened boundary | Attack may fail (still a publishable negative result) |
| F formal proof of lock | Formal scan analysis exists | RTL-level proof of a masking boundary incl. write-read path | Tool learning curve |
| G compression vs mask | Heavily studied | Only the PCPI/shared-chain context | Low |
| Scan-injected DFA | Not confirmed, technically awkward | None clear | High |
| LBIST for AES | Crowded | None strong | High |

**Updated recommendation:** C + F as the core (reuses your RTL; publishable whichever way the attack goes), extended toward A + B for the strongest novelty. Drop scan-injected DFA and LBIST as headline topics.

### 6.8 Additional references from this pass (confirm all details before citing)
- E. Biham, A. Shamir, "Differential fault analysis of secret key cryptosystems," CRYPTO 1997.
- P. Dusart, G. Letourneux, O. Vivolo, "Differential fault analysis on AES," ACNS 2003, pp. 293-306.
- "Fault-Injection Based Chosen-Plaintext Attacks on Multicycle AES," GLSVLSI 2022.
- "Design-for-Security vs. Design-for-Testability: A Case Study on DFT Chain in Cryptographic Circuits."
- "A Formal Framework for Gate-Level Information Leakage Using Z3" (2020).
- SecVerilog (hardware information-flow type system, noninterference).
- Hardware Trojan detection through information flow security verification, arXiv:1803.04102.
- M. Doulcier, M.-L. Flottes, B. Rouzeyre, "AES-based BIST: self-test, test pattern generation and signature analysis," 2007.
- "Secure Mutual Testing Strategy for Cryptographic SoCs," IACR ePrint 2014/544.
- "Two Countermeasures Against Hardware Trojans Exploiting Non-Zero Aliasing Probability of BIST," arXiv:1511.07792.
- "A dual mode self-test for a stand alone AES core," PLOS ONE, 2021.
- "Secure Scan Architecture Based on Hidden Authorization and Dynamic Replacement," J. Electronic Testing, 2026.

---

## 7. Independent verification of the v2 PRD (run by Claude, 29 Sep 2026)

The v2 PRD's central load-bearing claim — A3 (key+plaintext injection) and A6 (zeroize) succeed against Paper 1's unmodified RTL while `locked=1` and never unlocked — was **independently re-run**, not just trusted from the uploaded document's narration. This matters because the whole paper's contribution ordering (G4-before-G2, "already de-risked", the trimmed 10-12 week plan) depends on this one result being real.

**Method:** copied the actual project RTL (`aes_pcpi.v`, `aes_core.v`, `aes_sbox.v`, `scan_chain.v`, `scan_cell.v`, `scan_lock_controller.v`) and the exact `tb_attack_probe.v` as supplied, compiled and ran with Icarus Verilog 12.0 (matching the tool version claimed in the PRD).

**Result: reproduced exactly**, byte-for-byte against the pasted output:
```
DBG after inject: key_stage=0f1e2d3c4b5a69788796a5b4c3d2e1f0 block_stage=000102030405060708090a0b0c0d0e0f
                  core_fsm=0 round_key=0...0 key_reg=0...0
Ciphertext after injected-key ENCRYPT: 50b58e80ce784e98ad48d63390c5dfd7
Ciphertext after 256-shift zeroize then encrypt: 66e94bd4ef8a2c3b884cfa59ca342b2e
```

**Went one step further than the testbench itself does — checked the AES math independently in Python (pycryptodome), not by trusting the testbench's own `$display` narration:**
```
AES_encrypt(EVIL_KEY=0f1e2d3c4b5a69788796a5b4c3d2e1f0, block_stage=000102030405060708090a0b0c0d0e0f)
  = 50b58e80ce784e98ad48d63390c5dfd7   -- MATCHES the DUT's ciphertext exactly
AES_decrypt(EVIL_KEY, ciphertext) = block_stage   -- confirmed both directions
```
This confirms, independently of the RTL author and the testbench's own claims, that the coprocessor genuinely encrypted the attacker-injected key/plaintext pair — not a testbench display bug or a coincidence.

**Closed the one gap the PRD itself flagged as still open:** the original `tb_attack_probe.v` only observed "the ciphertext changed" for A6, not a direct register assertion. Added:
```verilog
if (dut.u_aes_core.round_key_reg_q === 128'h0 && dut.u_aes_core.key_reg_q === 128'h0)
```
**Result: PASS.** `round_key_reg` and `key_reg` are both confirmed hard-zero after 256 shifts, while locked, matching F3's mechanism exactly.

### Verdict on the PRD

- **A3 and A6 are real, not fabricated or narrated-only.** Both independently reproduced from the actual RTL, with the ciphertext validated against an independent AES implementation rather than trusted from the DUT/testbench's own output.
- **The project is doable as scoped** — the RTL, the lock, the attack mechanism, and the testbench all match the real files with no invented modules, ports, or behavior.
- **The only remaining PRD issue is the timeline inconsistency** already flagged in this README (§ prior discussion): the phase-by-phase breakdown sums to ~14-16 weeks even with the stated parallelism, not the "10-12 weeks" the document concludes with. Reconcile this against actual available weeks before treating Phase 8 (paper writing) as fixed.
- Everything else in the v2 PRD (F1-F3 gating claims, file inventory, testbench count) was already cross-checked against the real project files in an earlier pass and held up.

**Practical implication:** you can proceed directly into Phase 2/3 of the v2 PRD's plan. The go/no-go gate is closed for real, on evidence obtained independently of the document that claimed it.
