# Claims → Evidence (Paper 2)

Every claim Paper 2 intends to make, mapped to the exact testbench or check
that backs it, so §17 S9 ("every claim traceable to a passing test, proof, or
report") can be audited. All simulation is Icarus Verilog 12.0. "Ran here"
means reproduced in the current git repo; see `PROJECT_README.md` sections in
the last column. Nothing here is synthesized or formally proved — those are
explicitly marked "pending".

Run everything with `./run_regression.sh` (28 gated testbenches, all PASS).

## Attacks (the problem)

| Claim | Evidence (testbench / check) | Golden checked against | README |
|---|---|---|---|
| A1 scan-read recovers the key on the undefended design; Paper 1 lock blocks it | `tb_scan_attack`, `tb_attack_matrix`, `tb_attack_defenses` (A1/A8/A9) | key `000102..0f` recovered / absent from 645-bit stream | §5a, §5e, §6 |
| A3 key+plaintext injection: 128 locked shifts make the core encrypt an attacker key+plaintext, no unlock | `tb_attack_write_inject`, `tb_attack_defenses` (A3), `tb_attack_top_def` (A3, through the real CPU) | `AES(EVIL,000102..0f)=50b58e80..` (pycryptodome) | §5a, §5f, §5h |
| A3 also corrupts `block_stage` (plaintext), so it is key+plaintext not key-only | `tb_attack_write_inject` (F8 cases), `tb_sensitivity` (F2a) | — | §5b, §5c |
| A2 ciphertext spoof: a bare READRESULT after scan-forcing `state_reg` returns a forged ciphertext, in G0 and G1 | `tb_attack_modeswitch` (M3-A/M3-B), `tb_attack_defenses` (A2/A2c), `tb_attack_top_def` (A2) | forged `FFFFFFFF` / all-ones word | §5e, §5f, §5h |
| A6 zeroize: locked shifting wipes `round_key_reg` (128) and `key_reg` (256) | `tb_zeroize` (97 checks, model-exact), `tb_attack_defenses` (A6/A6@1) | independent 645-bit shift model | §5b, §5f |
| A4 brute force: v1 lock is one guess/clock, no limiter, worst case 2^32 = 42.95 s @100 MHz | `tb_attack_bruteforce` (14 checks) + arithmetic | — (2^32 derived, not simulated) | §5d, §6 |
| K10 (`round_key_reg` at DONE) inverts to the master key (Paper 1 errata) | `tb_sensitivity` (F6), independent Python key schedule | K10 `13111d7f..30c5` → `000102..0f` | §5c |

## Defenses (the fix)

| Claim | Evidence | README |
|---|---|---|
| G1 (Paper 1) blocks read only; A2/A3/A6 still succeed | `tb_attack_matrix`, `tb_attack_defenses`, `tb_attack_top_def` | §5e, §5f, §5h |
| G2 granular masking leaves the tail writable (plaintext corrupts, ENCRYPT can hang) | `tb_attack_defenses` (G2 cols) | §5f |
| G2R recirculating tail: observable but not injectable; still corrupts plaintext / hangs | `tb_attack_defenses` (G2R cols), `tb_testability_t1` (0 writable, tail observable) | §5f, §5i |
| G3 flush-on-edge defeated by holding `scan_en` high; one shift zeroizes the key | `tb_attack_defenses` (G3 A2c, A6@1) | §5f |
| **G4 write-blocking blocks A1/A2/A2b/A3/A3b/A3c/A6/A6@1/A9** | `tb_attack_defenses` (58 checks), `tb_attack_top_def` (A1/A2/A3/A6 via real CPU+lock) | §5f, §5h |
| Only G4 blocks every asserted attack row | `tb_attack_defenses`, `tb_attack_top_def` | §5f, §5h |
| Unlocked, every variant is cycle-identical to the undefended design | `tb_defense_equiv` (900 random cycles, L1-L5 unlocked; L1 locked) | §5f |
| Functional AES unchanged per variant: KAT, back-to-back KAT, resume, real-CPU | `tb_def_functional` (10 cells), `tb_scan_resume_def` (100 cases), `tb_cpu_driven_aes_def` (18 configs) | §5g |
| L1 lock: lockout + boot delay + no default code; ~45 yr worst case at defaults | `tb_lock_v2` (25 checks, 10 mutants), `tb_scan_lock_v2` (17 checks), `tb_cpu_driven_aes_def` (v2 through the CPU) | §5d, §5g |
| Rule BOOT_DELAY ≥ LOCKOUT (else reset-cycling is cheaper) | `tb_lock_v2` (measured both ways) | §5d |

## Testability

| Claim | Evidence | README |
|---|---|---|
| T1: Paper 1 is read-locked but write-open — 0 observable, 388/645 writable while locked | `tb_testability_t1` (gated assertions) | §5i |
| T1: G4 is 0 writable AND 0 observable while locked (whole chain frozen) | `tb_testability_t1` | §5i |
| T1: G2 freezes the 4 sensitive segments, tail (132) still writable / (133) observable | `tb_testability_t1` | §5i |
| T2: every variant is fully testable UNLOCKED (645/645 flush recovery) | `tb_testability_t2` | §5j |
| T2: a flush test detects injected scan stuck-at faults (10/10) | `tb_testability_t2` | §5j |

## Verification-of-the-tests (mutation)

| Claim | Evidence | README |
|---|---|---|
| The defense testbenches catch real RTL bugs (not vacuous PASS) | `mutate.py` 12/12 caught; +2 new-tb mutants (top-level ungate, resume stale-done); +2 T-metric-adjacent | §5f, §5g, §5h |

## Pending (not simulated / not proved here)

| Item | Status |
|---|---|
| Vivado overhead (LUT/FF/WNS) for G0/G1/G4, ≥3 directives | owner's machine |
| Write-side non-interference formal proof on G4 + negative control | SymbiYosys not confirmed installable |
| A5 CPU register-file attack | appendix extension, deferred |
| Board write-demo, S1 debug-tap removal | deferred / disclosure only |
