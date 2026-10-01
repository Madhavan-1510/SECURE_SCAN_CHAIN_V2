# What changed since the first upload (for your Vivado project)

Baseline = the original `Secure_Scan_Chain_Final_Year_Project_V2.zip` you uploaded.
This lists every file to **add**, **replace**, or **remove** in your Vivado
project to match the current state. Nothing in your original RTL's *logic* was
altered except one file deleted and two comment-only header edits (noted below).

## 1. ADD these new files (Add Sources in Vivado)

### RTL (synthesizable — add to the design source set)
| File | Purpose | Needed for synthesis? |
|---|---|---|
| `RTL/secure_scan_rv_top_def.v` | CPU+AES top with `DEFENSE_LEVEL` (0/1..5) and `LOCK_VERSION` (0/1/2). Use for the G0/G1/G4 **Vivado overhead numbers**. | Yes, if you synthesize this top |
| `RTL/board_top_def.v` | Spartan-7 board demo top: G1 + G4 on one bitstream, UART console, `sw[0]` selects. | Yes, if you build the board demo |
| `RTL/scan_uart_bridge.v` | UART command console (PCPI master + scan driver). | Yes (used by `board_top_def`) |
| `RTL/uart_rx.v` | UART receiver (pairs with your existing `uart_tx.v`). | Yes (used by `board_top_def`) |

### TB (simulation only — add to the simulation source set, NOT synthesis)
`TB/tb_attack_top_def.v`, `TB/tb_board_top_def.v`, `TB/tb_cpu_driven_aes_def.v`,
`TB/tb_scan_resume_def.v`, `TB/tb_testability_t1.v`, `TB/tb_testability_t2.v`.

### Docs / scripts (not part of Vivado)
`docs/board_demo.md`, `docs/claims_to_evidence.md`, `scripts/scan_console.py`,
`.gitignore`, and this file.

## 2. REPLACE these (overwrite your copies)

| File | What changed |
|---|---|
| `RTL/aes_core_def.v` | **Comment-only.** First header line now names the file. Logic identical — a re-synth is not required, but replace so headers match. |
| `RTL/aes_pcpi_def.v` | **Comment-only.** Same as above. |
| `run_regression.sh` | Rewritten for the `RTL/`+`TB/` layout, now 30 gated testbenches. Simulation helper; not used by Vivado. |
| `mutate.py` | Mutation-test runner, adapted to the folder layout. Not used by Vivado. |
| `PROJECT_README.md` | Status/results doc. Not used by Vivado. |

## 3. REMOVE this (delete from your Vivado project)

| File | Why |
|---|---|
| `RTL/secure_scan_rv_top.v` | Legacy v1 top, unused by anything. Delete it from the project tree. |

## 4. UNCHANGED (do nothing)

Every other file from your upload is byte-identical, including all your
original RTL (`aes_core.v`, `aes_pcpi.v`, `picorv32.v`, `scan_*`,
`board_top.v`, `secure_scan_rv_top_v2.v`, etc.), `aes_pcpi_defs.vh`, and
`CONSTRAINTS/constraints.xdc`. **The XDC is reused as-is** — its port names
already match `board_top_def`.

## 5. What to actually set as "top" in Vivado, by goal

| Goal | Top module | Constraints | Notes |
|---|---|---|---|
| Overhead numbers G0/G1/G4 | `secure_scan_rv_top_def` | clock-only XDC (`create_clock` on `clk`) | set generics `DEFENSE_LEVEL` / `LOCK_VERSION`; run synth+impl, report util + timing. **Do not** use the board XDC here (no sw/led ports on this top). |
| Live board demo | `board_top_def` | `CONSTRAINTS/constraints.xdc` (unchanged) | program board, open serial 115200; see `docs/board_demo.md`. |
| Paper 1 baseline (reference) | `secure_scan_rv_top_v2` | as before | untouched from your original. |

## 6. Simulation (cloud / Icarus — not Vivado)

`./run_regression.sh` runs all 30 gated testbenches. Logs land in
`.reg_work/<tb>/run.log`. In Vivado's simulator you can instead set any
`tb_*_def` as the simulation top and run Behavioral Simulation.
