# Board demo (Spartan-7 Boolean Board) — UART scan console

A single bitstream that shows both defenses live over a serial terminal:
a **G1** instance (Paper 1 read lock) and a **G4** instance (Paper 2 read +
write lock), sharing one hardened lock (`scan_lock_controller_v2`). `sw[0]`
picks which one the console drives.

Top module: **`RTL/board_top_def.v`**. Verified in simulation by
`TB/tb_board_top_def.v` (9/9 checks, part of `run_regression.sh`).

## Build in Vivado

1. Add sources: all `RTL/*.v` and `RTL/aes_pcpi_defs.vh`.
2. Add constraints: `CONSTRAINTS/constraints.xdc` (unchanged — it already has
   `clk`, `sw`, `led`, `btn`, `RGB0/1`, the two 7-seg displays, and
   `UART_rxd`/`UART_txd`). The port names match `board_top_def` exactly.
3. Set **`board_top_def`** as the top module.
4. For a real security build, override the lock timers to the production
   values (`BOOT_DELAY_CYCLES >= LOCKOUT_CYCLES`, ~1e8); the defaults here are
   ms-scale so the demo is quick.
5. Generate bitstream, program the board. Open a serial terminal at
   **115200 8N1** on the board's UART COM port (or use `scripts/scan_console.py`).

## Controls

- `btn[0]` system reset (CPU/AES datapath) · `btn[1]` lock-domain reset
- `sw[0]` select defense: **0 = G1**, **1 = G4**
- `led[0]` locked · `led[1]` lockout · `led[2]` selected defense · `led[3]` busy
- RGB0 red = locked / green = unlocked · 7-seg shows the last ciphertext word

## Serial commands (type the letter, optional hex, then Enter)

| Command | Action | Reply |
|---|---|---|
| `S` | status | `S def=.. lk=<0/1> lo=<0/1>` |
| `R` | scan-read 645 bits | `R <162 hex>` (all zeros while locked) |
| `W<32hex>` | shift 128 bits into the chain (write attack) | `W ok` |
| `K<32hex>` | LOADKEY | `K ok` |
| `B<32hex>` | LOADBLOCK | `B ok` |
| `E` | encrypt + read result | `E <32 hex ciphertext>` |
| `U<8hex>` | unlock attempt (secret `5EC2E7A1`) | status |
| `L` | relock | `L ok` |

## The demo (what to show)

Secret unlock code: `5EC2E7A1`. NIST KAT key `000102..0f`, block `00112233..ff`,
ciphertext `69C4E0D86A7B0430D8CDB78070B4C55A`.

1. **It works:** `U5EC2E7A1`, `K000102030405060708090A0B0C0D0E0F`,
   `B00112233445566778899AABBCCDDEEFF`, `E` → `69C4E0D8...` (the KAT).
2. **Read lock (Paper 1):** `L` to relock, then `R` → all zeros. The key is
   hidden on both G1 and G4.
3. **Write attack (the gap):** with `sw[0]=0` (G1), while locked send
   `W0F1E2D3C4B5A69788796A5B4C3D2E1F0` then `E` → `50b58e80...` — a *different*
   ciphertext. The attacker injected a key through the locked scan port.
4. **Write lock (Paper 2):** set `sw[0]=1` (G4), repeat step 3 → `E` returns the
   true KAT `69C4E0D8...`. The injection had no effect.
5. **Only while locked:** on G4, unlock first, then inject + `E` → the
   ciphertext changes again, confirming the defense only acts while locked and
   normal (authorised) test access is unaffected.

`scripts/scan_console.py --port <COM> --demo` runs steps 1–4 for you and prints
the verdict for each defense (it pauses for you to flip `sw[0]`).

## Notes

- No key or ciphertext debug tap is wired to the board (unlike the Paper 1
  `board_top.v`): the only readback is the scan port, which is what the defense
  governs. The 7-seg shows the public ciphertext word only.
- The console is a PCPI master, standing in for the CPU; the real-CPU path is
  separately proven in `tb_cpu_driven_aes_def` (18/18 configs).
