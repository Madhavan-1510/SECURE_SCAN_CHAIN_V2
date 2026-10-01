#!/usr/bin/env python3
"""
scan_console.py -- host console for board_top_def.v on the Boolean Board.

Talks to the on-FPGA UART console (115200 8N1) that drives the AES
coprocessor's scan port, PCPI port and lock. Lets you reproduce the Paper 1
(read lock) and Paper 2 (write lock) results live on hardware.

Commands sent to the board (also usable in --interactive):
  S            status: def / locked / lockout
  R            scan-read 645 bits (locked -> all zeros)
  W<32 hex>    shift 128 bits into the chain (write attack)
  K<32 hex>    LOADKEY     B<32 hex> LOADBLOCK
  E            encrypt + read result (prints ciphertext)
  U<8 hex>     unlock attempt      L  relock

sw[0] on the board selects which defense the console drives: 0 = G1
(Paper 1), 1 = G4 (Paper 2). The host cannot flip it, so --demo asks you to.

Usage:
  python3 scan_console.py --port /dev/ttyUSB1                 # interactive
  python3 scan_console.py --port COM4 --demo                 # guided attack demo
Requires: pip install pyserial
"""
import argparse, sys, time

KEY  = "000102030405060708090A0B0C0D0E0F"
BLK  = "00112233445566778899AABBCCDDEEFF"
KAT  = "69C4E0D86A7B0430D8CDB78070B4C55A"
EVIL = "0F1E2D3C4B5A69788796A5B4C3D2E1F0"
SECRET = "5EC2E7A1"

def line(ser, cmd, wait=0.3):
    ser.reset_input_buffer()
    ser.write((cmd + "\r").encode())
    time.sleep(wait)
    return ser.read_all().decode(errors="replace").strip()

def demo(ser):
    print("=== Paper 1 / Paper 2 live attack demo ===\n")
    for sel, name in ((0, "G1 (Paper 1, read lock)"), (1, "G4 (Paper 2, read+write lock)")):
        input(f">>> Set sw[0] = {sel}  ({name}), then press Enter...")
        print("  status      :", line(ser, "S"))
        # authorised setup, then relock
        print("  unlock      :", line(ser, "U" + SECRET, wait=0.5))
        line(ser, "K" + KEY); line(ser, "B" + BLK)
        ct_clean = line(ser, "E", wait=0.5)
        print("  clean KAT   :", ct_clean, " (expect E", KAT + ")")
        print("  relock      :", line(ser, "L"))
        # attacker, locked
        r = line(ser, "R", wait=0.6)
        allzero = all(c == "0" for c in r.split(" ", 1)[-1])
        print("  locked read :", "ALL ZERO (key hidden)" if allzero else "LEAK: " + r)
        line(ser, "W" + EVIL)                      # inject while locked
        ct_atk = line(ser, "E", wait=0.5)
        print("  after inject:", ct_atk)
        tag = ct_atk.split(" ", 1)[-1].upper()
        if tag == KAT:
            print("  --> VERDICT : write attack BLOCKED (ciphertext unchanged)\n")
        else:
            print("  --> VERDICT : write attack SUCCEEDED (ciphertext changed)\n")
    print("Expected: G1 changes, G4 unchanged. Both hide the key on read.")

def interactive(ser):
    print("Interactive. Type board commands (S/R/W../K../B../E/U../L), or 'quit'.")
    while True:
        try:
            c = input("scan> ").strip()
        except EOFError:
            break
        if c in ("quit", "exit"):
            break
        if c:
            print(line(ser, c, wait=0.5))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", required=True)
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--demo", action="store_true")
    a = ap.parse_args()
    try:
        import serial
    except ImportError:
        sys.exit("pyserial not installed: pip install pyserial")
    with serial.Serial(a.port, a.baud, timeout=0.2) as ser:
        (demo if a.demo else interactive)(ser)

if __name__ == "__main__":
    main()
