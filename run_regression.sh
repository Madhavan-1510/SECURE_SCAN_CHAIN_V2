#!/usr/bin/env bash
# One-command Icarus Verilog 12.0 regression for the RTL/ + TB/ project layout.
#   ./run_regression.sh                 run all gated testbenches
#   ./run_regression.sh tb_zeroize ...  run only the named testbenches
#   JOBS=4 ./run_regression.sh          run up to 4 testbenches in parallel
# Each tb is compiled against every RTL/*.v and runs in its own directory (tb_sensitivity writes CSVs to its cwd).
# A tb PASSES only if it compiles, finishes within the timeout, prints its
# "TESTBENCH: ALL TESTS/CHECKS PASSED" banner, and prints no failure marker.
# A missing file, compile error, or timeout is a FAIL.
# Default iverilog language flags on purpose: tb_scan_attack.v uses `matches`
# as an identifier, reserved under -g2012.
cd "$(dirname "$0")" || exit 2
ROOT=$(pwd)
WORK="$ROOT/.reg_work"
TIMEOUT_S=${TIMEOUT_S:-3600}
JOBS=${JOBS:-1}
RTL=$(ls "$ROOT"/RTL/*.v)

GATED="tb_scan_cell tb_scan_chain tb_aes_core tb_aes_pcpi tb_scan_attack tb_scan_lock \
tb_double_encrypt_control tb_scan_resume tb_keystage_lock_scope tb_cpu_driven_aes \
tb_scan_attack_harness tb_fpga_top tb_board_top tb_zeroize tb_attack_write_inject tb_sensitivity \
tb_attack_bruteforce tb_lock_v2 tb_scan_lock_v2 tb_attack_modeswitch tb_attack_matrix \
tb_attack_defenses tb_defense_equiv tb_def_functional tb_scan_resume_def tb_cpu_driven_aes_def tb_attack_top_def tb_testability_t1"
[ $# -gt 0 ] && GATED="$*"

run_one() {
  tb=$1; d="$WORK/$tb"; rm -rf "$d"; mkdir -p "$d"
  if [ ! -f "$ROOT/TB/$tb.v" ]; then echo "MISSING $tb" > "$d/verdict"; return; fi
  if ! iverilog -I"$ROOT/RTL" -o "$d/sim.vvp" -s "$tb" $RTL "$ROOT/TB/$tb.v" > "$d/compile.log" 2>&1; then
    echo "COMPILE-FAIL $tb" > "$d/verdict"; return; fi
  t0=$(date +%s)
  (cd "$d" && timeout "$TIMEOUT_S" vvp sim.vvp > run.log 2>&1); rc=$?
  dt=$(( $(date +%s) - t0 ))
  if [ $rc -eq 124 ]; then echo "TIMEOUT $tb ${dt}s" > "$d/verdict"
  elif grep -Eq "TESTBENCH: ALL (TESTS|CHECKS) PASSED" "$d/run.log" \
     && ! grep -Eq "GLOBAL TIMEOUT|^ *FAIL|RESULT: FAIL|TEST\(S\) FAILED" "$d/run.log"; then
    echo "PASS $tb ${dt}s" > "$d/verdict"
  else echo "FAIL $tb ${dt}s" > "$d/verdict"; fi
}

mkdir -p "$WORK"
n=0
for tb in $GATED; do
  run_one "$tb" &
  n=$((n+1)); [ $((n % JOBS)) -eq 0 ] && wait
done
wait

pass=0; fail=0; total=0
for tb in $GATED; do
  v=$(cat "$WORK/$tb/verdict" 2>/dev/null || echo "FAIL $tb (no verdict)")
  total=$((total+1))
  case "$v" in PASS*) pass=$((pass+1)); printf '%-14s %s\n' PASS "${v#PASS }";;
               *) fail=$((fail+1)); printf '%-14s %s   (see .reg_work/%s/)\n' "${v%% *}" "${v#* }" "$tb";; esac
done
echo "----"
echo "SUMMARY passed=$pass failed=$fail total=$total   (tb_attack_probe.v and probe_g235.v are informational, not gated)"
[ $fail -eq 0 ]
