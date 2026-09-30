#!/usr/bin/env bash
# One-command regression: compiles each tb_*.v with all non-tb RTL, runs it,
# gates on the PASS marker and absence of TIMEOUT/FAIL lines.
# Usage: ./run_regression.sh   (run from the RTL/tb directory, Icarus Verilog 12.0)
# Default iverilog flags on purpose: tb_scan_attack.v uses `matches` as an
# identifier, reserved under -g2012.
cd "$(dirname "$0")"
RTL=$(ls *.v | grep -v '^tb_')
GATED="tb_scan_cell tb_scan_chain tb_aes_core tb_aes_pcpi tb_scan_attack tb_scan_lock \
tb_double_encrypt_control tb_scan_resume tb_keystage_lock_scope tb_cpu_driven_aes \
tb_scan_attack_harness tb_fpga_top tb_board_top tb_zeroize tb_attack_write_inject tb_sensitivity"
pass=0; fail=0; mkdir -p .reg_logs
for tb in $GATED; do
  if ! iverilog -I. -o .reg_logs/$tb.vvp -s $tb $RTL $tb.v > .reg_logs/$tb.compile 2>&1; then
    echo "COMPILE-FAIL  $tb"; fail=$((fail+1)); continue; fi
  timeout 900 vvp .reg_logs/$tb.vvp > .reg_logs/$tb.log 2>&1
  if grep -Eq "TESTBENCH: (ALL TESTS|ALL CHECKS) PASSED" .reg_logs/$tb.log \
     && ! grep -Eq "GLOBAL TIMEOUT|^FAIL|RESULT: FAIL|TEST\(S\) FAILED" .reg_logs/$tb.log; then
    echo "PASS          $tb"; pass=$((pass+1))
  else echo "FAIL          $tb  (see .reg_logs/$tb.log)"; fail=$((fail+1)); fi
done
echo "----"; echo "passed=$pass failed=$fail (tb_attack_probe.v is informational, not gated)"
[ $fail -eq 0 ]
