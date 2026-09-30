import os,shutil,subprocess,sys,re,time
# Run from anywhere: flattens RTL/ + TB/ into one dir per mutant under .reg_work/mut/
base=os.path.dirname(os.path.abspath(__file__)); out=os.path.join(base,'.reg_work','mut'); shutil.rmtree(out,ignore_errors=True); os.makedirs(out)
def nth(s,pat,new,n):
    idx=-1
    for _ in range(n):
        idx=s.index(pat,idx+1)
    return s[:idx]+new+s[idx+len(pat):]
SE=".scan_en(scan_en_sens)"; TE=".scan_en(scan_en_tail)"; R=".scan_en(scan_en)"
C="aes_core_def.v"; P="aes_pcpi_def.v"
# (name, file, fn, tb)
M=[
 ("A_core_state_reg_ungated",C,lambda s:nth(s,SE,R,1),"tb_attack_defenses"),
 ("B_core_round_key_reg_ungated",C,lambda s:nth(s,SE,R,2),"tb_attack_defenses"),
 ("C_core_key_reg_ungated",C,lambda s:nth(s,SE,R,3),"tb_attack_defenses"),
 ("D_core_round_reg_ungated",C,lambda s:nth(s,TE,R,1),"tb_attack_defenses"),
 ("E_pcpi_key_stage_ungated",P,lambda s:nth(s,SE,R,1),"tb_attack_defenses"),
 ("F_pcpi_block_stage_ungated",P,lambda s:nth(s,TE,R,1),"tb_attack_defenses"),
 ("G_pcpi_fsm_state_ungated",P,lambda s:nth(s,TE,R,2),"tb_attack_defenses"),
 ("H_core_outmask_removed",C,lambda s:s.replace("wire seg_out_muxed = locked ? 1'b0 : seg_tap[4];","wire seg_out_muxed = seg_tap[4];"),"tb_attack_defenses"),
 ("I_core_gate_polarity",C,lambda s:s.replace("(scan_en & ~locked)","(scan_en & locked)"),"tb_attack_defenses"),
 ("EQ1_core_gate_polarity",C,lambda s:s.replace("(scan_en & ~locked)","(scan_en & locked)"),"tb_defense_equiv"),
 ("EQ2_flush_not_lock_qualified",P,lambda s:s.replace("FLUSH_EN & locked & (scan_en ^ scan_en_q)","FLUSH_EN & (scan_en ^ scan_en_q)"),"tb_defense_equiv"),
 ("EQ3_tailmux_ignores_lock",P,lambda s:s.replace("(GRANULAR && locked) ? tail_in : seg_tap[1]","GRANULAR ? tail_in : seg_tap[1]"),"tb_defense_equiv"),
]
if len(sys.argv)>1: M=[m for m in M if m[0] in sys.argv[1:]]
for name,f,fn,tb in M:
    d=f"{out}/{name}"; os.makedirs(d)
    for sub in ('RTL','TB'):
        for x in os.listdir(f"{base}/{sub}"):
            if x.endswith('.v') or x.endswith('.vh'): shutil.copy(f"{base}/{sub}/{x}",d)
    s=open(f"{d}/{f}").read(); t=fn(s); assert t!=s,name
    open(f"{d}/{f}","w").write(t)
    rtl=[x for x in sorted(os.listdir(d)) if x.endswith('.v') and not x.startswith('tb_') and x!='secure_scan_rv_top.v']
    c=subprocess.run(["iverilog","-I.","-o","m.vvp","-s",tb]+rtl+[tb+".v"],cwd=d,capture_output=True,text=True)
    if c.returncode: print(name,"COMPILE ERROR",c.stderr[:200],flush=True); continue
    t0=time.time(); r=subprocess.run(["vvp","m.vvp"],cwd=d,capture_output=True,text=True).stdout
    fl=re.findall(r"^FAIL:.*",r,re.M); ok="ALL TESTS PASSED" in r
    print(f"{name} [{tb}] {int(time.time()-t0)}s: FAIL-lines={len(fl)} {'SURVIVED (BAD)' if ok else 'caught'}",flush=True)
    for l in fl[:2]: print("     ",l[:140],flush=True)
print("MUTATION DONE",flush=True)
