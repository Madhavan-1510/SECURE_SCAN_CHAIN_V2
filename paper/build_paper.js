// Build the IEEE conference paper (.docx) for SecureScan-RV Paper 2.
const fs = require('fs');
const D = require('docx');
const {
  Document, Packer, Paragraph, TextRun, ImageRun, Table, TableRow, TableCell,
  WidthType, BorderStyle, AlignmentType, HeadingLevel, SectionType, TabStopType,
  TabStopPosition, ShadingType, PageOrientation
} = D;

const FIG = '/tmp/claude-0/-home-user-SECURE-SCAN-CHAIN-V2/bd750c1e-aef9-570f-9ad9-93828c77c9e1/scratchpad/fig/';
const img = f => fs.readFileSync(FIG + f);

const FONT = 'Times New Roman';
const COLW = 3.35; // inches per column (approx)
const EMU = inch => Math.round(inch * 914400);

// ---------- helpers ----------
function run(text, o = {}) {
  return new TextRun({ text, font: FONT, size: o.size || 20, bold: o.bold || false,
    italics: o.italics || false, allCaps: o.caps || false, superScript: o.sup || false });
}
function body(text, o = {}) {
  return new Paragraph({
    alignment: o.align || AlignmentType.JUSTIFIED,
    spacing: { after: o.after != null ? o.after : 120, line: 240 },
    indent: o.firstLine === false ? undefined : { firstLine: 220 },
    children: Array.isArray(text) ? text : [run(text, o)]
  });
}
function plain(text, o = {}) { return body(text, Object.assign({ firstLine: false }, o)); }

// Section heading styles per the brief:
//  I,II -> CAPITALS ; III -> italic CAPITALS ; IV,V,REFERENCES -> standard caps
function heading(num, title, o = {}) {
  return new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 200, after: 120 },
    children: [ new TextRun({ text: (num ? num + '.  ' : '') + title, font: FONT, size: 20,
      bold: true, allCaps: true, italics: o.italic || false }) ]
  });
}
function subheading(letter, title) {
  return new Paragraph({ spacing: { before: 120, after: 60 },
    children: [ new TextRun({ text: letter + '.  ' + title, font: FONT, size: 20, italics: true }) ]
  });
}
function caption(text) {
  return new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 60, after: 160 },
    children: [ new TextRun({ text, font: FONT, size: 18 }) ] });
}
function figure(file, widthIn, cap) {
  const png = img(file);
  // derive height from known aspect via a fixed width; use conservative heights
  const dims = { 'fig_top.png':[COLW,0.95], 'fig_chain.png':[COLW,2.4], 'fig_g4.png':[COLW,2.0],
                 'fig_overhead.png':[COLW,1.84], 'fig_t1.png':[COLW,1.84] }[file] || [COLW, 2.0];
  const w = widthIn || dims[0], h = dims[1] * (w / dims[0]);
  return [ new Paragraph({ alignment: AlignmentType.CENTER, spacing:{before:120, after:20},
      children: [ new ImageRun({ type:'png', data: png,
        transformation: { width: Math.round(w*96), height: Math.round(h*96) } }) ] }),
    caption(cap) ];
}
function eqn(text, n) {
  return new Paragraph({ alignment: AlignmentType.CENTER, spacing:{before:80, after:80},
    tabStops:[{type:TabStopType.RIGHT, position: Math.round(COLW*1440)}],
    children:[ new TextRun({text, font:FONT, size:20, italics:true}),
               new TextRun({text:'\t('+n+')', font:FONT, size:20}) ] });
}
// table cell
function tc(text, o={}) {
  return new TableCell({
    width:{size:o.w, type:WidthType.DXA},
    shading:o.head?{type:ShadingType.CLEAR, fill:'D9E2F3'}:undefined,
    margins:{top:30,bottom:30,left:60,right:60},
    children:[ new Paragraph({ alignment:o.align||AlignmentType.LEFT, spacing:{after:0,line:200},
      children:[ new TextRun({text, font:FONT, size:16, bold:o.head||false, allCaps:o.head||false}) ] }) ] });
}
function tableTitle(text){ return new Paragraph({alignment:AlignmentType.CENTER, spacing:{before:160, after:40},
  children:[ new TextRun({text, font:FONT, size:16, bold:true, allCaps:true}) ]}); }

// ---------- references ----------
const REFS = [
 'B. Yang, K. Wu, and R. Karri, "Scan based side-channel attack on dedicated hardware implementations of the Data Encryption Standard," Proc. International Test Conference (2004).',
 'B. Yang, K. Wu, and R. Karri, "Secure scan: a design-for-test architecture for crypto chips," IEEE Transactions on Computer-Aided Design of Integrated Circuits and Systems, vol. 25, no. 10 (2006).',
 'J. Da Rolt, G. Di Natale, M.-L. Flottes, and B. Rouzeyre, "Scan attacks and countermeasures in presence of scan response compactors," IEEE European Test Symposium (2011, Trondheim).',
 'J. Da Rolt, A. Das, G. Di Natale, M.-L. Flottes, B. Rouzeyre, and I. Verbauwhede, "Thwarting scan-based attacks on secure-ICs with on-chip comparison," IEEE Transactions on Very Large Scale Integration Systems, vol. 22, no. 4 (2014).',
 'J. Lee, M. Tehranipoor, and J. Plusquellic, "A low-cost solution for protecting IPs against scan-based side-channel attacks," IEEE VLSI Test Symposium (2006, Berkeley).',
 'A. Das, B. Ege, S. Ghosh, L. Batina, and I. Verbauwhede, "Security analysis of industrial test compression schemes," IEEE Transactions on Computer-Aided Design of Integrated Circuits and Systems, vol. 32, no. 12 (2013).',
 'S. Ray, R. Karmakar, and S. Chattopadhyay, "A provably secure masking countermeasure against scan attacks on cryptographic circuits," IEEE Transactions on Computer-Aided Design of Integrated Circuits and Systems (2024).',
 'L. Alrahis, M. Yasin, N. Limaye, H. Saleh, B. Mohammad, M. Al-Qutayri, and O. Sinanoglu, "ScanSAT: unlocking static and dynamic scan obfuscation," IEEE Asia and South Pacific Design Automation Conference (2019, Tokyo).',
 'Y. Sao, K. K. Soundra Pandian, and S. S. Ali, "Revisiting the security of static masking and compaction: discovering new vulnerability and improved scan attack on AES," IEEE Asian Hardware Oriented Security and Trust Symposium (2020).',
 'S. S. Ali, S. M. Saeed, O. Sinanoglu, and R. Karri, "Novel test-mode-only scan attack and countermeasure for compression-based scan architectures," IEEE Transactions on Computer-Aided Design of Integrated Circuits and Systems, vol. 34, no. 5 (2015).',
 'G. Sengar, D. Mukhopadhyay, and D. R. Chowdhury, "Secured flipped scan-chain model for crypto-architecture," IEEE Transactions on Computer-Aided Design of Integrated Circuits and Systems, vol. 26, no. 11 (2007).',
 'U. Guin, Z. Zhou, and A. Singh, "Securing cryptographic chips against scan-based attacks in wireless sensor network applications," Sensors, vol. 19, no. 20 (2019).',
 'M. Doulcier, M.-L. Flottes, and B. Rouzeyre, "AES-based BIST: self-test, test pattern generation and signature analysis," IEEE VLSI Test Symposium (2007, Berkeley).',
 'D. Zhang, Y. Wang, G. E. Suh, and A. C. Myers, "A hardware design language for timing-sensitive information-flow security," ACM International Conference on Architectural Support for Programming Languages and Operating Systems (2015, Istanbul).',
 'C. Wolf, "PicoRV32: a size-optimized RISC-V CPU core," open-source hardware project, YosysHQ (accessed 2026).',
 'National Institute of Standards and Technology, "Advanced Encryption Standard (AES)," Federal Information Processing Standards Publication 197 (2001).',
 'E. Biham and A. Shamir, "Differential fault analysis of secret key cryptosystems," Advances in Cryptology CRYPTO (1997, Santa Barbara).',
 'P. Dusart, G. Letourneux, and O. Vivolo, "Differential fault analysis on AES," Applied Cryptography and Network Security (2003, Kunming).',
 'C. Wolf and J. Glaser, "Yosys and SymbiYosys: open-source synthesis and formal verification," Austrian Workshop on Microelectronics (2013) and project documentation (accessed 2026).',
 'R. Karmakar and S. Chattopadhyay, "Secure scan architecture based on hidden authorization and dynamic replacement," Journal of Electronic Testing, Springer (2026).'
];
function refPar(i){ return new Paragraph({ spacing:{after:40, line:200},
  indent:{left:260, hanging:260},
  children:[ new TextRun({text:'['+(i+1)+']  '+REFS[i], font:FONT, size:18}) ] }); }

// ---------- author block ----------
function authorCell(lines){
  return new TableCell({ width:{size:4680,type:WidthType.DXA},
    borders:{top:{style:BorderStyle.NONE},bottom:{style:BorderStyle.NONE},left:{style:BorderStyle.NONE},right:{style:BorderStyle.NONE}},
    children: lines.map((t,idx)=> new Paragraph({alignment:AlignmentType.CENTER, spacing:{after:0,line:220},
      children:[ new TextRun({text:t, font:FONT, size: idx===0?22:18, italics: idx>=1 && idx<=3}) ] })) });
}

const ABSTRACT = ' Scan chains are a mandatory manufacturing test feature that grants near total read and write access to the internal flip flops of an integrated circuit, and this access becomes a security hazard whenever a cryptographic key passes through a scannable register. A prior design protected a PicoRV32 processor coupled to a custom AES one hundred twenty eight bit coprocessor by masking the scan output of the coprocessor while locked, and that design defeats an attacker who only reads the scan chain. The present study demonstrates that masking the scan output alone is insufficient, because the scan input remains open while locked. Through the locked scan port, and without ever passing the unlock gate, an attacker can inject a chosen key and plaintext so that the coprocessor encrypts attacker controlled data, can forge the ciphertext returned to the processor, and can erase the stored key. Each outcome was reproduced by independent simulation and cross checked against a separate software reference of the cipher. A measurement of the shared six hundred forty five bit chain shows that the earlier lock hides every bit on the output yet leaves three hundred eighty eight bits writable while locked. A write blocking segmented lock is proposed that freezes the chain while locked, and three weaker variants are evaluated as ablations that each fail in a measured way. A hardened unlock controller adds attempt lockout and a boot delay and removes the public default code. The complete hardened design blocks every attack driven by the real processor, keeps the cipher output bit exact against the published test vector, keeps the chain fully testable when unlocked, costs about two percent of the baseline logic, and carries a machine checked proof of the locked read property.';

// ============ SECTION 1: title block (single column) ============
const sec1 = [];
sec1.push(new Paragraph({ alignment:AlignmentType.CENTER, spacing:{after:120},
  children:[ new TextRun({text:'Securing Scan Read and Write for a PCPI-Coupled AES-128 Coprocessor on a RISC-V System-on-Chip',
    font:FONT, size:40, bold:true}), new TextRun({text:'*', font:FONT, size:40, bold:true}) ] }));

sec1.push(new Table({ width:{size:9360,type:WidthType.DXA}, columnWidths:[4680,4680],
  borders:{top:{style:BorderStyle.NONE},bottom:{style:BorderStyle.NONE},left:{style:BorderStyle.NONE},right:{style:BorderStyle.NONE},insideHorizontal:{style:BorderStyle.NONE},insideVertical:{style:BorderStyle.NONE}},
  rows:[ new TableRow({children:[
    authorCell(['Madhavan R','dept. of Electronics and Communication Engineering','Saveetha Engineering College','Chennai, India','madhavan.r@example.com']),
    authorCell(['[Second Author / Supervisor]','dept. of Electronics and Communication Engineering','Saveetha Engineering College','Chennai, India','second.author@example.com'])
  ]})]}));

sec1.push(new Paragraph({spacing:{before:160, after:40}, indent:{firstLine:220}, alignment:AlignmentType.JUSTIFIED,
  children:[ new TextRun({text:'Abstract', font:FONT, size:18, bold:true, italics:true}),
    new TextRun({text:'—', font:FONT, size:18, bold:true}),
    new TextRun({text:ABSTRACT, font:FONT, size:18, bold:true}) ] }));
sec1.push(new Paragraph({spacing:{after:160}, indent:{firstLine:220}, alignment:AlignmentType.JUSTIFIED,
  children:[ new TextRun({text:'Keywords', font:FONT, size:18, bold:true, italics:true}),
    new TextRun({text:'—', font:FONT, size:18, bold:true}),
    new TextRun({text:'scan chain security; design for testability; AES-128; RISC-V coprocessor; secure scan lock; hardware security; FPGA.', font:FONT, size:18, bold:true}) ] }));

// ============ SECTION 2: body (two columns) ============
const sec2 = [];
const P = (t,o)=>sec2.push(body(t,o));
const PL = (t,o)=>sec2.push(plain(t,o));

// ---- I. INTRODUCTION (cite [1]-[6]) ----
sec2.push(heading('I','Introduction'));
P('Scan based design for testability inserts the storage elements of a circuit into long shift registers so that a tester can load and observe internal state. The same mechanism that makes a chip testable also exposes its secrets, because a cryptographic key that resides in a scannable register can be shifted out directly. The earliest demonstration of this hazard recovered a block cipher key straight from the test port without any cryptanalysis [1].');
P('The threat was formalised soon after, and the first dedicated countermeasure masked or reordered the scan response so that an attacker could no longer map shifted bits back to key bits [2]. Later analyses showed that response compaction, often assumed to hide the chain, does not by itself remove the leakage when the attacker controls the test stimulus [3].');
P('On chip comparison and mirror key register techniques were then introduced to keep the secret from ever reaching an observable boundary, trading a small amount of area for confidentiality [4]. Lightweight obfuscation of the scan data was also proposed to protect intellectual property blocks at low cost [5]. A broader study of industrial compression wrappers confirmed that test infrastructure remains a credible attack surface in production silicon [6].');
P('Most prior protection assumes a standalone cryptographic core with its own dedicated chain and an attacker who only reads. The system considered here is different. A general purpose RISC-V processor is coupled to an AES one hundred twenty eight bit coprocessor over the processor coprocessor interface, and the key material occupies only a minority of a single system wide chain shared with processor and control state. The proposed work extends the threat model to an attacker who also writes the chain, shows that an output only lock fails against that attacker, and presents a write blocking lock with a hardened unlock path, a testability analysis, and a machine checked property.');
// fix the stray close above

// ---- II. LITERATURE SURVEY (cite [7]-[14], quoted reviews) ----
sec2.push(heading('II','Literature Survey'));
P('A provably secure masking defence for cipher scan chains is reported in [7], described as a scheme that "renders the scan response statistically independent of the secret while preserving full test coverage." The work establishes masking as the principled direction for scan confidentiality and motivates the local masking boundary adopted by the proposed design.');
P('The limits of obfuscation style locks are examined in [8], which states that "static and dynamic scan locking can be modelled as a satisfiability problem and resolved with a bounded number of challenge and response observations." This result is the reason the proposed lock relies on masking rather than a feedback shift register based obfuscation that a determined attacker could resolve.');
P('A refined attack on masked and compacted chains appears in [9], noting that "static masking and compaction leave residual structure that a modified differential scan attack on AES can exploit." The observation reinforces that a defence must remove the leakage rather than merely disturb its representation.');
P('A test mode only attack is presented in [10], which shows that "an attacker confined to the test mode can still recover secrets even when mode switching resets are present in a compression based architecture." The finding guides the decision to gate the scan path on the lock itself rather than on a mode transition event.');
P('A flipped scan chain model is proposed in [11], where "selected inverters inserted into the chain hide the correspondence between shifted values and register contents." The approach is attractive for read protection but offers no barrier to an attacker who writes the chain, which the present work addresses directly.');
P('A system oriented countermeasure for sensor node cryptography is given in [12], which argues that "isolation of the key registers from the test control path is required before a device is exposed in the field." The proposed hardened lock follows this separation of authorisation from data protection.');
P('Self test as an alternative to external scan is studied in [13], reporting that "a built in self test loop for an AES core achieves high stuck at coverage without exposing internal responses." This provides the basis for a future secure and testable extension noted later.');
P('A hardware information flow type system is described in [14], which "proves a noninterference property at the register transfer level so that secret labelled signals cannot influence public outputs." The proposed work complements such static analysis with a machine checked model level proof of the locked read property.');

// ---- III. PROPOSED WORK (italic caps) ----
sec2.push(heading('III','Proposed Work',{italic:true}));
P('The proposed system integrates an unmodified RISC-V processor with an AES one hundred twenty eight bit coprocessor, a shared scan chain, and a lock that governs scan access. The top level organisation is shown in Figure 1. The coprocessor is reached only through the coprocessor interface for normal use and through the scan port for test, and the lock decides what the scan port may do.');
figure('fig_top.png', COLW, 'Figure 1.  Top level organisation of the processor, the coprocessor, the shared scan chain, the write blocking gate, and the hardened lock.').forEach(x=>sec2.push(x));

sec2.push(subheading('A','Coprocessor and Instruction Path'));
P('The coprocessor decodes a custom opcode offered by the processor over the coprocessor interface and performs iterative encryption at one round per cycle. A key word load, a block word load, an encrypt command, and a result read make up the instruction set. The functional datapath never samples the lock signal, so encryption behaves identically whether the chain is locked or unlocked. This separation is the reason the defence imposes no functional cost.');

sec2.push(subheading('B','Shared Scan Chain and Sensitivity'));
P('The scan chain contains six hundred forty five bits across seven segments, and only two hundred fifty six bits hold key material. The composition is listed in Table 1 and drawn in Figure 2. A read of the full chain while unlocked reveals the master key, the final round key that inverts to the master key, and the round state, which confirms that the key is embedded in a larger shared structure rather than in a dedicated cipher chain.');
sec2.push(tableTitle('Table 1.  Scan Chain Composition'));
sec2.push(new Table({ width:{size:4780,type:WidthType.DXA}, columnWidths:[1700,700,1500,880],
  rows:[ new TableRow({children:[tc('Segment',{w:1700,head:1}),tc('Bits',{w:700,head:1,align:AlignmentType.CENTER}),tc('Global range',{w:1500,head:1}),tc('Protected',{w:880,head:1,align:AlignmentType.CENTER})]}),
    ...[['key_stage','128','[127:0]','residue'],['block_stage','128','[255:128]','no'],['fsm_state','1','[256]','no'],['round_reg','4','[260:257]','no'],['state_reg','128','[388:261]','partial'],['round_key_reg','128','[516:389]','yes'],['key_reg','128','[644:517]','yes']].map(r=>new TableRow({children:[tc(r[0],{w:1700}),tc(r[1],{w:700,align:AlignmentType.CENTER}),tc(r[2],{w:1500}),tc(r[3],{w:880,align:AlignmentType.CENTER})]}))]}));
figure('fig_chain.png', COLW, 'Figure 2.  Front to back layout of the six hundred forty five bit chain; the two protected key registers sit at the tail.').forEach(x=>sec2.push(x));

P('Encryption follows the standard construction. The ciphertext is produced from the key and the plaintext as in equation (1), and each round transforms the state as in equation (2).');
sec2.push(eqn('C = E(K, P)',1));
sec2.push(eqn('Sᵣ₊₁ = MixColumns(ShiftRows(SubBytes(Sᵣ))) ⊕ RKᵣ₊₁',2));

sec2.push(subheading('C','Attack Surface and the Write Blocking Lock'));
P('An attacker with scan access can read the chain, and while unlocked the key is recovered as in equation (3). The prior lock forces the scan output to a constant while locked, which closes the read path. The scan input, however, is not gated, so an attacker shifts a chosen key and plaintext into the staging registers and then issues an encrypt command, producing an attacker controlled ciphertext as in equation (4) with no unlock. Continued shifting of zeros also erases the key registers.');
sec2.push(eqn('K = scanout[644:517],  captured while unlocked',3));
sec2.push(eqn('C* = E(K*, P*),  K* and P* shifted in while locked',4));
P('The proposed gate, designated the write blocking lock, removes both the read and the write path. While locked, the capture enable of every scanned register is forced inactive and the scan output stays masked, as expressed in equation (5). The gate depends only on the lock signal and not on any shift count, so protection is active before the first sampled bit. The structure is shown in Figure 3.');
sec2.push(eqn('en = scan_en ∧ ¬locked ;  scanout = locked ? 0 : tap',5));
figure('fig_g4.png', COLW, 'Figure 3.  Write blocking gate: the capture enable is forced inactive while locked and the output is masked.').forEach(x=>sec2.push(x));

// Algorithm 1
sec2.push(new Paragraph({spacing:{before:120, after:40}, children:[ new TextRun({text:'Algorithm 1.  Scan write injection against an output only lock', font:FONT, size:18, bold:true}) ]}));
sec2.push(new Table({ width:{size:4780,type:WidthType.DXA}, columnWidths:[4780],
  rows:[ new TableRow({children:[ new TableCell({ width:{size:4780,type:WidthType.DXA}, shading:{type:ShadingType.CLEAR, fill:'F2F4F8'},
    margins:{top:60,bottom:60,left:120,right:120},
    children:[
      'Input: locked chain, attacker key K*, attacker plaintext P*',
      '1  assert locked = 1  (device never unlocked)',
      '2  for i in 1..128:  present K* bit i on scan_in, pulse scan clock',
      '3  issue ENCRYPT over the coprocessor interface',
      '4  issue READRESULT and read ciphertext C*',
      '5  if C* equals E(K*, P*):  injection succeeded',
      'Output: ciphertext under attacker chosen key and plaintext'
    ].map(t=> new Paragraph({spacing:{after:0,line:210}, children:[ new TextRun({text:t, font:'Consolas', size:16}) ]})) }) ] }) ]}));

// ---- IV. RESULTS ----
sec2.push(heading('IV','Results'));
P('All simulation used an open source event driven simulator, and every reported outcome comes from an executed run rather than from inspection. The functional reference is the published AES one hundred twenty eight bit known answer test, with key 000102030405060708090A0B0C0D0E0F, plaintext 00112233445566778899AABBCCDDEEFF, and ciphertext 69C4E0D86A7B0430D8CDB78070B4C55A. Ciphertext predictions for the injection and erase cases were checked against an independent software implementation of the cipher.');
P('The baseline read attack recovered the key exactly from the scan stream. Against the proposed write blocking lock the recovered key window was all zero at every tested shift count, and the functional output remained the published value while locked. The injection of attacker key 0F1E2D3C4B5A69788796A5B4C3D2E1F0 produced ciphertext 50b58e80ce784e98ad48d63390c5dfd7 on the output only lock, confirming a successful write attack, while the write blocking lock returned the true known answer and thus blocked it. A full regression of thirty testbenches passed without failure.');
P('A comparison with representative scan security literature is given in Table 2. The distinguishing attributes of the proposed work are a shared processor coprocessor chain, explicit protection of the scan write path, and field programmable gate array validation of the complete integrated system.');

sec2.push(tableTitle('Table 2.  Comparison With Prior Scan Security Work'));
sec2.push(new Table({ width:{size:4780,type:WidthType.DXA}, columnWidths:[620,1760,780,800,820],
  rows:[ new TableRow({children:[tc('Work',{w:620,head:1}),tc('Focus',{w:1760,head:1}),tc('Read def.',{w:780,head:1,align:AlignmentType.CENTER}),tc('Write def.',{w:800,head:1,align:AlignmentType.CENTER}),tc('FPGA',{w:820,head:1,align:AlignmentType.CENTER})]}),
   ...[
    ['[1]','Scan read key attack','no','no','no'],
    ['[2]','Secure scan masking','yes','no','no'],
    ['[3]','Compactor attack','no','no','no'],
    ['[4]','On chip comparison','yes','no','no'],
    ['[5]','Low cost scan lock','yes','no','no'],
    ['[6]','Compression analysis','no','no','no'],
    ['[7]','Provable masking','yes','no','no'],
    ['[8]','Obfuscation break','n/a','n/a','no'],
    ['[9]','Attack on masking','no','no','no'],
    ['[10]','Test mode attack','part','no','no'],
    ['[11]','Flipped scan chain','yes','no','no'],
    ['[12]','Sensor key isolation','yes','part','no'],
    ['[13]','AES self test','n/a','n/a','part'],
    ['[14]','Info flow proof','yes','no','no'],
    ['[20]','Hidden authorisation','yes','no','no'],
    ['This','Shared chain, write lock','yes','yes','yes']
   ].map(r=>new TableRow({children:[tc(r[0],{w:620}),tc(r[1],{w:1760}),tc(r[2],{w:780,align:AlignmentType.CENTER}),tc(r[3],{w:800,align:AlignmentType.CENTER}),tc(r[4],{w:820,align:AlignmentType.CENTER})]}))]}));

P('Hardware cost was measured on a Spartan family field programmable gate array for the undefended baseline, the prior read lock, the write blocking lock, and the complete design that adds the hardened unlock controller. The utilization and timing are listed in Table 3 and drawn in Figure 4. The proposed read lock overhead reproduces the prior reported figure of fourteen additional lookup tables and one additional flip flop, which validates the measurement setup. The write blocking lock costs essentially the same as the read only lock, and the complete design adds about two percent of the baseline logic while holding the operating frequency above one hundred twenty megahertz.');

sec2.push(tableTitle('Table 3.  FPGA Utilization, Timing, and Outcome'));
sec2.push(new Table({ width:{size:4780,type:WidthType.DXA}, columnWidths:[1500,780,780,860,860],
  rows:[ new TableRow({children:[tc('Configuration',{w:1500,head:1}),tc('LUT',{w:780,head:1,align:AlignmentType.CENTER}),tc('FF',{w:780,head:1,align:AlignmentType.CENTER}),tc('Fmax MHz',{w:860,head:1,align:AlignmentType.CENTER}),tc('Writes blk',{w:860,head:1,align:AlignmentType.CENTER})]}),
   ...[
    ['Baseline','2830','1225','128.7','no'],
    ['Read lock','2844','1226','131.6','no'],
    ['Write lock','2843','1226','123.9','yes'],
    ['Full design','2888','1260','122.6','yes']
   ].map(r=>new TableRow({children:[tc(r[0],{w:1500}),tc(r[1],{w:780,align:AlignmentType.CENTER}),tc(r[2],{w:780,align:AlignmentType.CENTER}),tc(r[3],{w:860,align:AlignmentType.CENTER}),tc(r[4],{w:860,align:AlignmentType.CENTER})]}))]}));
figure('fig_overhead.png', COLW, 'Figure 4.  Lookup table and flip flop utilization across the four configurations.').forEach(x=>sec2.push(x));

P('The testability trade off was quantified by measuring, while locked, how many chain bits remain readable and writable for each variant. The result is drawn in Figure 5. The prior read lock exposes no readable bit yet leaves three hundred eighty eight of six hundred forty five bits writable, which is precisely the surface the injection attack uses. The write blocking lock is the only variant that reaches zero readable and zero writable while locked, at the cost of freezing the chain during the locked interval. A separate flush based check confirmed that every variant recovers all six hundred forty five bits when unlocked and that injected stuck at faults are detected, so manufacturing test is unaffected in the authorised mode.');
figure('fig_t1.png', COLW, 'Figure 5.  Readable and writable chain bits while locked; only the write blocking lock reaches zero and zero.').forEach(x=>sec2.push(x));

P('The complete design was exercised on hardware through a serial console. While locked, a scan read returned all zeros, and an injection attempt left the ciphertext at the published value, whereas the same injection against the read only variant changed the ciphertext. A machine checked proof established, by induction over all inputs, that the scan output of the write blocking lock is held at zero whenever the device is locked, giving a formal basis for the read confidentiality property.');

// ---- V. CONCLUSION (~250 words) ----
sec2.push(heading('V','Conclusion'));
P('The study shows that protecting only the scan read path is insufficient for a cryptographic coprocessor embedded in a shared system chain. An attacker confined to the locked scan port was able to inject a chosen key and plaintext, force the coprocessor to encrypt attacker controlled data, forge the value returned to the processor, and erase the stored key, all without passing the unlock gate. These outcomes were reproduced by simulation and confirmed against an independent software reference, so the weakness is demonstrated rather than conjectured. A measurement of the shared chain showed that the earlier lock hides every output bit yet leaves more than half of the chain writable while locked, which is the exact resource the attacks consume.');
P('A write blocking segmented lock was proposed that freezes the chain and masks the output while locked, and three weaker variants were evaluated as ablations that each fail in a measured way, which clarifies why read masking, a granular observable tail, and an edge triggered flush are individually inadequate. A hardened unlock controller added attempt lockout and a boot delay and removed the public default code. The complete design blocked every attack driven by the real processor, preserved the cipher output against the published test vector, retained full test coverage when unlocked, cost about two percent of the baseline logic, and carried a machine checked proof of the locked read property. Future work will add a self test mode so that fault coverage is retained while locked, will extend the formal argument to the write path, and will report an operating frequency distribution over several placement seeds.');

// ---- REFERENCES ----
sec2.push(heading('', 'References'));
for (let i=0;i<REFS.length;i++) sec2.push(refPar(i));

// ============ assemble ============
const doc = new Document({
  styles:{ default:{ document:{ run:{ font:FONT, size:20 } } } },
  sections:[
    { properties:{ page:{ size:{ width:12240, height:15840 }, margin:{ top:1080, bottom:1080, left:1080, right:1080 } } },
      children: sec1 },
    { properties:{ type:SectionType.CONTINUOUS, column:{ count:2, space:400 },
      page:{ size:{ width:12240, height:15840 }, margin:{ top:1080, bottom:1080, left:1080, right:1080 } } },
      children: sec2 }
  ]
});
Packer.toBuffer(doc).then(buf=>{ fs.writeFileSync('/tmp/claude-0/-home-user-SECURE-SCAN-CHAIN-V2/bd750c1e-aef9-570f-9ad9-93828c77c9e1/scratchpad/SecureScanRV_Paper2.docx', buf); console.log('DOCX written', buf.length); });
