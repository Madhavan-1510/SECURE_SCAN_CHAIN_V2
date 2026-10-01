// Comprehensive ~30-page project report (.docx) for SecureScan-RV.
const fs = require('fs');
const D = require('docx');
const { Document, Packer, Paragraph, TextRun, ImageRun, Table, TableRow, TableCell,
  WidthType, BorderStyle, AlignmentType, HeadingLevel, PageBreak, ShadingType,
  TableOfContents, LevelFormat, PageNumber, Header, Footer } = D;

const FIGDIR = '/tmp/claude-0/-home-user-SECURE-SCAN-CHAIN-V2/bd750c1e-aef9-570f-9ad9-93828c77c9e1/scratchpad/fig/';
const img = f => fs.readFileSync(FIGDIR + f);
const FONT = 'Calibri', MONO = 'Consolas';
const C = []; // document body children

// ---------- helpers ----------
const t = (text, o={}) => new TextRun({ text, font:o.mono?MONO:FONT, size:o.size||22,
  bold:o.bold||false, italics:o.italics||false, color:o.color });
function para(text, o={}) {
  C.push(new Paragraph({ alignment:o.align||AlignmentType.JUSTIFIED,
    spacing:{after:o.after!=null?o.after:140, line:264},
    children: Array.isArray(text)?text:[t(text,o)] }));
}
function h1(text){ C.push(new Paragraph({ heading:HeadingLevel.HEADING_1, spacing:{before:260, after:140},
  children:[ new TextRun({text, font:FONT, size:30, bold:true, color:'1F3864'}) ] })); }
function h2(text){ C.push(new Paragraph({ heading:HeadingLevel.HEADING_2, spacing:{before:200, after:100},
  children:[ new TextRun({text, font:FONT, size:26, bold:true, color:'2E5496'}) ] })); }
function h3(text){ C.push(new Paragraph({ heading:HeadingLevel.HEADING_3, spacing:{before:160, after:80},
  children:[ new TextRun({text, font:FONT, size:23, bold:true, color:'1F4E79'}) ] })); }
function bullet(text, o={}){ C.push(new Paragraph({ bullet:{level:o.level||0}, spacing:{after:60, line:260},
  children: Array.isArray(text)?text:[t(text,o)] })); }
function term(name, def){ C.push(new Paragraph({ spacing:{after:80, line:260},
  children:[ t(name+' — ',{bold:true}), t(def) ] })); }
function code(lines){ C.push(new Table({ width:{size:9360,type:WidthType.DXA}, columnWidths:[9360],
  rows:[ new TableRow({children:[ new TableCell({ width:{size:9360,type:WidthType.DXA},
    shading:{type:ShadingType.CLEAR, fill:'F2F4F8'}, margins:{top:80,bottom:80,left:140,right:140},
    children: lines.map(l=> new Paragraph({spacing:{after:0,line:230},
      children:[ new TextRun({text:l===''?' ':l, font:MONO, size:17}) ]})) }) ]}) ]})); }
function pagebreak(){ C.push(new Paragraph({children:[new PageBreak()]})); }
function fig(file, cap, wIn){
  const sizes={ 'fig_top.png':[6.4,1.8],'fig_chain.png':[4.2,4.2],'fig_g4.png':[5.2,3.8],
    'fig_overhead.png':[5.6,3.0],'fig_t1.png':[5.6,3.0],'fig_scancell.png':[6.0,1.7],'fig_modes.png':[5.0,3.4]};
  const s=sizes[file]||[5.5,3.2]; const w=wIn||s[0], h=s[1]*(w/s[0]);
  C.push(new Paragraph({alignment:AlignmentType.CENTER, spacing:{before:120,after:20},
    children:[ new ImageRun({type:'png', data:img(file), transformation:{width:Math.round(w*96), height:Math.round(h*96)}}) ]}));
  C.push(new Paragraph({alignment:AlignmentType.CENTER, spacing:{after:160},
    children:[ new TextRun({text:cap, font:FONT, size:18, italics:true}) ]}));
}
function th(s){ return new TableCell({ shading:{type:ShadingType.CLEAR, fill:'D9E2F3'}, margins:{top:40,bottom:40,left:80,right:80},
  children:[ new Paragraph({children:[ new TextRun({text:s, font:FONT, size:18, bold:true}) ]}) ], width:{size:s.w,type:WidthType.DXA} }); }
function tbl(widths, header, rows){
  const mk=(cells,hd)=> new TableRow({children: cells.map((c,i)=> new TableCell({
    width:{size:widths[i],type:WidthType.DXA}, shading: hd?{type:ShadingType.CLEAR, fill:'D9E2F3'}:undefined,
    margins:{top:40,bottom:40,left:80,right:80},
    children:[ new Paragraph({spacing:{after:0,line:230}, children:[ new TextRun({text:c, font:FONT, size:18, bold:hd||false}) ]}) ] })) });
  C.push(new Table({ width:{size:widths.reduce((a,b)=>a+b,0),type:WidthType.DXA}, columnWidths:widths,
    rows:[ mk(header,true), ...rows.map(r=>mk(r,false)) ] }));
  C.push(new Paragraph({spacing:{after:140},children:[t(' ')]}));
}

// ===================== TITLE PAGE =====================
C.push(new Paragraph({spacing:{before:1600, after:200}, alignment:AlignmentType.CENTER,
  children:[ new TextRun({text:"SecureScan-RV", font:FONT, size:64, bold:true, color:"1F3864"}) ]}));
C.push(new Paragraph({alignment:AlignmentType.CENTER, spacing:{after:120},
  children:[ new TextRun({text:"Securing Scan Read and Write for a PCPI-Coupled AES-128 Coprocessor on a RISC-V System-on-Chip", font:FONT, size:30, bold:true}) ]}));
C.push(new Paragraph({alignment:AlignmentType.CENTER, spacing:{after:600},
  children:[ new TextRun({text:"Comprehensive Project Report", font:FONT, size:26, italics:true, color:"2E5496"}) ]}));
C.push(new Paragraph({alignment:AlignmentType.CENTER, spacing:{after:80}, children:[ new TextRun({text:"A complete explanation of the design, the attacks, the defenses,", font:FONT, size:22}) ]}));
C.push(new Paragraph({alignment:AlignmentType.CENTER, spacing:{after:600}, children:[ new TextRun({text:"the register-transfer-level code, the testbenches, the design-for-test concepts, and every result.", font:FONT, size:22}) ]}));
C.push(new Paragraph({alignment:AlignmentType.CENTER, spacing:{after:60}, children:[ new TextRun({text:"Author: Madhavan R", font:FONT, size:22, bold:true}) ]}));
C.push(new Paragraph({alignment:AlignmentType.CENTER, spacing:{after:60}, children:[ new TextRun({text:"Department of Electronics and Communication Engineering", font:FONT, size:20}) ]}));
C.push(new Paragraph({alignment:AlignmentType.CENTER, spacing:{after:60}, children:[ new TextRun({text:"Saveetha Engineering College, Chennai, India", font:FONT, size:20}) ]}));
C.push(new Paragraph({alignment:AlignmentType.CENTER, spacing:{after:600}, children:[ new TextRun({text:"Target device: AMD/Xilinx Spartan-7 (Boolean Board, XC7S50-CSGA324)", font:FONT, size:20}) ]}));
C.push(new Paragraph({alignment:AlignmentType.CENTER, children:[ new TextRun({text:"Simulation: Icarus Verilog 12.0   |   Synthesis: Vivado   |   Formal: Yosys and SymbiYosys with Z3", font:FONT, size:18, italics:true}) ]}));
pagebreak();

// ===================== TABLE OF CONTENTS =====================
h1("Table of Contents");
C.push(new TableOfContents("Contents", { hyperlink:true, headingStyleRange:"1-2" }));
C.push(new Paragraph({children:[t("(In Microsoft Word, right-click this table and choose Update Field to populate page numbers.)",{italics:true,size:18})]}));
pagebreak();

// ===================== CH 1: INTRODUCTION =====================
h1("1. Introduction and Motivation");
para("Modern integrated circuits are almost impossible to manufacture reliably without a test infrastructure built into the silicon itself. The dominant such infrastructure is the scan chain, a design-for-test feature that links the internal storage elements of a chip into long shift registers. During test, an engineer can load any desired pattern into every flip-flop and read back the response, which makes an otherwise opaque chip fully controllable and observable. This capability is indispensable for catching manufacturing defects, yet it is also a security hazard: the very same access that helps a tester also helps an attacker. If a secret key ever rests in a flip-flop that belongs to the scan chain, an attacker who can operate the test port can shift that key straight out, with no mathematical attack on the cipher at all.");
para("This project studies that hazard on a realistic system rather than on an isolated cipher. The system is a complete System-on-Chip: a RISC-V processor (PicoRV32) with a custom AES-128 cryptographic coprocessor attached over the Processor Co-Processor Interface, and a single scan chain of six hundred forty five bits shared across the processor-facing control logic, the coprocessor staging registers, and the Advanced Encryption Standard datapath. An earlier phase of the work (referred to throughout as Paper 1) added a lock that masks the coprocessor scan output while locked, and that lock successfully defeats an attacker who only reads the chain.");
para("The present work (Paper 2) shows that defending the read path alone is not enough. While the lock blanks the scan output, it leaves the scan input open, so an attacker can write the chain even while the device is locked. Through that open write path, and without ever supplying the unlock code, an attacker can inject a chosen key and plaintext and make the coprocessor encrypt attacker-controlled data, can forge the ciphertext that the processor reads back, and can erase the stored key. The project then designs a stronger lock that blocks both the read and the write path, evaluates three weaker alternatives that each fail in a measurable way, hardens the unlock mechanism, measures the exact cost on a Spartan-7 field-programmable gate array, proves one key property with a formal tool, and demonstrates the whole story live on hardware through a serial console.");
para("This report is written to be self-contained. Every term is defined, every file is explained, every attack and defense is described mechanically, and every result quoted here was produced by an actual simulation, synthesis, or formal run during the project. A reader who has never seen a scan chain or the Advanced Encryption Standard should be able to follow the entire argument from this document alone.");

h2("1.1 What the reader will learn");
bullet("The fundamentals of design-for-test: scan cells, scan chains, controllability, observability, stuck-at faults, and automatic test pattern generation.");
bullet("The structure of the Advanced Encryption Standard (AES-128) and how an iterative hardware engine computes it one round per clock cycle.");
bullet("How a RISC-V processor offloads work to a coprocessor over the Processor Co-Processor Interface.");
bullet("Exactly how a scan chain leaks a key, and the new result that it also accepts an injected key while locked.");
bullet("The complete defense: a write-blocking segmented lock, a hardened unlock controller, and why three weaker variants are insufficient.");
bullet("How the design is verified: a thirty-testbench regression, mutation testing, a formal proof, field-programmable gate array synthesis numbers, and a live board demonstration.");

// ===================== CH 2: BACKGROUND CONCEPTS =====================
h1("2. Background Concepts and Terminology");
para("This chapter defines, from first principles, every concept the rest of the report relies on. A reader already fluent in digital design and cryptography may skim it; a reader new to the area should read it fully, because the security argument depends on these mechanics.");

h2("2.1 Digital logic building blocks");
term("Flip-flop (register bit)", "a one-bit memory element that captures the value on its data input at the active edge of the clock and holds it until the next edge. A group of flip-flops that stores a multi-bit value is called a register. The AES key, for example, is stored in a one hundred twenty eight bit register, that is, one hundred twenty eight flip-flops.");
term("Combinational logic", "logic whose output depends only on the present inputs (for example the substitution and mixing steps of AES). It has no memory. Registers separate blocks of combinational logic and give a circuit its notion of clocked time.");
term("Clock and clock edge", "a periodic square wave that paces the circuit. Flip-flops update on the rising (positive) edge in this design. One clock period at one hundred megahertz is ten nanoseconds.");
term("Reset", "a signal that forces registers to a known starting value. This design uses active-low reset, written resetn, meaning the circuit is held in reset while the signal is zero and runs when it is one.");

h2("2.2 Design-for-test and the scan chain");
para("A manufactured chip can contain billions of transistors, yet its external pins are few. A defect deep inside cannot be reached from the pins during normal operation. Design-for-test, abbreviated DFT, adds structure so that internal nodes become reachable. The most widely used DFT technique is scan.");
term("Scan cell", "an ordinary functional flip-flop augmented with a two-to-one multiplexer on its data input, selected by a signal called scan-enable. When scan-enable is low the flip-flop captures its normal functional value; when scan-enable is high it captures the value coming from the previous cell in the chain. Figure 1 shows this structure.");
fig("fig_scancell.png","Figure 1. A scan cell: a flip-flop with a multiplexer that selects functional data or the scan-chain input.");
term("Scan chain", "many scan cells wired output-to-input so that, when scan-enable is high, they behave as one long shift register. A pattern shifted in at one end (scan-in) travels cell by cell on each clock, and the stored contents travel out the other end (scan-out). A chain of six hundred forty five cells needs six hundred forty five clock pulses to be fully loaded or unloaded.");
term("Functional mode versus scan mode", "with scan-enable low the circuit does its real job (here, AES encryption); with scan-enable high the same flip-flops form the test shift register. The two modes share the physical flip-flops, which is efficient but is also the root of the security problem. Figure 2 illustrates the two modes.");
fig("fig_modes.png","Figure 2. The same flip-flops serve functional mode and scan mode; a key in a scannable flop can be shifted out.");
term("Controllability", "the ability to set an internal node to a desired value. Scan gives near-total controllability, because any pattern can be shifted in. A write-based attack abuses controllability.");
term("Observability", "the ability to determine an internal node's value from an output. Scan gives near-total observability, because the stored state can be shifted out. A read-based attack abuses observability.");
term("Stuck-at fault", "the standard manufacturing-defect model, in which a node is permanently stuck at logic zero (stuck-at-0) or logic one (stuck-at-1). Test patterns are generated to make each such fault change an observable output, which detects the defect.");
term("Automatic test pattern generation (ATPG)", "software that computes the input patterns needed to detect a target set of faults. Scan makes ATPG tractable because every flip-flop becomes directly controllable and observable.");
term("Fault coverage", "the fraction of modeled faults that a given test set detects. High coverage is the central goal of manufacturing test, which is why removing scan access entirely is undesirable and why the trade-off studied in this project matters.");
term("Flush test", "a simple chain-integrity check that shifts a known pattern (often alternating ones and zeros) through the whole chain and verifies it emerges intact; a broken or stuck cell corrupts the stream and is detected.");

h2("2.3 The Advanced Encryption Standard, AES-128");
para("AES is the worldwide standard block cipher, defined in the Federal Information Processing Standards publication 197. The one hundred twenty eight bit variant, AES-128, transforms a one hundred twenty eight bit block of plaintext into a one hundred twenty eight bit block of ciphertext under a one hundred twenty eight bit key, and is reversible with the same key.");
term("Block and key", "both are one hundred twenty eight bits, that is, sixteen bytes, written as thirty two hexadecimal characters. The standard known-answer test used throughout this project uses key 000102030405060708090A0B0C0D0E0F and plaintext 00112233445566778899AABBCCDDEEFF, which produce ciphertext 69C4E0D86A7B0430D8CDB78070B4C55A.");
term("Rounds", "AES-128 applies ten rounds of transformation to the block. Each round mixes the data and combines it with a round key derived from the main key.");
term("SubBytes", "a non-linear byte substitution using a fixed lookup table called the S-box. It provides confusion, making the relationship between key and ciphertext complex. In hardware this is sixteen parallel S-box lookups on the sixteen state bytes.");
term("ShiftRows", "a byte permutation that cyclically shifts the rows of the state, spreading bytes across columns.");
term("MixColumns", "a linear mixing of each column of the state over a finite field, providing diffusion so that each output byte depends on several input bytes. It is skipped in the final round.");
term("AddRoundKey", "a bitwise exclusive-or of the state with the round key; this is where the secret enters each round.");
term("Key schedule and K10", "the process that expands the main key into eleven round keys. The last round key, called K10, is produced by the schedule and, crucially, the main key can be computed back from K10. A design that leaves K10 observable therefore leaks the master key just as surely as leaking the key directly.");
term("Iterative engine", "the hardware here computes one round per clock cycle and reuses the same logic ten times, which is small and typical for an embedded coprocessor. A register called the round counter tracks progress, and a small finite-state machine sequences idle, running, and done.");

h2("2.4 RISC-V, PicoRV32, and the coprocessor interface");
term("RISC-V", "an open instruction-set architecture. Because it is open, custom instructions and coprocessors can be added without licensing restrictions, which is why it is a natural platform for a cryptographic accelerator.");
term("PicoRV32", "a small, widely used, open-source RISC-V processor core. In this project it is used unmodified, which was verified by comparing the source against the upstream project; this matters because a reviewer must trust that the processor itself was not altered to make the attack or defense work.");
term("Processor Co-Processor Interface (PCPI)", "a simple handshake built into PicoRV32 by which the processor offers any instruction it does not itself implement to an external unit. The coprocessor inspects the instruction, claims it if it recognizes the custom opcode, performs the work, and signals completion. This is how software running on the processor drives the AES engine.");
term("Custom-1 opcode and funct3", "the AES instructions use the RISC-V custom-1 opcode, and a three-bit field called funct3 selects the operation: load a key word, load a plaintext word, start encryption, read a result word, or read status. Because the key and block are one hundred twenty eight bits but a processor register is thirty two bits, the key and block are loaded four words at a time.");
term("System-on-Chip (SoC)", "a complete system — processor, coprocessor, memory, and peripherals — on one chip. The security significance here is that the AES key shares one scan chain with unrelated SoC logic, unlike the textbook case of a standalone cipher with its own dedicated chain.");

h2("2.5 Implementation and verification tools");
term("Register-transfer level (RTL)", "a description of hardware in terms of registers and the logic between them, written in a hardware description language (Verilog here). Synthesis turns RTL into actual gates.");
term("Verilog and testbench", "Verilog is the hardware description language used. A testbench is a non-synthesizable Verilog program that drives a design with stimulus, checks the responses with assertions, and prints a pass or fail verdict. It is how a design is verified before it is built.");
term("Icarus Verilog", "the open-source Verilog simulator used for all functional verification in this project, version 12.0. A simulation executes the RTL and the testbench together and reports the result.");
term("Field-programmable gate array (FPGA)", "a reconfigurable chip whose logic is defined by a downloaded configuration called a bitstream. It lets a design run in real hardware without fabricating a custom chip. The target here is a Spartan-7 device on the Boolean Board.");
term("Vivado", "the vendor toolchain that synthesizes RTL, places and routes it onto the FPGA, reports resource usage and timing, and generates the bitstream.");
term("Look-up table (LUT) and flip-flop (FF)", "the two main FPGA resources. A LUT implements a small piece of combinational logic; a flip-flop stores one bit. Design cost is reported mainly in LUTs and flip-flops.");
term("Maximum frequency (Fmax) and worst negative slack (WNS)", "timing metrics. Worst negative slack is the timing margin on the most critical path; a positive value means the design meets the target clock. Maximum frequency is the highest clock the design can run at, computed from the slack.");
term("Formal verification", "mathematically proving a property holds for all inputs, rather than testing specific cases. This project uses Yosys with the SymbiYosys front-end and the Z3 solver to prove a property by induction, meaning it holds for every input and for all time, not merely up to a bounded number of cycles.");
term("Mutation testing", "a way to check that the testbenches are meaningful. A deliberate bug (a mutant) is injected into the design; if the testbench still passes, the test is blind to that bug and is inadequate. Every mutant injected in this project was caught, which is evidence the tests are not vacuous.");

// ===================== CH 3: THREAT MODEL =====================
h1("3. Threat Model");
para("A security claim is only meaningful against a stated adversary. This chapter fixes what the attacker can do, what is public, and what the defense must achieve.");
h2("3.1 Attacker capabilities");
bullet("Physical or test-port (JTAG-style) access: the attacker controls the scan-enable and scan-in signals, observes scan-out, and can halt and single-step the clock.");
bullet("The attacker can also trigger normal-mode operation, for example by issuing coprocessor instructions, and can read any public result.");
bullet("The attacker knows the register-transfer-level design, the scan-chain map, and the public default unlock code, following the principle that security must not rest on secrecy of the design.");
bullet("The attacker may submit many unlock attempts.");
h2("3.2 Assets to protect");
bullet("Confidentiality of the AES-128 master key, and of anything from which it can be recovered, including the final round key K10 and early-round state.");
bullet("Integrity of the key, the plaintext, the ciphertext, and the control state; the attacker must not be able to substitute any of these.");
bullet("Availability of the coprocessor; the attacker must not be able to wipe or hang it through the test port.");
h2("3.3 Attacker goals");
bullet("Confidentiality goal: recover key bits (a read attack).");
bullet("Integrity goal: make the device encrypt under an attacker-chosen key or plaintext, or forge the result (a write attack).");
bullet("Availability goal: erase or stall the device.");
bullet("Unlock goal: pass the lock by guessing or by exploiting the default code.");
h2("3.4 Out of scope");
para("Power and electromagnetic side channels, breaking AES mathematically, invasive microprobing, voltage or clock glitch fault injection, and software-level exfiltration are not considered. The contribution concerns the scan and test interface specifically.");
h2("3.5 Defense goals");
para("While locked, no sensitive bit may reach scan-out (read protection), and no attacker-chosen value may reach any key, plaintext, or control register (write protection). The unlock mechanism must resist guessing. When unlocked, behavior must be identical to the undefended design so that legitimate manufacturing test is unaffected. In every case the functional cipher result must remain correct.");

// ===================== CH 4: ARCHITECTURE =====================
h1("4. System Architecture");
para("Figure 3 shows the whole system. The processor fetches and executes a program; when it meets the custom AES opcode it offers the instruction over the Processor Co-Processor Interface. The coprocessor wrapper claims it, drives the AES engine, and returns the result. Every flip-flop of interest also belongs to the shared scan chain, and the lock decides what the scan port may do.");
fig("fig_top.png","Figure 3. Top-level organization: processor, coprocessor wrapper, AES engine, shared scan chain, write-blocking gate, and hardened lock.");
para("The coprocessor has two completely separate interfaces. The functional interface is the Processor Co-Processor Interface, used for real encryption. The test interface is the scan port. The central design principle is that the lock governs only the test interface; the functional interface never samples the lock. This is precisely why the defense can be strong on the test side while costing nothing in functional behavior: a locked device still encrypts correctly, it simply refuses scan access.");

h2("4.1 The instruction set of the coprocessor");
para("The coprocessor decodes the RISC-V custom-1 opcode. The three-bit funct3 field selects one of five operations, listed in Table 1. Because a processor register is thirty two bits and the key and block are one hundred twenty eight bits, loading uses a two-bit word index so that four load instructions assemble a full value.");
tbl([1500,5200,2660],["funct3","Instruction","Effect"],[
 ["000","AES_LOADKEY","load one thirty two bit key word, selected by the word index"],
 ["001","AES_LOADBLOCK","load one thirty two bit plaintext word"],
 ["010","AES_ENCRYPT","run the ten-round encryption on the loaded key and block"],
 ["011","AES_READRESULT","read back one thirty two bit ciphertext word"],
 ["100","AES_STATUS","read a busy flag so software can poll"]]);

h2("4.2 The six hundred forty five bit scan chain");
para("The scan chain threads seven registers in a fixed order from the scan input to the scan output. Only two of them, the round-key register and the key register, hold the master key, which is two hundred fifty six of the six hundred forty five bits, about thirty nine percent. The remainder is shared system state. This is the structural point that distinguishes the work from a standalone cipher: the secret is embedded in a much larger shared chain. Figure 4 draws the layout and Table 2 lists it precisely.");
fig("fig_chain.png","Figure 4. Front-to-back layout of the chain; the two protected key registers sit at the tail, nearest the scan output.");
tbl([2100,900,1900,1360],["Segment","Bits","Global range","Protected"],[
 ["key_stage","128","[127:0]","key residue"],
 ["block_stage","128","[255:128]","no (plaintext)"],
 ["fsm_state","1","[256]","no (control)"],
 ["round_reg","4","[260:257]","no (control)"],
 ["state_reg","128","[388:261]","partial (early rounds)"],
 ["round_key_reg","128","[516:389]","yes (equals K10 at done)"],
 ["key_reg","128","[644:517]","yes (master key)"]]);
para("Two facts from this table drive the whole attack and defense story. First, the key register sits at the very tail, nearest the scan output, so a full read dump exposes it. Second, the staging registers key_stage and block_stage sit at the very front, nearest the scan input, so a short write of one hundred twenty eight shifts lands an attacker value directly into them. The round-key register holding K10 is doubly dangerous because K10 inverts to the master key.");

// ===================== CH 5: RTL FILES =====================
h1("5. Register-Transfer-Level Design, File by File");
para("This chapter explains every synthesizable source file. The original files are the Paper 1 baseline and are reused unchanged; the files marked new were added for Paper 2. Understanding each one is necessary to follow the attacks and defenses.");

h2("5.1 Original (baseline) RTL");
term("picorv32.v", "the RISC-V processor core, used unmodified and confirmed byte-identical to the upstream open-source project. It fetches instructions, executes the base integer set, and offers unknown instructions over the coprocessor interface. Keeping it unmodified is a trust argument: the processor was not tweaked to suit the result.");
term("aes_pcpi_defs.vh", "a header file that defines the custom-1 opcode and the five funct3 codes. Including it everywhere keeps the encodings consistent between the coprocessor and the testbenches.");
term("aes_sbox.v", "the AES substitution box, a fixed eight-bit-to-eight-bit lookup table. Twenty instances are used per round: sixteen on the data state and four in the key schedule. It is pure combinational logic.");
term("aes_core.v", "the AES-128 engine. It holds the key register, the round-key register, the state register, and the round counter, and it sequences ten rounds with a small finite-state machine (idle, running, done). Each cycle it applies SubBytes, ShiftRows, MixColumns, and AddRoundKey, and it was scan-retrofitted so that its four registers are scan cells. The functional next-state of each register is computed by explicit combinational logic, reproducing the original behavior exactly, so that the storage can live inside scan cells without changing the result.");
term("aes_pcpi.v", "the wrapper that connects the engine to the processor. It decodes the custom instruction combinationally (required, because the processor expects an immediate claim), holds the key-staging and block-staging registers and a one-bit coprocessor state, and manages the handshake. It also fixes a subtle handshake race, documented in its comments, in which a stale done flag from a previous operation could be mistaken for completion of a new one; a guard named core-seen-running prevents this.");
term("scan_cell.v", "the one-bit scan flip-flop of Figure 1. On reset it takes a reset value; when scan-enable is high it captures scan-in; otherwise it captures the functional value. Its output doubles as the scan output to the next cell.");
term("scan_chain.v", "a parameterized register built from scan cells, wiring each cell's output to the next cell's scan input to form a shift register of any requested width.");
term("scan_lock_controller.v", "the Paper 1 lock. It is a fail-safe design that powers up locked, unlocks only when a presented code equals a fixed unlock code, and relocks on demand. It is deliberately simple and carries no cryptographic weight of its own; its only job is access control, and the real protection is the masking it enables.");
term("secure_scan_rv_top_v2.v", "the Paper 1 top level that instantiates the processor, the coprocessor, a memory, and the lock. It is left untouched so that the Paper 1 synthesis numbers remain a valid baseline.");
term("Board support files", "board_top.v, lock_switch_ctrl.v, scan_dump_controller.v, fpga_top.v, io_conditioning.v, power_on_reset.v, edge_reset_pulse.v, seven_seg_hex.v, uart_tx.v, and a constraints file. These provide the Paper 1 on-board demonstration, with debounced buttons, a seven-segment display, a serial transmitter, and clean reset conditioning.");

h2("5.2 New RTL added for Paper 2");
term("aes_core_def.v and aes_pcpi_def.v", "parameterized defense variants of the engine and the wrapper. A single parameter named DEFENSE_LEVEL selects the behavior: level one reproduces the Paper 1 lock, level four is the write-blocking lock, and levels two, three, and five are the three weaker variants evaluated as ablations. The functional datapath is identical to the originals; only the scan gating changes with the level.");
term("scan_lock_controller_v2.v", "the hardened lock, called L1. It adds an attempt counter with a lockout period, a boot delay during which attempts are ignored, and it removes the public default code by taking the reference code on a dedicated provisioning input. It remains fail-safe locked out of reset. A design rule established by measurement is that the boot delay should be at least as long as the lockout period, otherwise an attacker who can cycle power defeats the lockout.");
term("secure_scan_rv_top_def.v", "a new top level with two parameters: DEFENSE_LEVEL selects the datapath variant and LOCK_VERSION selects no lock, the Paper 1 lock, or the hardened lock. This single top is what is synthesized to obtain the overhead numbers for every configuration, and it is the first place the hardened lock is wired into a complete system.");
term("board_top_def.v", "the Paper 2 board demonstration top. It instantiates both a Paper 1 variant and a write-blocking variant on one bitstream, sharing one hardened lock, and a switch selects which one the serial console drives. It exposes no key or ciphertext on any debug pin; the only readback is the scan port itself, which is exactly what the defense governs.");
term("scan_uart_bridge.v and uart_rx.v", "the on-board serial console. The bridge is both a coprocessor-interface master and a scan driver: it receives single-letter commands over the serial receiver, drives the scan port or issues coprocessor instructions, and prints results as hexadecimal. It lets the whole attack and defense be demonstrated from a laptop terminal.");

// ===================== CH 6: TESTBENCHES =====================
h1("6. Testbenches and the Regression Suite");
para("A testbench is a Verilog program that instantiates the design, drives it with stimulus, and checks the response with assertions that each print a pass or fail line. A testbench passes only when it prints its completion banner and no failure marker. The whole set is run by a single script that compiles each testbench against all the design files, runs it in its own directory, and counts a missing, uncompilable, or timed-out testbench as a failure. The full suite contains thirty gated testbenches and passes completely.");
h2("6.1 Functional and structural testbenches");
term("tb_scan_cell, tb_scan_chain", "verify the scan primitives: the correct priority of reset, scan, and functional capture, the bit ordering of the shift register, and the pre-shift sampling rule.");
term("tb_aes_core, tb_aes_pcpi", "verify the cipher and the handshake: the engine reproduces the standard known-answer ciphertext, and the wrapper never stalls non-AES instructions while holding the interface for the full encryption latency.");
term("tb_double_encrypt_control, tb_scan_resume", "isolate and then confirm the fix of a handshake race, and verify that the coprocessor performs a correct fresh encryption after a scan session without an intervening reset, across twenty cases.");
term("tb_cpu_driven_aes", "the most realistic functional test: the actual processor fetches a hand-assembled program, recognizes the custom opcode, drives the coprocessor over the real interface, and stores the ciphertext to memory, which matches the standard known-answer value.");
term("tb_scan_attack_harness, tb_fpga_top, tb_board_top", "verify the synthesizable attack and defense demonstration logic and the board input conditioning, including a deliberately bouncy button model.");
h2("6.2 Attack and defense testbenches");
term("tb_scan_attack, tb_attack_matrix", "the baseline read attack and the attack-by-design matrix for the undefended and Paper 1 configurations.");
term("tb_attack_write_inject", "the key and plaintext injection attack, sweeping shift counts and the plaintext least-significant-bit interaction with the finite-state machine.");
term("tb_attack_modeswitch", "the ciphertext-spoof attack, in which a bare result read returns a scan-forced value as if it were a genuine ciphertext.");
term("tb_zeroize", "the erase attack, with a direct assertion that the key and round-key registers are exactly zero after enough shifts while locked, compared against an independent shift model, with ninety seven checks.");
term("tb_attack_bruteforce, tb_lock_v2, tb_scan_lock_v2", "the brute-force cost model against the Paper 1 lock, and the unit and integration tests of the hardened lock, including ten injected mutants that are all caught.");
term("tb_attack_defenses", "the central seven-column attack-by-design matrix covering the undefended design, the Paper 1 lock, the write-blocking lock, and the three weaker variants, with fifty eight assertions and golden ciphertexts checked against an independent software cipher.");
term("tb_defense_equiv", "a lock-step equivalence check proving that, when unlocked, every defense variant behaves cycle-for-cycle like the undefended design over nine hundred random cycles.");
term("tb_def_functional", "a per-variant functional check: the standard known-answer test and a back-to-back encryption for all five variants, locked and unlocked.");
term("tb_scan_resume_def, tb_cpu_driven_aes_def", "the resume sweep and the real-processor program run on every variant and every lock version, one hundred resume cases and eighteen configurations respectively.");
term("tb_attack_top_def", "the attacks driven through the complete new top level by the real processor with the real hardened lock, confirming that only the write-blocking lock with the hardened unlock blocks every attack.");
term("tb_testability_t1, tb_testability_t2", "the two design-for-test measurements explained in Chapter 9: how much of the chain is readable and writable while locked, and whether the chain stays fully testable and fault-detecting when unlocked.");
term("tb_board_top_def", "a simulation of the serial console that types commands over the modeled serial line and checks every reply, so the board demonstration is verified before any bitstream is built.");

// ===================== CH 7: ATTACKS =====================
h1("7. The Attacks in Depth");
para("This chapter explains each attack mechanically. Every ciphertext quoted was produced by simulation and independently confirmed against a separate software implementation of the cipher, so the outcomes are demonstrated rather than argued.");
h2("7.1 A1: scan-read key recovery");
para("The attacker loads a key and plaintext, starts an encryption, freezes the circuit a few cycles in, then raises scan-enable and shifts the whole chain out. The window of the stream corresponding to the key register contains the key exactly. On the undefended design the key is recovered with no cryptanalysis. An exhaustive search of every one hundred twenty eight bit window of the captured stream found the key in exactly two places, the key register and the key-staging residue, confirming the scan map is complete. The Paper 1 lock blocks this attack by masking the scan output to zero while locked.");
h2("7.2 A3: key and plaintext injection (the headline result)");
para("This is the central new attack. While the device is locked and never unlocked, the attacker shifts a chosen one hundred twenty eight bit value into the key-staging register, which sits at the very front of the chain and therefore needs only one hundred twenty eight shifts. The same shift pushes the previous staging contents into the block-staging register. The attacker then issues the normal encrypt instruction over the coprocessor interface. The engine loads the attacker's value as the key and encrypts, producing a ciphertext under an attacker-chosen key and plaintext. With attacker key 0F1E2D3C4B5A69788796A5B4C3D2E1F0 the resulting ciphertext is 50b58e80ce784e98ad48d63390c5dfd7, which matches the independent software computation exactly. The Paper 1 lock does not stop this, because it never gated the scan input.");
h2("7.3 A2: ciphertext spoofing");
para("Here the attacker shifts a chosen value into the state register, which holds the cipher output, and then issues a bare result-read instruction with no encryption. The coprocessor returns the scan-forced value to the processor as if it were a genuine ciphertext. Software that trusts the coprocessor is thus fed a forged result. This works on the undefended design and on the Paper 1 lock alike.");
h2("7.4 A6: zeroize and denial of service");
para("Because the lock, when it does gate anything, feeds a constant zero into the round-key register, shifting while locked drives zeros into the key registers and erases the key. A direct assertion confirmed both key registers become exactly zero, and a subsequent encryption then produces the encryption of an all-zero block under an all-zero key, the value 66e94bd4ef8a2c3b884cfa59ca342b2e. This is an availability attack: the device is left unusable.");
h2("7.5 A4: unlock brute force");
para("The Paper 1 lock accepts one guess per clock with no attempt limit and ships with a public default code, so the worst case is two to the power thirty two guesses, about forty three seconds at one hundred megahertz, and the public default makes it a zero-effort attack in practice. The hardened lock addresses this, as Chapter 8 describes.");
h2("7.6 A5: processor register file");
para("A broader attack that scans the processor register file is noted as a deferred appendix item; it requires putting the register file into the chain and is not part of the core contribution.");

// ===================== CH 8: DEFENSES =====================
h1("8. The Defenses in Depth");
para("Five scan-side behaviors were implemented and compared, selected by the DEFENSE_LEVEL parameter, plus the hardened unlock controller. Only the write-blocking lock closes every attack; the other three variants are kept as ablations that show why simpler ideas are insufficient.");
h2("8.1 G0 and G1: undefended and the Paper 1 lock");
para("G0 is the undefended design, with the lock signal tied inactive; every attack succeeds. G1 is the Paper 1 lock: while locked it forces the scan output to a constant zero and gates the scan input of only the round-key register. It blocks the read attack but leaves the write path open, so injection, spoofing, and erase all still succeed.");
h2("8.2 G2 and G2R: granular masking and recirculating tail");
para("G2 freezes only the sensitive segments and leaves a non-sensitive tail observable, aiming to keep part of the chain testable. It is read-safe, but the tail remains writable, so an attacker can still corrupt the plaintext and can hang the encryption. G2R makes the tail recirculate so that the attacker cannot choose the value, yet the rotation still corrupts the plaintext and can still hang the engine. Both are read-masking variants, not write defenses.");
h2("8.3 G3: flush on scan-enable edge");
para("G3 clears every register on a transition of scan-enable while locked. It turns an injection into an erase, which seems protective, but the flush is edge-triggered: holding scan-enable high defeats it, and a single hostile shift erases the key, making it the cheapest denial of service of all variants.");
h2("8.4 G4: write blocking (the proposed defense)");
para("G4 freezes the entire chain while locked by forcing the capture-enable of every scan cell inactive, and it keeps the scan output masked. The gate depends only on the lock signal, not on any shift count, so protection is active before the very first sampled bit and cannot be shifted around. Figure 5 shows the structure. Because the functional path never samples the lock, the engine still encrypts correctly while locked. G4 is the only variant that blocks the read, the spoof, the injection, and the erase at once.");
fig("fig_g4.png","Figure 5. The write-blocking gate: the capture enable of every scan cell is forced inactive while locked, and the output is masked.");
h2("8.5 L1: the hardened unlock controller");
para("The hardened lock replaces the fixed public code with a provisioned reference supplied on a dedicated input, adds an attempt counter that triggers a lockout period after a few wrong codes, and adds a boot delay that ignores attempts for a time after reset so that power cycling cannot reset the attempt counter cheaply. The verified design rule is that the boot delay must be at least as long as the lockout period. Against this lock the brute-force cost at the default parameters is a projection of roughly forty five years, computed from a formula that was verified at scaled parameters.");
h2("8.6 Algorithm view of attack and defense");
code(["Attack A3 (injection), against an output-only lock:",
 "  assert locked = 1            # device never unlocked",
 "  for i in 1..128:             # key_stage is at the chain front",
 "      drive scan_in = Kstar[i]; pulse scan clock",
 "  issue AES_ENCRYPT over PCPI",
 "  issue AES_READRESULT -> C*   # C* = AES(Kstar, Pstar)",
 "",
 "Defense G4 (write blocking):",
 "  en_cell   = scan_en AND (NOT locked)   # 0 while locked -> no capture",
 "  scan_out  = locked ? 0 : tap            # masked while locked",
 "  => scan_in cannot reach any cell, and nothing is observable"]);

// ===================== CH 9: DFT / TESTABILITY =====================
h1("9. Design-for-Test Impact and Testability Metrics");
para("Freezing the chain protects it but also removes test access while locked. Two measurements quantify this trade-off exactly.");
h2("9.1 T1: readable and writable bits while locked");
para("For each variant the measurement loads known data, asserts the lock, and counts how many of the six hundred forty five chain bits can still be read at the output and written from the input. The result, drawn in Figure 6, is the sharpest single number in the project: the Paper 1 lock hides every output bit yet leaves three hundred eighty eight of the six hundred forty five bits writable, which is exactly the surface the injection attack consumes. Only the write-blocking lock reaches zero readable and zero writable.");
fig("fig_t1.png","Figure 6. Readable and writable chain bits while locked. Only the write-blocking lock reaches zero and zero.");
tbl([2200,1700,1700,2160],["Variant","Writable /645","Observable","Note"],[
 ["G1 (Paper 1)","388","0","read-locked but write-open"],
 ["G2 granular","132","133","tail only"],
 ["G3 flush","388","0","erased, not blocked"],
 ["G4 write-block","0","0","fully closed"],
 ["G2R recirculating","0","133","observable, not injectable"]]);
h2("9.2 T2: chain integrity and fault detection when unlocked");
para("The second measurement confirms the defense does not harm legitimate test. A flush test shifts a known alternating pattern and its complement through the chain and checks it emerges intact; every variant recovers all six hundred forty five bits when unlocked, so full test access is preserved in the authorized mode. Injected stuck-at faults at representative chain sites were all detected by the flush test, confirming the chain remains a usable manufacturing-test structure. The cost of the write-blocking lock is therefore confined to the locked interval only.");
para("A natural extension, noted as future work, is a built-in self-test mode so that fault coverage is retained even while locked, which would remove the only real drawback of the write-blocking approach.");

// ===================== CH 10: FORMAL =====================
h1("10. Formal Verification");
para("Testing exercises specific cases; formal verification proves a property for all inputs. Using Yosys with the SymbiYosys front-end and the Z3 solver, the read-confidentiality property of the write-blocking lock was proved: whenever the device is locked, the scan output is always zero. The proof succeeded by induction, which means it holds for every possible input sequence and for all time, not merely up to a bounded number of cycles. This gives a mathematical basis for the read-protection claim rather than a sampled one.");
para("A stronger write-side non-interference property, stating that no attacker scan input can change any register while locked, was formulated as a two-copy equivalence check. Its full form proved expensive for the solver because the model carries the entire cipher datapath, and it is recorded as ongoing work; the read-side proof stands as the completed formal result. The formal scripts are included in the project so the proof can be reproduced.");

// ===================== CH 11: RESULTS =====================
h1("11. Results");
h2("11.1 Simulation");
para("The full regression of thirty gated testbenches passes with zero failures under Icarus Verilog 12.0. The baseline read attack recovers the key exactly; the write-blocking lock returns the true known-answer ciphertext under every attack; the injection against the output-only lock changes the ciphertext to the predicted value while the write-blocking lock holds it at the correct value. Mutation testing injected deliberate faults into the defense and the lock, and every mutant was caught, which shows the testbenches are meaningful.");
h2("11.2 Attack-by-design matrix through the complete system");
tbl([1900,1500,1500,1500,1360],["Config","A1 read","A2 spoof","A3 inject","A6 erase"],[
 ["Undefended","succeeds","succeeds","succeeds","succeeds"],
 ["Paper 1 lock","blocked","succeeds","succeeds","succeeds"],
 ["Write-block + L1","blocked","blocked","blocked","blocked"]]);
para("Driven by the real processor with the real hardened lock, only the write-blocking configuration blocks all four attacks, and when unlocked it behaves exactly like the undefended design, so the defense is inert in authorized use.");
h2("11.3 Field-programmable gate array cost");
para("Synthesis on the Spartan-7 device gives the numbers in Table 5 and Figure 7. The read-lock overhead reproduces the previously reported fourteen additional look-up tables and one additional flip-flop, which validates the measurement setup. The write-blocking lock costs essentially the same as the read-only lock, and the complete design with the hardened unlock adds about two percent of the baseline logic while keeping the clock above one hundred twenty megahertz.");
tbl([2100,1300,1300,1500,1560],["Configuration","LUT","FF","Fmax MHz","Writes blocked"],[
 ["Baseline","2830","1225","128.7","no"],
 ["Read lock (Paper 1)","2844","1226","131.6","no"],
 ["Write-block","2843","1226","123.9","yes"],
 ["Full design + L1","2888","1260","122.6","yes"]]);
fig("fig_overhead.png","Figure 7. Look-up table and flip-flop utilization across the four configurations.");
h2("11.4 Live hardware demonstration");
para("The complete design was programmed onto the Boolean Board and driven from a serial console, and four demonstrations were captured. First, a known-answer encryption returned the standard ciphertext 69C4E0D86A7B0430D8CDB78070B4C55A, and an unlocked scan read then exposed the key, the final round key, and the ciphertext in the stream, which is the read attack shown live. Second, after relocking, the same scan read returned all zeros, confirming the read lock. Third, on the Paper 1 variant an injection while locked produced a ciphertext different from the known answer, confirming the write attack succeeds. Fourth, on the write-blocking variant the identical injection returned the true known-answer ciphertext, confirming the write attack is blocked. The color indicator was red while locked and green while unlocked. These four screens constitute the complete argument on silicon: the cipher is correct, the read lock hides the key, the write attack defeats the earlier lock, and the write-blocking lock defeats the attack.");

// ===================== CH 12: REPRODUCE =====================
h1("12. How to Reproduce");
para("Every result can be regenerated from the project tree.");
code(["# Functional + security simulation (30 testbenches):",
 "  ./run_regression.sh            # expect: SUMMARY passed=30 failed=0 total=30",
 "",
 "# Mutation testing of the defenses:",
 "  python3 mutate.py              # expect: all mutants caught",
 "",
 "# Formal read-lock proof:",
 "  sby -f -d formal/readlock formal/readlock.sby   # expect: DONE (PASS)",
 "",
 "# FPGA overhead (Vivado): set DEFENSE_LEVEL and LOCK_VERSION in",
 "  secure_scan_rv_top_def.v, synthesize + implement, then:",
 "  report_utilization ; report_timing_summary",
 "",
 "# Board demo: synthesize board_top_def.v with board_top_def.xdc,",
 "  program, open a serial terminal at 115200 8N1, type: S U<secret> K.. B.. E R L"]);

// ===================== CH 13: GLOSSARY =====================
h1("13. Glossary");
term("AddRoundKey","the AES step that exclusive-ors the state with a round key.");
term("ATPG","automatic test pattern generation; software that computes test patterns.");
term("Bitstream","the configuration file that programs an FPGA.");
term("Block cipher","an algorithm that encrypts a fixed-size block of data under a key; AES is one.");
term("Boot delay","a period after reset during which the hardened lock ignores unlock attempts.");
term("Controllability","the ease of setting an internal node to a chosen value.");
term("Coprocessor","a specialized unit that accelerates a task for a processor; here, AES.");
term("DEFENSE_LEVEL","the parameter selecting which scan-side defense a variant implements.");
term("Design-for-test (DFT)","design techniques, chiefly scan, that make a chip testable.");
term("Fault coverage","the fraction of modeled faults a test set detects.");
term("Finite-state machine","a small controller that sequences a circuit through named states.");
term("Flush test","shifting a known pattern through the chain to check its integrity.");
term("Fmax","the maximum clock frequency at which a design meets timing.");
term("Hexadecimal","base-sixteen notation; one hex character encodes four bits.");
term("Known-answer test","encryption of a fixed standard input to a publicly known output, used to confirm correctness.");
term("K10","the final AES round key, from which the master key can be recovered.");
term("Lockout","a period during which the hardened lock refuses attempts after several wrong codes.");
term("Look-up table (LUT)","the basic combinational resource of an FPGA.");
term("Masking","forcing the scan output to a constant so no secret is observable.");
term("Mutation testing","injecting deliberate bugs to confirm the tests can detect them.");
term("Non-interference","the formal property that secret inputs cannot influence an observable output.");
term("Observability","the ease of determining an internal node's value from an output.");
term("PCPI","the Processor Co-Processor Interface of PicoRV32.");
term("Round","one of the ten transformation passes of AES-128.");
term("Scan cell","a flip-flop with a multiplexer that selects functional data or the scan input.");
term("Scan chain","many scan cells wired into one long shift register for test.");
term("Scan-enable","the signal that switches flip-flops between functional and scan mode.");
term("Stuck-at fault","a defect model in which a node is permanently zero or one.");
term("System-on-Chip","a complete system integrated on a single chip.");
term("Worst negative slack","the smallest timing margin in the design; positive means timing is met.");

// ===================== CH 14: CONCLUSION =====================
h1("14. Conclusion and Future Work");
para("Protecting only the scan read path is insufficient for a cryptographic coprocessor embedded in a shared system chain. An attacker confined to the locked scan port was shown to inject a chosen key and plaintext, force encryption under attacker control, forge the returned ciphertext, and erase the key, all without unlocking. A measurement showed the earlier lock hides every output bit yet leaves more than half the chain writable, which is exactly the resource the attacks use.");
para("The proposed write-blocking segmented lock freezes and masks the chain while locked and closes every attack, three weaker variants were shown to fail in measured ways, and a hardened unlock controller resists brute force. The complete design keeps the cipher correct, keeps the chain fully testable when unlocked, costs about two percent of the baseline logic, holds the clock above one hundred twenty megahertz, carries a machine-checked proof of the locked read property, and was demonstrated live on a Spartan-7 board. Future work will add a self-test mode so that coverage is retained while locked, will extend the formal argument to the write path, and will report a frequency distribution over several placement seeds.");

// ===================== APPENDIX =====================
h1("Appendix A. Key Constants and File Map");
tbl([3400,5960],["Name","Value / meaning"],[
 ["Known-answer key","000102030405060708090A0B0C0D0E0F"],
 ["Known-answer plaintext","00112233445566778899AABBCCDDEEFF"],
 ["Known-answer ciphertext","69C4E0D86A7B0430D8CDB78070B4C55A"],
 ["Final round key K10","13111D7FE3944A17F307A78B4D2B30C5"],
 ["Attacker key used","0F1E2D3C4B5A69788796A5B4C3D2E1F0"],
 ["Injected ciphertext","50b58e80ce784e98ad48d63390c5dfd7"],
 ["Erased ciphertext","66e94bd4ef8a2c3b884cfa59ca342b2e"],
 ["Board unlock secret (demo)","5EC2E7A1"],
 ["Chain length / protected","645 bits total, 256 protected"]]);
para("The register-transfer-level sources are under RTL, the testbenches under TB, the formal scripts under formal, the synthesis reports under results, and the supporting documents under docs. The regression is run by run_regression.sh and the mutation study by mutate.py.");


// ===================== APPENDIX B: AES MATH =====================
h1("Appendix B. The AES-128 Transformation in Detail");
para("This appendix expands the cipher so the data path inside the engine is fully concrete. AES-128 arranges the sixteen bytes of the block as a four-by-four array called the state, filled column by column. Encryption is an initial key addition followed by ten rounds; rounds one through nine are full rounds and the tenth omits the column mixing.");
para("The initial step adds the first round key to the block, as in equation one, where the circled plus denotes bitwise exclusive-or.");
C.push(new Paragraph({alignment:AlignmentType.CENTER, spacing:{before:80,after:80}, children:[ new TextRun({text:"state = block XOR K0            (1)", font:MONO, size:19}) ]}));
para("Each full round then applies four steps in sequence. SubBytes replaces every byte through the substitution box; ShiftRows rotates row r left by r positions; MixColumns multiplies each column by a fixed matrix in the finite field with two hundred fifty six elements; and AddRoundKey exclusive-ors the round key. The combined round is equation two.");
C.push(new Paragraph({alignment:AlignmentType.CENTER, spacing:{before:80,after:80}, children:[ new TextRun({text:"state = MixColumns(ShiftRows(SubBytes(state))) XOR RKr      (2)", font:MONO, size:19}) ]}));
para("The finite-field doubling used inside MixColumns is the operation xtime, equation three, where a left shift is followed by a conditional exclusive-or with the constant one-b in hexadecimal when the top bit was set. Multiplication by three is xtime of the byte exclusive-or the byte itself, equation four.");
C.push(new Paragraph({alignment:AlignmentType.CENTER, spacing:{before:80,after:80}, children:[ new TextRun({text:"xtime(a) = (a << 1) XOR (a[7] ? 0x1b : 0x00)      (3)", font:MONO, size:19}) ]}));
C.push(new Paragraph({alignment:AlignmentType.CENTER, spacing:{before:80,after:80}, children:[ new TextRun({text:"mul3(a) = xtime(a) XOR a      (4)", font:MONO, size:19}) ]}));
para("The key schedule expands the sixteen-byte key into eleven round keys. Each new four-byte word is formed from the previous word and the word four positions back; at the start of each group the previous word is rotated, passed through the substitution box, and combined with a round constant, equation five. The final round key produced this way is K10, and because the schedule is invertible the master key can be computed back from K10, which is why leaving K10 observable leaks the key.");
C.push(new Paragraph({alignment:AlignmentType.CENTER, spacing:{before:80,after:80}, children:[ new TextRun({text:"w[i] = w[i-4] XOR SubWord(RotWord(w[i-1])) XOR Rcon      (5)", font:MONO, size:19}) ]}));
para("In the hardware engine the state register holds the running state, the round-key register holds the current round key and advances through the schedule, the key register retains the master key for reload, and the round counter indexes the ten rounds. One round is computed per clock, so a full encryption completes in about eleven cycles. At the done state the state register equals the ciphertext and the round-key register equals K10, which is exactly why a scan read at that moment is so damaging on an unprotected design.");

// ===================== APPENDIX C: PCPI HANDSHAKE =====================
h1("Appendix C. The Processor Co-Processor Interface Handshake");
para("The interface lets the processor offload an instruction it does not implement. Understanding the handshake clarifies both the legitimate data path and why the attacks need no special timing.");
para("When the processor meets an instruction it cannot decode, it drives the instruction word and the two source-register values onto the interface and raises a valid signal. Every attached coprocessor inspects the opcode combinationally. If the opcode is not its own, the coprocessor keeps its wait and ready signals low so the processor can take its normal illegal-instruction path. If the opcode is the custom AES opcode, the coprocessor must claim it in the same cycle by raising its wait signal, because the processor starts a short timeout the moment valid rises.");
para("For the load and result-read operations the coprocessor completes in one cycle and pulses its ready signal, with a write-enable that tells the processor whether to store a returned value. For the encrypt operation the coprocessor holds the wait signal for the full ten-round latency and pulses ready when the engine reaches its done state. A guard called core-seen-running ensures that a stale done flag left over from a previous encryption cannot be mistaken for completion of a new one, a race that was isolated and fixed and is covered by a dedicated control testbench.");
para("The security relevance is that the attacks use only this ordinary interface to trigger encryption or read a result, combined with ordinary scan shifting to place or extract values. No abnormal timing, glitch, or undocumented mode is required, which is what makes the write attack realistic.");

// ===================== APPENDIX D: COMPARISON =====================
h1("Appendix D. Relationship to Prior Work");
para("Masking the scan output to defeat read attacks is established prior art, beginning with the first scan side-channel attack on a block cipher and the secure-scan architecture that answered it, and continuing through on-chip comparison, low-cost scan locks, compaction analysis, and a provably secure masking scheme. The analyses of obfuscation-style locks, which can be resolved as a satisfiability problem given enough challenge and response pairs, are the reason this project relies on masking rather than a feedback-shift-register obfuscation. Table 6 places the present work against representative prior art.");
tbl([900,3200,1600,1660,2000],["Work","Focus","Read defense","Write defense","FPGA system"],[
 ["Prior","Scan read attack and secure-scan masking","yes","no","no"],
 ["Prior","On-chip comparison and low-cost locks","yes","no","no"],
 ["Prior","Provably secure masking of a cipher chain","yes","no","no"],
 ["Prior","Obfuscation and its satisfiability break","n/a","n/a","no"],
 ["Prior","Flipped scan chain and hidden authorization","yes","no","no"],
 ["This work","Shared processor-coprocessor chain, write lock","yes","yes","yes"]]);
para("The distinguishing attributes are three. First, the target is a shared system chain holding processor, control, and cipher state rather than a dedicated cipher chain. Second, the threat model and the defense explicitly cover the scan write path, not only the read path. Third, the complete integrated system is validated on a field-programmable gate array, with the overhead measured against a matching baseline.");

// ===================== APPENDIX E: PAPER 1 ERRATA =====================
h1("Appendix E. Corrections Carried From Paper 1");
para("Honest reporting requires listing the imprecise statements in the earlier work so that the present report does not repeat them.");
bullet("The earlier lock was described as segmented, but the register-transfer-level code blanks the whole coprocessor scan output as one unit; the present write-blocking lock is the one that is genuinely segment-aware.");
bullet("The claim that every scan-relevant register is a scan primitive was overstated; a few control registers remain plain flip-flops, which is in fact part of why the spoof attack is possible.");
bullet("The phrase zero functional overhead sat next to a measured frequency drop; the accurate statement is zero effect on encryption correctness, with a small frequency cost reported as a range.");
bullet("The frequency explanation was asserted rather than shown; the recommended fix, carried into this project, is to report a distribution over several placement seeds.");
bullet("The final round key was treated as harmless on hardware; it is key-equivalent because it inverts to the master key, and is treated as sensitive here.");


// ===================== ASSEMBLE =====================
const doc = new Document({
  features:{ updateFields:true },
  styles:{ default:{ document:{ run:{ font:FONT, size:22 } },
    heading1:{ run:{ font:FONT, size:30, bold:true, color:'1F3864' } },
    heading2:{ run:{ font:FONT, size:26, bold:true, color:'2E5496' } } } },
  sections:[{
    properties:{ page:{ size:{ width:12240, height:15840 }, margin:{ top:1440, bottom:1440, left:1440, right:1440 } } },
    footers:{ default: new Footer({ children:[ new Paragraph({ alignment:AlignmentType.CENTER,
      children:[ new TextRun({ children:['SecureScan-RV Project Report    |    Page ', PageNumber.CURRENT], font:FONT, size:16 }) ] }) ] }) },
    children: C
  }]
});
Packer.toBuffer(doc).then(b=>{ fs.writeFileSync('/tmp/claude-0/-home-user-SECURE-SCAN-CHAIN-V2/bd750c1e-aef9-570f-9ad9-93828c77c9e1/scratchpad/SecureScanRV_Project_Report.docx', b); console.log('REPORT written', b.length); });
