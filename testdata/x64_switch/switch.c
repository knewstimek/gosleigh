/* x86-64 real-switch corpus for Gosleigh track B (true jump-table recovery).
 *
 * Unlike testdata/x64_breadth/breadth.c (fed as raw .text at base 0, where even
 * Ghidra falls back to CALLIND because there is no reloc/image base and the
 * .rdata jump table is unmapped), this source is compiled AND fully linked into
 * a PE32+ executable. The link step resolves the image base (default
 * 0x140000000) and places the switch jump table into a real .rdata section with
 * image-relative (4-byte RVA) entries -- exactly the input on which Ghidra
 * recovers a genuine `switch (sel) { case 0: ... }`.
 *
 * Freestanding by design: no #include, a custom entry point, and linked with
 * /NODEFAULTLIB so no CRT/Windows SDK import is pulled in. The resulting .exe
 * has zero imports; its only interesting relocations are the jump-table RVAs,
 * which is precisely what the loader/recovery path must consume.
 *
 * op_switch is dense (selector 0..7) with a DISTINCT operation per case so the
 * compiler cannot collapse it into a constant value-lookup table; it must emit
 * a code jump table (BRANCHIND into eight separate case blocks). That is the
 * shape ActionSwitchNorm + JumpBasic recovery are meant to reconstruct.
 */

/* Dense 0..7 switch, one distinct arithmetic op per case, so MSVC /Od lowers it
 * to a .rdata code jump table rather than a data value table. */
long op_switch(long sel, long a, long b) {
	switch (sel) {
	case 0: return a + b;
	case 1: return a - b;
	case 2: return a * b;
	case 3: return a ^ b;
	case 4: return a | b;
	case 5: return a & b;
	case 6: return a << (b & 63);
	case 7: return a >> (b & 63);
	default: return -1;
	}
}

/* Custom entry point. References op_switch so the linker cannot dead-strip it,
 * and returns its low bits as the process exit code. No CRT, no imports. */
int entry(void) {
	return (int)op_switch(3, 7, 2);
}
