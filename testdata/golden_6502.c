/*
	Provenance: manual fallback.
	analyzeHeadless was not available on PATH on 2026-04-02.
	This file is a hand-written approximation of the expected Ghidra C output
	for test_6502.bin at entry 0x0000.
*/

typedef unsigned char byte;

extern byte RAM[65536];
extern void software_interrupt(void);

void entry(void)
{
	(void)RAM[0x0000];
	software_interrupt();
}
