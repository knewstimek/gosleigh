# Goal 03: Ghidra Golden Output Generation + First Comparison

## Objective

Generate Ghidra's C decompiler output for a small 6502 binary, then compare it with Gosleigh's output to identify the first set of parity gaps.

## Part A: Create a test 6502 binary

Create a small but non-trivial 6502 program in testdata/ that exercises:
- Arithmetic (LDA, ADC, SBC)
- Memory access (LDA/STA with different addressing modes)
- Control flow (JMP, BNE, BEQ, JSR, RTS)
- At least 2 functions (main + subroutine)

Size: ~32-64 bytes. Store as testdata/test_6502.bin with a companion testdata/test_6502_info.txt describing entry point and function boundaries.

## Part B: Generate Ghidra golden output

Use Ghidra headless analyzer to decompile the test binary:
1. Check if Ghidra is installed (look for analyzeHeadless or ghidra installation)
2. If not available, create a script that can be run manually, and document the steps
3. Create a Ghidra script (testdata/ghidra_decompile.py) that:
   - Loads the binary as raw 6502
   - Decompiles the function at the entry point
   - Writes the C output to stdout or a file
4. Store the golden output as testdata/golden_6502.c

## Part C: Run Gosleigh and compare

1. Run gosleigh CLI on the same binary
2. Diff the output against golden_6502.c
3. Document every difference in a new file: docs/PARITY_GAPS.md
4. Categorize gaps: cosmetic (whitespace/naming), structural (different control flow), semantic (wrong logic)

## Success criteria
- testdata/test_6502.bin exists with documented layout
- testdata/golden_6502.c exists (from Ghidra or manually verified C output)
- Gosleigh produces C output for the same binary
- docs/PARITY_GAPS.md documents all found differences
- go test ./... passes

## Constraints
- Tabs indentation, English comments, no non-ASCII in code
- If Ghidra headless is not available, create the golden output manually based on what Ghidra WOULD produce (document this clearly)
- Use mcp__agent-tool__* tools
