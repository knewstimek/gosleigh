# D5: MUL/IMUL golden fixtures + CLI verification + multiply function E2E

## Objective

1. Verify the cmd/gosleigh CLI tool works end-to-end on a real ELF binary.
2. Add MUL and IMUL golden fixtures to close the arithmetic opcode gap.
3. Add a multiply function E2E test (a*b function using IMUL).

## Why

Phase D4 verified if-else diamond CFG. The remaining common x86 arithmetic ops
for real-world decompilation are multiply and divide. IMUL is extremely common
in compiled C (integer multiply). Without it, the decompiler cannot handle any
function that multiplies two values.

The CLI tool (cmd/gosleigh) has not been tested against a real ELF since it was
implemented in Phase C1. This phase validates the full user-facing pipeline.

## Part 1: CLI tool verification

Run the CLI on testdata/elfs/simple_add.elf and verify it produces C output.

The CLI was implemented in cmd/gosleigh/main.go with a "translate" subcommand.
The expected invocation is:
  go run ./cmd/gosleigh translate --sla <path> --pspec <path> --binary <elf_path> --output c

Or using the EngineBuilder.BinaryPath path if that is how the CLI works.

Steps:
1. Read cmd/gosleigh/main.go to understand the exact CLI flags
2. Find the correct paths for x86-packed.sla and x86.pspec in testdata/
3. Run the CLI on testdata/elfs/simple_add.elf:
   go run ./cmd/gosleigh translate <flags> 2>&1
4. Verify that the output is non-empty C code (not an error)
5. Add a shell-based CLI integration test to pkg/loader/elf_test.go
   OR document the verified CLI invocation in a comment in elf_test.go

If the CLI has a bug (e.g., it requires --entry flag that was not known to work),
fix the CLI bug. Do NOT add a full shell exec test if it would be fragile on all
platforms -- a manual verification and a t.Logf noting the CLI command is acceptable.

## Part 2: IMUL golden fixture

Add to TestGoldenX86:
  {"x86_IMUL_EAX_EBX", []byte{0x0F, 0xAF, 0xC3}},  // IMUL EAX, EBX (opcode 0x0F 0xAF /r, ModRM=0xC3 = EAX*EBX->EAX)

Expected p-code: INT_MULT + overflow/sign flags -- typically 2-4 ops.
Generate golden fixture: testdata/golden/x86_IMUL_EAX_EBX.json.
Must produce >= 1 op.

Also add if useful:
  {"x86_MUL_EBX", []byte{0xF7, 0xE3}},  // MUL EBX (unsigned multiply EAX*EBX -> EDX:EAX)

Expected p-code: INT_MULT + potential upper half store -- typically 2-3 ops.

## Part 3: Multiply function E2E test

Add TestX86MultiplyFunction to pkg/loader/loader_test.go.

The multiply function (int mul(int a, int b) { return a * b; }) bytes:
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 8B 45 08        MOV EAX, [EBP+8]   (arg a)
  0x06: 0F AF 45 0C     IMUL EAX, [EBP+12] (EAX *= arg b, disp8=0x0C)
  0x0A: 5D              POP EBP
  0x0B: C3              RET
  Total: 12 bytes

As byte slice: {0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x0F, 0xAF, 0x45, 0x0C, 0x5D, 0xC3}

TestX86MultiplyFunction:
  a. EngineBuilder{SLAPath, PspecPath, Bytes: prog}
  b. bridge.Build(engine, bridge.BuildConfig{Name:"mul", Entry:base, MaxInstructions:20})
  c. Assert len(result.Instructions) >= 4
  d. Heritage + BatchAActions + BlockStructure + FinalStructure
  e. PrintC output non-empty
  f. t.Logf("Multiply C output:\n%s", output)

Note: IMUL EAX,[EBP+12] uses a memory operand with disp8. This is:
  opcode 0F AF /r where /r = 0x45 (EAX, [EBP+disp8]) and disp8 = 0x0C
If the resolve.go fix in D4 is correct, this should work. If not, diagnose and fix.

## Part 4: Update docs

- docs/STATUS.md: add Phase D5 completion entry
- docs/X86_ROADMAP.md: mark item 13 (Rules MUL/IMUL) as complete

## In-scope

1. cmd/gosleigh CLI verification on simple_add.elf
2. pkg/sla/x86_golden_test.go: add IMUL_EAX_EBX (and MUL_EBX if it works)
3. testdata/golden/x86_IMUL_EAX_EBX.json (and x86_MUL_EBX.json if MUL works)
4. pkg/loader/loader_test.go: add TestX86MultiplyFunction
5. Fix any IMUL/MUL or memory-operand gaps encountered
6. docs/STATUS.md + docs/X86_ROADMAP.md updates

## Out-of-scope

- INT_DIV / IDIV (integer division) -- Phase D6
- FLOAT ops -- future
- DWARF/symtab parsing -- future
- 64-bit x86 -- future
- Do not modify existing golden fixtures

## Invariants

- All existing tests (go test ./...) must pass
- New golden fixtures >= 1 op each
- TestX86MultiplyFunction must NOT skip
- ASCII-only, tabs for indentation, English comments
- No new external dependencies

## Done when

- go build ./... passes
- go test ./pkg/sla/... -run TestGoldenX86 passes with >= 19 subtests (17 + IMUL + MUL)
- go test ./pkg/loader/... -run TestX86MultiplyFunction passes and logs non-empty C output
- go test ./... passes with all tests green
- CLI produces non-empty C output for simple_add.elf (verified manually or via test)
