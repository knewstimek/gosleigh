# D13: CMOVcc + BSWAP golden fixtures + CMOVCC E2E

## Objective

Add golden fixture coverage for conditional-move (CMOVcc) instructions and BSWAP:
1. CMOVE EAX, EBX (0F 44 D8) -- Conditional Move if Equal (ZF=1)
2. CMOVNE EAX, EBX (0F 45 D8) -- Conditional Move if Not Equal
3. CMOVGE EAX, EBX (0F 4D D8) -- Conditional Move if Greater or Equal (signed)
4. CMOVL EAX, EBX (0F 4C D8) -- Conditional Move if Less (signed)
5. CMOVG EAX, EBX (0F 4F D8) -- Conditional Move if Greater (signed)
6. BSWAP EAX (0F C8) -- Byte Swap (reverse byte order of EAX)

Plus an E2E test for a function that uses CMOVG for a branchless max().

## Why

After D12, the golden fixture set covers most common x86 ops used in real code.
CMOVcc is missing and is the last major gap for modern compiler output:

- GCC and Clang -O2+ frequently use CMOVcc to replace branch-based if-else with
  branchless conditional moves. Without CMOVcc, any optimized comparison expression
  will produce incorrect decompilation.
- BSWAP is used in network protocols (htonl/ntohl), cryptographic algorithms, and
  endian conversion routines. Common in any networking or crypto code.

Together these two cover the major gap between "debug build" x86 and "optimized build" x86.

## Part 1: Golden fixtures to add

### CMOVcc (all use ModRM 0xD8 = mod=11, reg=3(EBX), rm=0(EAX) -- source EBX -> dest EAX)

Wait -- ModRM for "CMOV EAX, EBX" means destination=EAX, source=EBX.
ModRM encoding: mod=11 (register), reg=0 (EAX=destination), rm=3 (EBX=source).
ModRM byte = 11 000 011 = 0xC3.

  {"x86_CMOVE_EAX_EBX",  []byte{0x0F, 0x44, 0xC3}},  // CMOVE EAX, EBX (if ZF=1)
  {"x86_CMOVNE_EAX_EBX", []byte{0x0F, 0x45, 0xC3}},  // CMOVNE EAX, EBX (if ZF=0)
  {"x86_CMOVGE_EAX_EBX", []byte{0x0F, 0x4D, 0xC3}},  // CMOVGE EAX, EBX (if SF=OF)
  {"x86_CMOVL_EAX_EBX",  []byte{0x0F, 0x4C, 0xC3}},  // CMOVL EAX, EBX (if SF!=OF)
  {"x86_CMOVG_EAX_EBX",  []byte{0x0F, 0x4F, 0xC3}},  // CMOVG EAX, EBX (if ZF=0 and SF=OF)

Expected: BOOL condition-expression -> tmp, then conditional COPY(EBX -> EAX) if tmp.
Ghidra models CMOVcc as: tmp = (condition flags) ; EAX = (condition ? EBX : EAX).
Accept whatever the SLA emits -- record golden verbatim. Typical: 2-5 ops each.

### BSWAP
  {"x86_BSWAP_EAX", []byte{0x0F, 0xC8}},  // BSWAP EAX (opcode 0F C8+rd, rd=0 for EAX)

Expected: byte reversal sequence or dedicated BSWAP p-code. ~2-4 ops.
Ghidra likely models as: temp = EAX; EAX = (SUBPIECE(temp,3,1) | SUBPIECE(temp,2,1)<<8 |
SUBPIECE(temp,1,1)<<16 | SUBPIECE(temp,0,1)<<24). Or may use a single BYTESWAP op.

Total golden subtests after D13: >= 69 (63 + 5 CMOV + 1 BSWAP = 69)

## Part 2: E2E branchless max() using CMOVG

Add TestX86BranchlessMaxFunction to pkg/loader/loader_test.go.

A branchless max function using CMOVG:

int max_cmov(int a, int b) {
    int result = a;
    if (b > a) result = b;  // implemented as CMOVG EAX, ECX
    return result;
}

Assembly:
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 8B 45 08        MOV EAX, [EBP+8]    (a -> result)
  0x06: 8B 4D 0C        MOV ECX, [EBP+12]   (b)
  0x09: 39 C1           CMP EAX, ECX        (a vs b)
  0x0B: 0F 4F C1        CMOVG EAX, ECX      (if a > b, EAX = ECX=b? -- wait)

Actually CMOVG EAX, ECX means: if (a > b is false, i.e. b >= a), move ECX into EAX.
Let me reconsider -- CMP EAX,ECX sets flags based on EAX-ECX.
CMOVG moves source to dest if ZF=0 AND SF=OF, i.e. if EAX > ECX (a > b).
That would keep EAX=a if a > b. We want EAX=b if b > a.

Better: CMP ECX,EAX then CMOVG EAX,ECX -- compares b vs a, if b > a then EAX=b.

  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 8B 45 08        MOV EAX, [EBP+8]    (a)
  0x06: 8B 4D 0C        MOV ECX, [EBP+12]   (b)
  0x09: 3B C1           CMP EAX, ECX        (a - b; if b > a then SF != OF)
  0x0B: 0F 4C C1        CMOVL EAX, ECX      (if a < b [SF!=OF], EAX = ECX=b)
  0x0E: 5D              POP EBP
  0x0F: C3              RET
  Total: 16 bytes

Note: 0x0F 0x4C 0xC1 = CMOVL EAX, ECX (ModRM 0xC1 = mod=11, reg=0=EAX, rm=1=ECX)

Bytes: {0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x8B, 0x4D, 0x0C, 0x3B, 0xC1, 0x0F, 0x4C, 0xC1, 0x5D, 0xC3}

Assertions:
- len(result.Instructions) >= 5
- Heritage + pipeline runs without error
- PrintC output non-empty
- t.Logf("max_cmov C output:\n%s", output)

## In-scope

1. pkg/sla/x86_golden_test.go: add CMOVE_EAX_EBX, CMOVNE_EAX_EBX, CMOVGE_EAX_EBX, CMOVL_EAX_EBX, CMOVG_EAX_EBX, BSWAP_EAX
2. testdata/golden/: 6 new JSON fixture files (generated with GOSLEIGH_UPDATE_GOLDEN=1)
3. pkg/loader/loader_test.go: TestX86BranchlessMaxFunction (CMOVL branchless max E2E)
4. Fix any decode gaps for CMOVcc or BSWAP if needed
5. docs/STATUS.md + docs/X86_ROADMAP.md updates

## Out-of-scope

- CMOVcc with memory operand
- CMOVCC unsigned variants (CMOVB, CMOVBE, etc.) -- lower priority
- REP/REPNE string ops
- FPU/SSE
- 64-bit

## Invariants

- All existing tests pass (63 golden subtests, 15 E2E tests)
- New golden fixtures >= 1 op each
- TestX86BranchlessMaxFunction must NOT skip
- No new external dependencies
- ASCII-only, tabs for indentation, English comments

## Done when

- go test ./pkg/sla/... -run TestGoldenX86 passes with >= 69 subtests
- go test ./pkg/loader/... -run TestX86BranchlessMaxFunction passes with non-empty PrintC
- go test ./... passes green
