# D16: SIB/reg+disp addressing + struct/array access E2E

## Objective

Add golden fixture coverage for memory addressing modes not yet covered:
1. MOV EAX, [EBX+8]     (89 43 08 -> 8B 43 08) -- register + disp8 (struct member read)
2. MOV [EBX+8], EAX     (89 43 08)              -- register + disp8 (struct member write)
3. MOV EAX, [ECX+EAX*4] (8B 04 81)              -- SIB: base=ECX, index=EAX, scale=4 (array read)
4. MOV EAX, [EBP+ECX*4+8] (8B 44 8D 08)         -- SIB+disp8 (array in frame)
5. LEA EAX, [EBX+ECX*4]   (8D 04 8B)            -- LEA with SIB (pointer arithmetic)
6. MOV EAX, [EAX+EBX]    (8B 04 03)             -- SIB: base=EBX, index=EAX, scale=1

Plus a struct-access E2E: a function that reads/writes struct fields via pointer.

## Why

After D15 (82 golden subtests), the remaining critical gap for real compiled code:
- [EBP+offset] (stack): done (D10)
- [EAX] (indirect): done (used in CALL/JMP indirect fixtures)
- [EBX+disp8] (reg+disp): NOT covered -- used for every struct field access
- SIB (scaled index byte): NOT covered -- used for every array element access

Every real C function that takes a pointer argument, accesses struct members,
or indexes into arrays uses these addressing modes. Without them, real-world
decompilation cannot work.

Example: `foo->bar` compiles to MOV EAX, [EBX+offset_of_bar].
Example: `arr[i]` compiles to MOV EAX, [ECX+EAX*4] (SIB, scale=4 for int[]).

## Part 1: Golden fixtures

### MOV EAX, [EBX+8] -- register + disp8 read
  {"x86_MOV_EAX_EBX_disp8", []byte{0x8B, 0x43, 0x08}},

ModRM 0x43 = mod=01 (disp8), reg=0 (EAX=dest), rm=3 (EBX=base).
Expected: LOAD([EBX + 8]) -> EAX. 1 op.

### MOV [EBX+8], EAX -- register + disp8 write
  {"x86_MOV_EBX_disp8_EAX", []byte{0x89, 0x43, 0x08}},

ModRM 0x43 = mod=01 (disp8), reg=0 (EAX=src), rm=3 (EBX=base).
Expected: STORE(EAX -> [EBX + 8]). 1 op.

### MOV EAX, [ECX+EAX*4] -- SIB array read (scale=4)
  {"x86_MOV_EAX_SIB_ECX_EAX4", []byte{0x8B, 0x04, 0x81}},

ModRM 0x04 = mod=00, reg=0 (EAX=dest), rm=4 (SIB follows).
SIB 0x81 = scale=10 (4), index=000 (EAX), base=001 (ECX).
Address = ECX + EAX*4.
Expected: INT_ADD(ECX, INT_MULT(INT_ZEXT(EAX), 4)) -> addr, LOAD(addr) -> EAX. 2-3 ops.

### LEA EAX, [EBX+ECX*4] -- SIB pointer arithmetic
  {"x86_LEA_EAX_SIB", []byte{0x8D, 0x04, 0x8B}},

ModRM 0x04 = mod=00, reg=0 (EAX=dest), rm=4 (SIB follows).
SIB 0x8B = scale=10 (4), index=001 (ECX), base=011 (EBX).
Address = EBX + ECX*4.
Expected: INT_ADD(EBX, INT_MULT(INT_ZEXT(ECX), 4)) -> EAX (no memory load). 1-2 ops.

### MOV EAX, [EBP+ECX*4+8] -- SIB + disp8 (array in frame)
  {"x86_MOV_EAX_SIB_disp8", []byte{0x8B, 0x44, 0x8D, 0x08}},

ModRM 0x44 = mod=01 (disp8), reg=0 (EAX=dest), rm=4 (SIB follows).
SIB 0x8D = scale=10 (4), index=001 (ECX), base=101 (EBP).
disp8 = 0x08.
Address = EBP + ECX*4 + 8.
Expected: LOAD([EBP + ECX*4 + 8]) -> EAX. 2-3 ops.

### MOV EAX, [EAX+EBX] -- SIB scale=1 (pointer + offset)
  {"x86_MOV_EAX_EAX_EBX", []byte{0x8B, 0x04, 0x03}},

ModRM 0x04 = mod=00, reg=0 (EAX=dest), rm=4 (SIB).
SIB 0x03 = scale=00 (1), index=000 (EAX), base=011 (EBX).
Address = EBX + EAX*1 = EBX + EAX.
Expected: LOAD([EBX + EAX]) -> EAX. 1-2 ops.

Total golden subtests after D16: >= 88 (82 + 6 = 88)

## Part 2: E2E struct-access function

Add TestX86StructAccessFunction to pkg/loader/loader_test.go.

A function that reads a field from a struct pointer:

typedef struct { int x; int y; int z; } Point;
int get_y(Point *p) {
    return p->y;  // p->y is at offset 4
}

Assembly (p in EBP+8, return p->y = [p+4]):
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 8B 45 08        MOV EAX, [EBP+8]    (p)
  0x06: 8B 40 04        MOV EAX, [EAX+4]    (p->y, disp8=4)
  0x09: 5D              POP EBP
  0x0A: C3              RET
  Total: 11 bytes

Bytes: {0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x8B, 0x40, 0x04, 0x5D, 0xC3}

Note: 0x8B 0x40 0x04 = MOV EAX, [EAX+4]. ModRM 0x40 = mod=01(disp8), reg=0(EAX=dst), rm=0(EAX=base).

Assertions:
- len(result.Instructions) >= 4
- Heritage + pipeline runs without error
- PrintC output non-empty
- t.Logf("get_y C output:\n%s", output)

Also add TestX86ArrayIndexFunction:

int get_elem(int *arr, int i) {
    return arr[i];
}

Assembly (arr in EBP+8, i in EBP+12):
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 8B 45 08        MOV EAX, [EBP+8]    (arr)
  0x06: 8B 4D 0C        MOV ECX, [EBP+12]   (i)
  0x09: 8B 04 88        MOV EAX, [EAX+ECX*4] (arr[i])
  0x0C: 5D              POP EBP
  0x0D: C3              RET
  Total: 14 bytes

ModRM for [EAX+ECX*4]: 0x04, SIB: scale=10(4), index=001(ECX), base=000(EAX) = 0x88.

Bytes: {0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x8B, 0x4D, 0x0C, 0x8B, 0x04, 0x88, 0x5D, 0xC3}

Assertions:
- len(result.Instructions) >= 5
- Heritage + pipeline runs without error
- PrintC output non-empty
- t.Logf("get_elem C output:\n%s", output)

## In-scope

1. pkg/sla/x86_golden_test.go: add MOV_EAX_EBX_disp8, MOV_EBX_disp8_EAX, MOV_EAX_SIB_ECX_EAX4, LEA_EAX_SIB, MOV_EAX_SIB_disp8, MOV_EAX_EAX_EBX
2. testdata/golden/: 6 new JSON fixture files
3. pkg/loader/loader_test.go: TestX86StructAccessFunction + TestX86ArrayIndexFunction
4. Fix any SIB decode gaps if needed
5. docs/STATUS.md + docs/X86_ROADMAP.md updates

## Out-of-scope

- [disp32] absolute addressing (rare in position-independent code)
- [EBP+ECX*4] without disp8 (ESP/EBP base with SIB has special encoding)
- segment override prefixes (CS/DS/ES/FS/GS)
- FPU/SSE
- 64-bit

## Invariants

- All existing tests pass (82 golden subtests, 13 E2E tests)
- New golden fixtures >= 1 op each
- TestX86StructAccessFunction and TestX86ArrayIndexFunction must NOT skip
- No new external dependencies
- ASCII-only, tabs for indentation, English comments

## Done when

- go test ./pkg/sla/... -run TestGoldenX86 passes with >= 88 subtests
- go test ./pkg/loader/... -run TestX86StructAccessFunction passes
- go test ./pkg/loader/... -run TestX86ArrayIndexFunction passes
- go test ./... passes green
